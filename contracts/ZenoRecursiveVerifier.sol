// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/// The batched universal decider, without its final pairing check.
interface IZenoBatchedDecider {
    function verifyDeferred(
        bytes32[] calldata vks,
        uint256[][] calldata keys,
        uint256[][] calldata accs,
        uint256[] calldata proof
    ) external view returns (uint256[4] memory lr);
}

/// @title ZenoRecursiveVerifier — one EVM decision for any number of IVC steps
/// @notice Decides the final state `(i, z₀, zᵢ, U, u, U_cf)` of the recursive
/// (CycleFold) IVC: `zᵢ = Fⁱ(z₀)`, at a cost independent of `i`. The
/// statement is bound to a *system*: `keccak256(primary vk ‖ closing vk ‖
/// CycleFold data hash)`, which anyone can recompute from the step circuit
/// and the public reference string.
///
/// One Keccak transcript (replaying `evm-verifier::recursive` exactly):
/// 1. folds the last primary instance `u` into `U`, then a random masking
///    instance (zero knowledge), with on-chain NIFS folds;
/// 2. decides the CycleFold accumulator with a Spartan-style argument over
///    `F_q`, evaluating the fixed CycleFold matrices (read from a data
///    contract) itself; its Hyrax openings reduce to the combined rows `e'`,
///    `w'`, whose inner products it checks;
/// 3. assembles the public input of the closing circuit, which proves the
///    remaining Grumpkin equation and recomputes `u.x = H(vk, i, z₀, zᵢ, U, U_cf)`;
/// 4. verifies one batched universal decider proof for the masked primary
///    accumulator and the closing instance, and checks its pairing equation.
contract ZenoRecursiveVerifier {
    /// Order of the BN254 scalar field.
    uint256 internal constant R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    /// Modulus of the BN254 base field (= the order of Grumpkin).
    uint256 internal constant Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 internal constant INV2_Q =
        10944121435919637611123202872628637544348155578648911831344518947322613104292;
    uint256 internal constant INV6_Q =
        18240202393199396018538671454381062573913592631081519718907531578871021840486;
    /// `(1 + 2^255) mod q`: a row weight `s` reaches the closing circuit as
    /// the `t` with `2^255 + 2t + 1 ≡ s`.
    uint256 internal constant ODD_K =
        14119558874979547267292681013829403749242370018224634694350716214666112402803;
    uint256 internal constant LOG_COLS = 7;
    uint256 internal constant COLS = 128;
    uint256 internal constant LIMB_MASK = (1 << 128) - 1;
    // Generator of G2, in the precompile's (imaginary, real) coordinate order.
    uint256 internal constant G2_X_IM =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 internal constant G2_X_RE =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 internal constant G2_Y_IM =
        4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 internal constant G2_Y_RE =
        8495653923123431417604973247489272438418190587263600148770280649306958101930;

    bytes32 internal constant DOMAIN = keccak256("zeno-llull/recursive-decider/v1");

    IZenoBatchedDecider public immutable decider;
    /// Data contract holding the CycleFold matrices (`0x00 ‖ data`).
    address public immutable cfData;
    bytes32 public immutable cfCodeHash;
    /// `keccak256(systemId ‖ keccak256(i ‖ z₀ ‖ zᵢ))` of every decided claim.
    mapping(bytes32 => bool) public decided;

    event RecursiveDecided(bytes32 indexed systemId, uint64 steps, bytes32 claimHash);

    error MalformedInput();
    error InvalidProof(uint256 step);
    error InvalidPoint();

    /// Dimensions read from the CycleFold data header.
    struct Dims {
        uint256 logM;
        uint256 logN;
        uint256 io;
        uint256 rowsW;
        uint256 rowsE;
        uint256 arity;
    }

    /// Offsets into `state`.
    struct Layout {
        uint256 acc; // U: comm_E, u, comm_W, x
        uint256 last; // u: comm_W, x
        uint256 commT;
        uint256 mask;
        uint256 maskT;
        uint256 cf; // rows of W, rows of E, u, x
        uint256 cfU;
        uint256 length;
    }

    /// The CycleFold argument's outputs needed for the closing input.
    struct CfOut {
        uint256[] rx;
        uint256[] ry;
        uint256 gamma;
    }

    constructor(IZenoBatchedDecider decider_, address cfData_) {
        decider = decider_;
        cfData = cfData_;
        bytes32 h;
        assembly ("memory-safe") {
            h := extcodehash(cfData_)
        }
        cfCodeHash = h;
    }

    /// @notice Decides a final IVC state; reverts if any check fails.
    /// @param primaryKey universal decider key of the primary circuit (23 words).
    /// @param closingKey universal decider key of the closing circuit (23 words).
    /// @param state `[i, k, z₀[k], zᵢ[k], U(6), u(3), comm_T(2), mask(6),
    /// mask_T(2), U_cf rows of W, rows of E (2 words each), U_cf.u, U_cf.x]`.
    /// @param cfProof `[outer sum-check, claims(4), inner sum-check, W(r_y'),
    /// e'(128), w'(128), closing comm_W(2)]`.
    /// @param deciderProof the batched universal proof for both circuits.
    function finalizeRecursive(
        uint256[] calldata primaryKey,
        uint256[] calldata closingKey,
        uint256[] calldata state,
        uint256[] calldata cfProof,
        uint256[] calldata deciderProof
    ) external returns (bytes32 systemId) {
        if (primaryKey.length != 23 || closingKey.length != 23) revert MalformedInput();
        // Both universal proofs must be over the same [τ]₂.
        for (uint256 k = 19; k < 23; ++k) {
            if (primaryKey[k] != closingKey[k]) revert MalformedInput();
        }
        bytes32 vkP = keccak256(abi.encodePacked(primaryKey));
        bytes32 vkC = keccak256(abi.encodePacked(closingKey));
        systemId = keccak256(abi.encodePacked(vkP, vkC, cfCodeHash));

        Dims memory d = _dims(state.length > 1 ? state[1] : 0);
        Layout memory l = _layout(d);
        if (state.length != l.length || state[0] == 0 || state[0] >= 1 << 64) revert MalformedInput();
        if (cfProof.length != 3 * d.logM + 4 + 2 * (d.logN + 1) + 1 + 2 * COLS + 2) {
            revert MalformedInput();
        }

        bytes32 tr = DOMAIN;
        tr = _absorb(tr, abi.encodePacked(vkP, vkC, cfCodeHash));
        tr = _absorb(tr, abi.encodePacked(state[0], state[2:2 + 2 * d.arity]));
        tr = _absorb(tr, abi.encodePacked(state[l.acc:l.commT]));

        // ---- 1. Fold u into U, then mask --------------------------------------
        uint256[] memory acc = new uint256[](6);
        {
            tr = _absorb(tr, abi.encodePacked(state[l.commT:l.commT + 2]));
            uint256 r1;
            (tr, r1) = _challenge(tr, R);
            (acc[0], acc[1]) = _addMul(state[l.acc], state[l.acc + 1], state[l.commT], state[l.commT + 1], r1);
            acc[2] = addmod(state[l.acc + 2], r1, R);
            (acc[3], acc[4]) = _addMul(state[l.acc + 3], state[l.acc + 4], state[l.last], state[l.last + 1], r1);
            acc[5] = addmod(state[l.acc + 5], mulmod(r1, state[l.last + 2], R), R);

            tr = _absorb(tr, abi.encodePacked(state[l.mask:l.mask + 6]));
            tr = _absorb(tr, abi.encodePacked(state[l.maskT:l.maskT + 2]));
            uint256 r2;
            (tr, r2) = _challenge(tr, R);
            uint256 m = l.mask;
            (acc[0], acc[1]) = _addMul(acc[0], acc[1], state[l.maskT], state[l.maskT + 1], r2);
            (acc[0], acc[1]) = _addMul(acc[0], acc[1], state[m], state[m + 1], mulmod(r2, r2, R));
            acc[2] = addmod(acc[2], mulmod(r2, state[m + 2], R), R);
            (acc[3], acc[4]) = _addMul(acc[3], acc[4], state[m + 3], state[m + 4], r2);
            acc[5] = addmod(acc[5], mulmod(r2, state[m + 5], R), R);
        }

        // ---- 2. The CycleFold accumulator over F_q ----------------------------
        tr = _absorb(tr, abi.encodePacked(state[l.cf:l.length]));
        CfOut memory cf;
        (tr, cf) = _cycleFold(tr, d, state[l.cfU:l.length], cfProof);

        // ---- 3. The closing instance --------------------------------------------
        uint256[] memory closing = _closingInstance(d, l, state, cfProof, cf);

        // ---- 4. One batched universal proof for both circuits, one pairing ------
        {
            bytes32[] memory vks = new bytes32[](2);
            (vks[0], vks[1]) = (vkP, vkC);
            uint256[][] memory keys = new uint256[][](2);
            (keys[0], keys[1]) = (primaryKey, closingKey);
            uint256[][] memory accs = new uint256[][](2);
            (accs[0], accs[1]) = (acc, closing);
            _pairing(decider.verifyDeferred(vks, keys, accs, deciderProof), primaryKey);
        }

        bytes32 claimHash = keccak256(abi.encodePacked(state[0], state[2:2 + 2 * d.arity]));
        decided[keccak256(abi.encodePacked(systemId, claimHash))] = true;
        emit RecursiveDecided(systemId, uint64(state[0]), claimHash);
    }

    // ------------------------------------------------------------------
    // Layout
    // ------------------------------------------------------------------

    function _dims(uint256 arity) private view returns (Dims memory d) {
        address data = cfData;
        uint256 header;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            extcodecopy(data, ptr, 1, 32)
            header := mload(ptr)
        }
        d.logM = header >> 248;
        d.logN = (header >> 240) & 0xff;
        d.io = (header >> 232) & 0xff;
        if (d.logM < LOG_COLS || d.logN < LOG_COLS || arity == 0 || arity > 64) revert MalformedInput();
        d.rowsW = 1 << (d.logN - LOG_COLS);
        d.rowsE = 1 << (d.logM - LOG_COLS);
        d.arity = arity;
    }

    function _layout(Dims memory d) private pure returns (Layout memory l) {
        l.acc = 2 + 2 * d.arity;
        l.last = l.acc + 6;
        l.commT = l.last + 3;
        l.mask = l.commT + 2;
        l.maskT = l.mask + 6;
        l.cf = l.maskT + 2;
        l.cfU = l.cf + 2 * (d.rowsW + d.rowsE);
        l.length = l.cfU + 1 + d.io;
    }

    // ------------------------------------------------------------------
    // The Spartan argument over F_q
    // ------------------------------------------------------------------

    /// @param ux `[U_cf.u, U_cf.x…]`.
    function _cycleFold(bytes32 tr, Dims memory d, uint256[] calldata ux, uint256[] calldata p)
        private
        view
        returns (bytes32, CfOut memory out)
    {
        uint256 pos;
        uint256[] memory tau = new uint256[](d.logM);
        for (uint256 i = 0; i < d.logM; ++i) (tr, tau[i]) = _challenge(tr, Q);

        // Outer: Σ eq(τ,x)·(Az·Bz − u·Cz − E)(x) = 0.
        uint256 claim;
        (tr, claim, out.rx) = _sumcheck(tr, 0, d.logM, 3, p[pos:pos + 3 * d.logM]);
        pos += 3 * d.logM;
        {
            uint256 rhs = addmod(
                mulmod(p[pos], p[pos + 1], Q),
                Q - addmod(mulmod(ux[0], p[pos + 2], Q), p[pos + 3], Q),
                Q
            );
            if (claim != mulmod(_eqPoints(tau, out.rx), rhs, Q)) revert InvalidProof(11);
        }
        tr = _absorb(tr, abi.encodePacked(p[pos:pos + 4]));
        uint256 rho;
        (tr, rho) = _challenge(tr, Q);

        // Inner: Σ (A+ρB+ρ²C)(r_x,y)·Z(y) = v_A + ρv_B + ρ²v_C.
        claim = addmod(
            p[pos],
            addmod(mulmod(rho, p[pos + 1], Q), mulmod(mulmod(rho, rho, Q), p[pos + 2], Q), Q),
            Q
        );
        uint256 vE = p[pos + 3];
        pos += 4;
        (tr, claim, out.ry) = _sumcheck(tr, claim, d.logN + 1, 2, p[pos:pos + 2 * (d.logN + 1)]);
        pos += 2 * (d.logN + 1);
        uint256 vW = p[pos++];
        {
            // Z = (W ‖ (u, x)): eq(r_y, ·) is (1 − r_y0)·eq(r_y', ·) on the
            // first half and r_y0·eq(r_y', ·) on the second.
            uint256[] memory eqY = _eqTable(out.ry, 1, d.logN);
            uint256 ry0 = out.ry[0];
            uint256 m = _matrixEval(rho, ry0, _eqTable(out.rx, 0, d.logM), eqY);
            uint256 io = mulmod(ux[0], eqY[0], Q);
            for (uint256 i = 1; i < ux.length; ++i) io = addmod(io, mulmod(ux[i], eqY[i], Q), Q);
            uint256 z = addmod(mulmod(addmod(1, Q - ry0, Q), vW, Q), mulmod(ry0, io, Q), Q);
            if (claim != mulmod(m, z, Q)) revert InvalidProof(12);
        }
        tr = _absorb(tr, abi.encodePacked(vW));

        // Hyrax: the combined rows open Ẽ(r_x) and W̃(r_y[1..]).
        {
            uint256[] memory eqE = _eqTable(out.rx, d.logM - LOG_COLS, LOG_COLS);
            uint256[] memory eqW = _eqTable(out.ry, 1 + d.logN - LOG_COLS, LOG_COLS);
            uint256 e;
            uint256 w;
            assembly ("memory-safe") {
                let rowE := add(p.offset, shl(5, pos))
                let rowW := add(rowE, shl(5, COLS))
                for { let j := 0 } lt(j, COLS) { j := add(j, 1) } {
                    let o := shl(5, j)
                    e := addmod(e, mulmod(calldataload(add(rowE, o)), mload(add(add(eqE, 0x20), o)), Q), Q)
                    w := addmod(w, mulmod(calldataload(add(rowW, o)), mload(add(add(eqW, 0x20), o)), Q), Q)
                }
            }
            if (e != vE || w != vW) revert InvalidProof(13);
        }
        tr = _absorb(tr, abi.encodePacked(p[pos:pos + COLS]));
        tr = _absorb(tr, abi.encodePacked(p[pos + COLS:pos + 2 * COLS]));
        (tr, out.gamma) = _challenge(tr, Q);
        return (tr, out);
    }

    /// @dev `(A + ρB + ρ²C)(r_x, r_y) = Σ_groups ρ^k·value·(r_y0 or 1 − r_y0)·
    /// Σ_entries eq(r_x, row)·eq(r_y', col mod n)`, from the data contract
    /// (see `evm-verifier::recursive::cf_matrix_data`): entries hold the byte
    /// offsets of their row and column in the two tables.
    function _matrixEval(uint256 rho, uint256 ry0, uint256[] memory eqX, uint256[] memory eqY)
        private
        view
        returns (uint256 total)
    {
        address data = cfData;
        assembly ("memory-safe") {
            let size := extcodesize(data)
            let code := mload(0x40)
            extcodecopy(data, code, 1, sub(size, 1))
            mstore(0x40, add(code, and(add(size, 31), not(31))))
            let header := mload(code)
            let nv := and(shr(216, header), 0xffff)
            let ng := and(shr(200, header), 0xffff)
            let ne := and(shr(184, header), 0xffff)
            let values := add(code, 0x20)
            let group := add(values, shl(5, nv))
            let entry := add(group, shl(2, ng))
            if gt(add(entry, shl(2, ne)), add(code, sub(size, 1))) { revert(0, 0) }
            let x := add(eqX, 0x20)
            let y := add(eqY, 0x20)
            let rho2 := mulmod(rho, rho, Q)
            for { let g := 0 } lt(g, ng) { g := add(g, 1) } {
                let head := shr(224, mload(add(group, shl(2, g))))
                let end := add(entry, shl(2, and(head, 0xffff)))
                let inner := 0
                for { } lt(entry, end) { entry := add(entry, 4) } {
                    let e := shr(224, mload(entry))
                    inner := addmod(inner, mulmod(mload(add(x, shr(16, e))), mload(add(y, and(e, 0xffff))), Q), Q)
                }
                let v := mload(add(values, shl(5, and(shr(16, head), 0xff))))
                let tag := shr(24, head)
                switch and(tag, 0x7f)
                case 1 { v := mulmod(v, rho, Q) }
                case 2 { v := mulmod(v, rho2, Q) }
                switch shr(7, tag)
                case 0 { v := mulmod(v, sub(add(Q, 1), ry0), Q) }
                default { v := mulmod(v, ry0, Q) }
                total := addmod(total, mulmod(v, inner, Q), Q)
            }
        }
    }

    // ------------------------------------------------------------------
    // The closing circuit's public input
    // ------------------------------------------------------------------

    function _closingInstance(
        Dims memory d,
        Layout memory l,
        uint256[] calldata state,
        uint256[] calldata p,
        CfOut memory cf
    ) private pure returns (uint256[] memory acc) {
        uint256 rows = d.rowsW + d.rowsE;
        uint256 count = 2 + 2 * d.arity + 10 + 2 * rows + 2 + 2 * d.io + 2 * rows + 2 * COLS;
        acc = new uint256[](5 + count);
        // [comm_E = 0, u = 1, comm_W] then x.
        acc[2] = 1;
        uint256 wPos = p.length - 2;
        acc[3] = p[wPos];
        acc[4] = p[wPos + 1];
        uint256 o = 5;
        acc[o++] = state[l.last + 2]; // h = u.x
        acc[o++] = state[0];
        for (uint256 i = 0; i < 2 * d.arity; ++i) acc[o++] = state[2 + i];
        // U as the state hash absorbs it: comm_W, comm_E (two limbs per coordinate), u, x.
        o = _limbs(acc, o, state[l.acc + 3]);
        o = _limbs(acc, o, state[l.acc + 4]);
        o = _limbs(acc, o, state[l.acc]);
        o = _limbs(acc, o, state[l.acc + 1]);
        acc[o++] = state[l.acc + 2];
        acc[o++] = state[l.acc + 5];
        // U_cf: row coordinates, then u and x as limbs.
        for (uint256 i = l.cf; i < l.cfU; ++i) acc[o++] = state[i];
        for (uint256 i = l.cfU; i < l.length; ++i) o = _limbs(acc, o, state[i]);
        // Row weights s = (γ·L_W, L_E), as t with 2^255 + 2t + 1 ≡ s.
        uint256[] memory lw = _eqTable(cf.ry, 1, d.logN - LOG_COLS);
        uint256[] memory le = _eqTable(cf.rx, 0, d.logM - LOG_COLS);
        for (uint256 i = 0; i < lw.length; ++i) o = _limbs(acc, o, _oddT(mulmod(cf.gamma, lw[i], Q)));
        for (uint256 i = 0; i < le.length; ++i) o = _limbs(acc, o, _oddT(le[i]));
        // The combined row c = γ·w' + e', two limbs per value.
        if (o + 2 * COLS != acc.length) revert MalformedInput();
        uint256 gamma = cf.gamma;
        assembly ("memory-safe") {
            let rowE := add(p.offset, shl(5, sub(wPos, shl(1, COLS))))
            let rowW := add(rowE, shl(5, COLS))
            let dst := add(add(acc, 0x20), shl(5, o))
            for { let j := 0 } lt(j, COLS) { j := add(j, 1) } {
                let c := addmod(mulmod(gamma, calldataload(add(rowW, shl(5, j))), Q), calldataload(add(rowE, shl(5, j))), Q)
                mstore(dst, and(c, LIMB_MASK))
                mstore(add(dst, 0x20), shr(128, c))
                dst := add(dst, 0x40)
            }
        }
    }

    function _oddT(uint256 s) private pure returns (uint256) {
        return mulmod(addmod(s, Q - ODD_K, Q), INV2_Q, Q);
    }

    function _limbs(uint256[] memory out, uint256 o, uint256 v) private pure returns (uint256) {
        out[o] = v & LIMB_MASK;
        out[o + 1] = v >> 128;
        return o + 2;
    }

    // ------------------------------------------------------------------
    // Sum-check and multilinear helpers over F_q
    // ------------------------------------------------------------------

    function _sumcheck(bytes32 tr, uint256 claim, uint256 rounds, uint256 degree, uint256[] calldata msgs)
        private
        pure
        returns (bytes32, uint256, uint256[] memory point)
    {
        point = new uint256[](rounds);
        for (uint256 i = 0; i < rounds; ++i) {
            uint256[] calldata m = msgs[i * degree:(i + 1) * degree];
            tr = _absorb(tr, abi.encodePacked(m));
            uint256 r;
            (tr, r) = _challenge(tr, Q);
            point[i] = r;
            uint256 p1 = addmod(claim, Q - m[0] % Q, Q);
            claim = degree == 2 ? _interp2(m[0], p1, m[1], r) : _interp3(m[0], p1, m[1], m[2], r);
        }
        return (tr, claim, point);
    }

    function _interp2(uint256 p0, uint256 p1, uint256 p2, uint256 r) private pure returns (uint256) {
        uint256 r1 = addmod(r, Q - 1, Q);
        uint256 r2 = addmod(r, Q - 2, Q);
        return addmod(
            mulmod(mulmod(p0, INV2_Q, Q), mulmod(r1, r2, Q), Q),
            addmod(Q - mulmod(p1, mulmod(r, r2, Q), Q), mulmod(mulmod(p2, INV2_Q, Q), mulmod(r, r1, Q), Q), Q),
            Q
        );
    }

    function _interp3(uint256 p0, uint256 p1, uint256 p2, uint256 p3, uint256 r)
        private
        pure
        returns (uint256)
    {
        uint256 r1 = addmod(r, Q - 1, Q);
        uint256 r2 = addmod(r, Q - 2, Q);
        uint256 r3 = addmod(r, Q - 3, Q);
        uint256 acc = mulmod(p0, Q - mulmod(mulmod(mulmod(r1, r2, Q), r3, Q), INV6_Q, Q), Q);
        acc = addmod(acc, mulmod(p1, mulmod(mulmod(mulmod(r, r2, Q), r3, Q), INV2_Q, Q), Q), Q);
        acc = addmod(acc, mulmod(p2, Q - mulmod(mulmod(mulmod(r, r1, Q), r3, Q), INV2_Q, Q), Q), Q);
        return addmod(acc, mulmod(p3, mulmod(mulmod(mulmod(r, r1, Q), r2, Q), INV6_Q, Q), Q), Q);
    }

    function _eqPoints(uint256[] memory a, uint256[] memory b) private pure returns (uint256 acc) {
        acc = 1;
        for (uint256 i = 0; i < a.length; ++i) {
            uint256 term = addmod(
                mulmod(a[i], b[i], Q),
                mulmod(addmod(1, Q - a[i], Q), addmod(1, Q - b[i], Q), Q),
                Q
            );
            acc = mulmod(acc, term, Q);
        }
    }

    /// @dev The table `eq(point[start..start+len], ·)` (first variable = MSB).
    function _eqTable(uint256[] memory point, uint256 start, uint256 len)
        private
        pure
        returns (uint256[] memory t)
    {
        if (start + len > point.length) revert MalformedInput();
        t = new uint256[](1 << len);
        assembly ("memory-safe") {
            let base := add(t, 0x20)
            mstore(base, 1)
            let r := add(add(point, 0x20), shl(5, start))
            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                let ri := mload(add(r, shl(5, i)))
                for { let j := shl(i, 1) } gt(j, 0) { j := sub(j, 1) } {
                    let v := mload(add(base, shl(5, sub(j, 1))))
                    let h := mulmod(v, ri, Q)
                    let dst := add(base, shl(6, sub(j, 1)))
                    mstore(add(dst, 0x20), h)
                    mstore(dst, addmod(v, sub(Q, h), Q))
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Transcript and BN254 helpers
    // ------------------------------------------------------------------

    /// @dev `transcript ← keccak256(0 ‖ transcript ‖ words)`.
    function _absorb(bytes32 tr, bytes memory words) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(uint256(0), tr, words));
    }

    /// @dev `transcript ← keccak256(1 ‖ transcript)`; returns it modulo `m`.
    function _challenge(bytes32 tr, uint256 m) private pure returns (bytes32 next, uint256 c) {
        next = keccak256(abi.encodePacked(uint256(1), tr));
        c = uint256(next) % m;
    }

    function _neg(uint256 y) private pure returns (uint256) {
        return y == 0 ? 0 : Q - y;
    }

    /// @dev `e(L, G₂)·e(−Rt, [τ]₂) = 1` for `lr = (L, Rt)`.
    function _pairing(uint256[4] memory lr, uint256[] calldata key) private view {
        uint256[12] memory input = [
            lr[0], lr[1], G2_X_IM, G2_X_RE, G2_Y_IM, G2_Y_RE,
            lr[2], _neg(lr[3]), key[19], key[20], key[21], key[22]
        ];
        bool ok;
        uint256[1] memory out;
        assembly ("memory-safe") {
            ok := staticcall(gas(), 0x08, input, 0x180, out, 0x20)
        }
        if (!ok || out[0] != 1) revert InvalidProof(19);
    }

    /// @dev Returns `(ax, ay) + k·(bx, by)`; the identity is `(0, 0)`.
    function _addMul(uint256 ax, uint256 ay, uint256 bx, uint256 by, uint256 k)
        private
        view
        returns (uint256, uint256)
    {
        uint256[4] memory buf;
        bool ok;
        buf[0] = bx;
        buf[1] = by;
        buf[2] = k;
        assembly ("memory-safe") {
            ok := staticcall(gas(), 0x07, buf, 0x60, buf, 0x40)
        }
        if (!ok) revert InvalidPoint();
        buf[2] = ax;
        buf[3] = ay;
        assembly ("memory-safe") {
            ok := staticcall(gas(), 0x06, buf, 0x80, buf, 0x40)
        }
        if (!ok) revert InvalidPoint();
        return (buf[0], buf[1]);
    }
}
