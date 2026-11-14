// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {ZenoBn254, ZenoFq} from "./lib/ZenoBn254.sol";

import {ZenoCycleFoldShape} from "./ZenoCycleFoldShape.sol";
import {ZenoFees} from "./lib/ZenoFees.sol";

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
/// CycleFold matrices hash)`, which anyone can recompute from the step
/// circuit and the public reference string.
///
/// One Keccak transcript (replaying `evm-verifier::recursive` exactly):
/// 1. folds the last primary instance `u` into `U`, then a random masking
///    instance (zero knowledge), with on-chain NIFS folds;
/// 2. decides the CycleFold accumulator with a Spartan-style argument over
///    `F_q`, evaluating the fixed CycleFold matrices itself from their
///    uniform records (`ZenoCycleFoldShape`) with the Hyrax tables; its
///    Hyrax openings reduce to the combined rows `e'`, `w'`, whose inner
///    products it checks;
/// 3. assembles the public input of the closing circuit, which proves the
///    remaining Grumpkin equation and recomputes `u.x = H(vk, i, z₀, zᵢ, U, U_cf)`;
/// 4. verifies one batched universal decider proof for the masked primary
///    accumulator and the closing instance, and checks its pairing equation.
contract ZenoRecursiveVerifier is ZenoFees {
    /// Order of the BN254 scalar field.
    uint256 internal constant R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    /// Modulus of the BN254 base field (= the order of Grumpkin).
    uint256 internal constant Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 internal constant INV2_Q =
        10944121435919637611123202872628637544348155578648911831344518947322613104292;
    /// `(1 + 2^255) mod q`: a row weight `s` reaches the closing circuit as
    /// the `t` with `2^255 + 2t + 1 ≡ s`.
    uint256 internal constant ODD_K =
        14119558874979547267292681013829403749242370018224634694350716214666112402803;
    uint256 internal constant LOG_COLS = 7;
    uint256 internal constant COLS = 128;
    uint256 internal constant LIMB_MASK = (1 << 128) - 1;

    bytes32 internal constant DOMAIN = keccak256("zeno-llull/recursive-decider/v1");

    IZenoBatchedDecider public immutable decider;
    /// `keccak256(systemId ‖ keccak256(i ‖ z₀ ‖ zᵢ))` of every decided claim.
    mapping(bytes32 => bool) public decided;

    event RecursiveDecided(bytes32 indexed systemId, uint64 steps, bytes32 claimHash);

    error MalformedInput();
    error InvalidProof(uint256 step);
    error AlreadyDecided();

    /// Dimensions read from the header of the CycleFold records.
    struct Dims {
        uint256 logM;
        uint256 logN;
        uint256 io;
        uint256 rowsW;
        uint256 rowsE;
        uint256 arity;
        bytes data; // ZenoCycleFoldShape.DATA
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

    /// The CycleFold argument's outputs needed for the closing input: the
    /// points and the Hyrax row weights `L_W = eq(r_y[1..1+b], ·)`,
    /// `L_E = eq(r_x[0..b], ·)` (`b` row bits).
    struct CfOut {
        uint256[] rx;
        uint256[] ry;
        uint256[] lw;
        uint256[] le;
        uint256 gamma;
    }

    /// @param decisionFee_ fee per `finalizeRecursive`; @param maxFee_ its
    /// permanent cap. No step is folded on-chain here, so `stepFee` starts
    /// at zero and is not charged. Fees never affect what is decided.
    constructor(IZenoBatchedDecider decider_, uint256 decisionFee_, uint256 maxFee_)
        ZenoFees(0, decisionFee_, maxFee_)
    {
        decider = decider_;
    }

    /// @notice `keccak256` of the CycleFold records: the CycleFold part of
    /// every system id.
    function cfShapeHash() external pure returns (bytes32) {
        return ZenoCycleFoldShape.HASH;
    }

    /// @notice Decides a final IVC state; reverts if any check fails. Costs
    /// `decisionFee` (`msg.value`). A claim `(i, z₀, zᵢ)` already decided for
    /// this system reverts at once with `AlreadyDecided` (read `decided`).
    /// @param primaryKey universal decider key of the primary circuit (24 words).
    /// @param closingKey universal decider key of the closing circuit (24 words).
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
    ) external payable returns (bytes32 systemId) {
        _chargeDecision();
        if (primaryKey.length != 24 || closingKey.length != 24) revert MalformedInput();
        // Both universal proofs must be over the same [τ]₂.
        for (uint256 k = 19; k < 23; ++k) {
            if (primaryKey[k] != closingKey[k]) revert MalformedInput();
        }
        bytes32 vkP = keccak256(abi.encodePacked(primaryKey));
        bytes32 vkC = keccak256(abi.encodePacked(closingKey));
        systemId = keccak256(abi.encodePacked(vkP, vkC, ZenoCycleFoldShape.HASH));

        Dims memory d = _dims(state.length > 1 ? state[1] : 0);
        Layout memory l = _layout(d);
        if (state.length != l.length || state[0] == 0 || state[0] >= 1 << 64) revert MalformedInput();
        // A claim decided before is not decided (nor paid for) again: the
        // second submission of the same `(i, z₀, zᵢ)` for this system reverts
        // after this lookup, and its fee goes back to the sender.
        bytes32 claimHash = keccak256(abi.encodePacked(state[0], state[2:2 + 2 * d.arity]));
        bytes32 claimKey = keccak256(abi.encodePacked(systemId, claimHash));
        if (decided[claimKey]) revert AlreadyDecided();
        if (cfProof.length != 3 * d.logM + 4 + 2 * (d.logN + 1) + 1 + 2 * COLS + 2) {
            revert MalformedInput();
        }
        _canonical(d, l, state, cfProof);

        bytes32 tr = DOMAIN;
        tr = _absorb(tr, abi.encodePacked(vkP, vkC, ZenoCycleFoldShape.HASH));
        tr = _absorb(tr, abi.encodePacked(state[0], state[2:2 + 2 * d.arity]));
        tr = _absorb(tr, abi.encodePacked(state[l.acc:l.commT]));

        // ---- 1. Fold u into U, then mask --------------------------------------
        uint256[] memory acc = new uint256[](6);
        {
            tr = _absorb(tr, abi.encodePacked(state[l.commT:l.commT + 2]));
            uint256 r1;
            (tr, r1) = _challenge(tr, R);
            (acc[0], acc[1]) = ZenoBn254.addMul(state[l.acc], state[l.acc + 1], state[l.commT], state[l.commT + 1], r1);
            acc[2] = addmod(state[l.acc + 2], r1, R);
            (acc[3], acc[4]) = ZenoBn254.addMul(state[l.acc + 3], state[l.acc + 4], state[l.last], state[l.last + 1], r1);
            acc[5] = addmod(state[l.acc + 5], mulmod(r1, state[l.last + 2], R), R);

            tr = _absorb(tr, abi.encodePacked(state[l.mask:l.mask + 6]));
            tr = _absorb(tr, abi.encodePacked(state[l.maskT:l.maskT + 2]));
            uint256 r2;
            (tr, r2) = _challenge(tr, R);
            uint256 m = l.mask;
            (acc[0], acc[1]) = ZenoBn254.addMul(acc[0], acc[1], state[l.maskT], state[l.maskT + 1], r2);
            (acc[0], acc[1]) = ZenoBn254.addMul(acc[0], acc[1], state[m], state[m + 1], mulmod(r2, r2, R));
            acc[2] = addmod(acc[2], mulmod(r2, state[m + 2], R), R);
            (acc[3], acc[4]) = ZenoBn254.addMul(acc[3], acc[4], state[m + 3], state[m + 4], r2);
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
            uint256[4] memory lr = decider.verifyDeferred(vks, keys, accs, deciderProof);
            // e(L, G₂) = e(Rt, [τ]₂)
            if (
                !ZenoBn254.pairingEquals(
                    lr[0], lr[1], lr[2], lr[3], primaryKey[19], primaryKey[20], primaryKey[21], primaryKey[22]
                )
            ) revert InvalidProof(19);
        }

        decided[claimKey] = true;
        emit RecursiveDecided(systemId, uint64(state[0]), claimHash);
    }

    // ------------------------------------------------------------------
    // Layout
    // ------------------------------------------------------------------

    function _dims(uint256 arity) private pure returns (Dims memory d) {
        d.data = ZenoCycleFoldShape.DATA;
        bytes memory data = d.data;
        uint256 header;
        assembly ("memory-safe") {
            header := mload(add(data, 0x20))
        }
        d.logM = header >> 248;
        d.logN = (header >> 240) & 0xff;
        d.io = (header >> 232) & 0xff;
        // The records' slots are the Hyrax columns.
        if (((header >> 224) & 0xff) != LOG_COLS || d.logM <= LOG_COLS || d.logN <= LOG_COLS) {
            revert MalformedInput();
        }
        if (arity == 0 || arity > 64) revert MalformedInput();
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

    /// @dev Every scalar is given in canonical form (below its modulus), so
    /// that a claim and a proof have one encoding. Coordinates of BN254
    /// points are checked by the precompiles; coordinates of the CycleFold
    /// rows are elements of `F_r`, scalars of the CycleFold accumulator and
    /// every word of the CycleFold argument elements of `F_q`.
    function _canonical(Dims memory d, Layout memory l, uint256[] calldata state, uint256[] calldata p)
        private
        pure
    {
        bool ok = true;
        for (uint256 i = 2; i < l.acc; ++i) ok = ok && state[i] < R;
        ok = ok && state[l.acc + 2] < R && state[l.acc + 5] < R && state[l.last + 2] < R;
        ok = ok && state[l.mask + 2] < R && state[l.mask + 5] < R;
        for (uint256 i = l.cf; i < l.cfU; ++i) ok = ok && state[i] < R;
        for (uint256 i = l.cfU; i < l.length; ++i) ok = ok && state[i] < Q;
        for (uint256 i = 0; i < p.length; ++i) ok = ok && p[i] < Q;
        if (!ok || d.arity == 0) revert MalformedInput();
    }

    // ------------------------------------------------------------------
    // The Spartan argument over F_q
    // ------------------------------------------------------------------

    /// @param ux `[U_cf.u, U_cf.x…]`.
    function _cycleFold(bytes32 tr, Dims memory d, uint256[] calldata ux, uint256[] calldata p)
        private
        pure
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
            if (claim != mulmod(ZenoFq.eqPoints(tau, out.rx), rhs, Q)) revert InvalidProof(11);
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
        // The only tables: eq over the slot (column) bits and over the type
        // (row) bits of r_x and r_y[1..].
        uint256[] memory eqE = _eqTable(out.rx, d.logM - LOG_COLS, LOG_COLS);
        uint256[] memory eqW = _eqTable(out.ry, 1 + d.logN - LOG_COLS, LOG_COLS);
        out.le = _eqTable(out.rx, 0, d.logM - LOG_COLS);
        out.lw = _eqTable(out.ry, 1, d.logN - LOG_COLS);
        {
            // Z = (W ‖ (u, x)): eq(r_y, ·) is (1 − r_y0)·eq(r_y', ·) on the
            // first half and r_y0·eq(r_y', ·) on the second; (u, x) sits in
            // the first slots of the first type.
            uint256 ry0 = out.ry[0];
            uint256 m = _matrixEval(d.data, rho, ry0, eqE, eqW, out.le, out.lw);
            if (ux.length > COLS) revert MalformedInput();
            uint256 io;
            for (uint256 i = 0; i < ux.length; ++i) io = addmod(io, mulmod(ux[i], eqW[i], Q), Q);
            io = mulmod(io, out.lw[0], Q);
            uint256 z = addmod(mulmod(addmod(1, Q - ry0, Q), vW, Q), mulmod(ry0, io, Q), Q);
            if (claim != mulmod(m, z, Q)) revert InvalidProof(12);
        }
        tr = _absorb(tr, abi.encodePacked(vW));

        // Hyrax: the combined rows open Ẽ(r_x) and W̃(r_y[1..]).
        {
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

    /// @dev `(A + ρB + ρ²C)(r_x, r_y)` from the CycleFold records (see
    /// `evm-verifier::cf_uniform`): with `X = eq(r_x,lo, ·)`, `Y = eq(r_y,lo, ·)`
    /// over the slot bits and `H_x`, `H_y` over the type bits, a record
    /// repeated over the slots contributes through one of
    /// `D₀ = Σ_j X_j·Y_j`, `D₁ = Σ_j X_j·Y_(j−1)`, `Σ_j X_j`, `Σ_j 2^(steps−j)·Y_j`.
    function _matrixEval(
        bytes memory data,
        uint256 rho,
        uint256 ry0,
        uint256[] memory xs,
        uint256[] memory ys,
        uint256[] memory hx,
        uint256[] memory hy
    ) private pure returns (uint256 total) {
        assembly ("memory-safe") {
            let header := mload(add(data, 0x20))
            let logN := byte(1, header)
            let logS := byte(3, header)
            let steps := byte(4, header)
            let values := add(data, 0x40)
            // Header bytes 5–6: number of values; 7–8: number of records.
            let rec := add(values, shl(5, and(shr(200, header), 0xffff)))
            let end := add(rec, mul(and(shr(184, header), 0xffff), 6))
            if gt(end, add(add(data, 0x20), mload(data))) { revert(0, 0) }
            let x := add(xs, 0x20)
            let y := add(ys, 0x20)
            let hxp := add(hx, 0x20)
            let hyp := add(hy, 0x20)
            let w0 := sub(add(Q, 1), ry0)
            // The sums over the slots.
            let d0 := mulmod(mload(x), mload(y), Q)
            let d1 := 0
            let sx := mload(x)
            for { let j := 1 } lt(j, steps) { j := add(j, 1) } {
                let xj := mload(add(x, shl(5, j)))
                let yj := add(y, shl(5, j))
                d0 := addmod(d0, mulmod(xj, mload(yj), Q), Q)
                d1 := addmod(d1, mulmod(xj, mload(sub(yj, 0x20)), Q), Q)
                sx := addmod(sx, xj, Q)
            }
            let pk := 0
            let w := 2
            for { let j := steps } gt(j, 0) { j := sub(j, 1) } {
                pk := addmod(pk, mulmod(w, mload(add(y, shl(5, sub(j, 1)))), Q), Q)
                w := addmod(w, w, Q)
            }
            d0 := mulmod(d0, w0, Q)
            d1 := mulmod(d1, w0, Q)
            pk := mulmod(pk, w0, Q)
            let rho2 := mulmod(rho, rho, Q)
            let sMask := sub(shl(logS, 1), 1)
            let nMask := sub(shl(logN, 1), 1)
            for { } lt(rec, end) { rec := add(rec, 6) } {
                let e := shr(208, mload(rec))
                let a := and(shr(16, e), 0xffff)
                let b := and(e, 0xffff)
                let kind := shr(42, e)
                let term := 0
                switch kind
                case 0 { term := mulmod(mulmod(mload(add(hxp, shl(5, a))), mload(add(hyp, shl(5, b))), Q), d0, Q) }
                case 1 { term := mulmod(mulmod(mload(add(hxp, shl(5, a))), mload(add(hyp, shl(5, b))), Q), d1, Q) }
                case 4 {
                    let row := mulmod(mload(add(hxp, shl(5, shr(logS, a)))), mload(add(x, shl(5, and(a, sMask)))), Q)
                    term := mulmod(mulmod(row, mload(add(hyp, shl(5, b))), Q), pk, Q)
                }
                default {
                    // A single column of the padded Z.
                    let f := w0
                    if shr(logN, b) { f := ry0 }
                    let rest := and(b, nMask)
                    let col := mulmod(
                        mulmod(f, mload(add(hyp, shl(5, shr(logS, rest)))), Q), mload(add(y, shl(5, and(rest, sMask)))), Q
                    )
                    switch kind
                    case 2 { term := mulmod(mulmod(mload(add(hxp, shl(5, a))), sx, Q), col, Q) }
                    default {
                        let row := mulmod(mload(add(hxp, shl(5, shr(logS, a)))), mload(add(x, shl(5, and(a, sMask)))), Q)
                        term := mulmod(row, col, Q)
                    }
                }
                let v := mload(add(values, shl(5, and(shr(32, e), 0xff))))
                switch and(shr(40, e), 3)
                case 1 { v := mulmod(v, rho, Q) }
                case 2 { v := mulmod(v, rho2, Q) }
                total := addmod(total, mulmod(v, term, Q), Q)
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
        for (uint256 i = 0; i < cf.lw.length; ++i) o = _limbs(acc, o, _oddT(mulmod(cf.gamma, cf.lw[i], Q)));
        for (uint256 i = 0; i < cf.le.length; ++i) o = _limbs(acc, o, _oddT(cf.le[i]));
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
            claim = degree == 2 ? ZenoFq.interp2(m[0], p1, m[1], r) : ZenoFq.interp3(m[0], p1, m[1], m[2], r);
        }
        return (tr, claim, point);
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

}
