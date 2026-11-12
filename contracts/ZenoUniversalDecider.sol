// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/// @title ZenoUniversalDecider — on-chain verifier of the universal decider
/// @notice Verifies that a KZG-committed relaxed R1CS accumulator is
/// satisfiable for a circuit given only by seven public commitments to its
/// matrices. There are no per-circuit proving or verifying keys and no
/// per-circuit secret: the only trusted input is the universal reference
/// string (its `[τ]₂`).
///
/// The proof is the Fiat–Shamir transcript of four sum-checks (constraint
/// check, matrix-vector reduction, matrix evaluation with LogUp lookups, and
/// the two lookup tables) followed by five HyperKZG openings that share one
/// pairing check. This contract replays exactly the transcript of
/// `evm-verifier::universal`.
contract ZenoUniversalDecider {
    /// Order of the BN254 scalar field.
    uint256 internal constant R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    /// Modulus of the BN254 base field.
    uint256 internal constant Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 internal constant INV2 =
        10944121435919637611123202872628637544274182200208017171849102093287904247809;
    uint256 internal constant INV6 =
        18240202393199396018538671454381062573790303667013361953081836822146507079681;
    // Generator of G2, in the precompile's (imaginary, real) coordinate order.
    uint256 internal constant G2_X_IM =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 internal constant G2_X_RE =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 internal constant G2_Y_IM =
        4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 internal constant G2_Y_RE =
        8495653923123431417604973247489272438418190587263600148770280649306958101930;

    bytes32 internal constant DOMAIN = keccak256("zeno-llull/universal-decider/v1");

    error InvalidProof(uint256 step);
    error InvalidPoint();
    error MalformedInput();

    /// Fiat–Shamir transcript and a read cursor over the proof words.
    struct State {
        bytes32 transcript;
        uint256[] proof;
        uint256 pos;
        // Challenges shared by the lookup sum-checks.
        uint256 beta;
        uint256 gamma;
        // Accumulated pairing equation e(L, G2) = e(Rt, [τ]₂).
        uint256 lx;
        uint256 ly;
        uint256 rx;
        uint256 ry;
        // Scalar of the generator term −(Σ …)·G, applied once at the end.
        uint256 gAcc;
    }

    /// @notice Verifies a universal decider proof; reverts if it is invalid.
    /// @param vk identifier of the circuit and commitment key (as in sessions).
    /// @param key `[log_m, log_n, log_k, row, col, val_A, val_B, val_C,
    /// count_row, count_col, H, [τ]₂]`: dimensions, the seven matrix
    /// commitments, the blinding generator and `[τ]₂` (23 words).
    /// @param acc the accumulator `[comm_E, u, comm_W, x…]`.
    /// @param proof the proof words, in protocol order.
    function verify(
        bytes32 vk,
        uint256[] calldata key,
        uint256[] calldata acc,
        uint256[] calldata proof
    ) external view returns (bool) {
        if (key.length != 23 || acc.length < 6) revert MalformedInput();
        uint256 logM = key[0];
        uint256 logN = key[1];
        uint256 logK = key[2];
        if (logM < 2 || logN < 2 || logK < 2 || logM > 32 || logN > 32 || logK > 32) {
            revert MalformedInput();
        }

        State memory s;
        s.proof = proof;
        s.transcript = DOMAIN;
        uint256 rW = _next(s);
        uint256 rE = _next(s);
        {
            uint256[] memory head = new uint256[](2);
            head[0] = uint256(vk);
            head[1] = uint256(keccak256(abi.encodePacked(key[0:17])));
            uint256[] memory blinds = new uint256[](2);
            blinds[0] = rW;
            blinds[1] = rE;
            s.transcript = keccak256(abi.encodePacked(uint256(0), s.transcript, head, acc, blinds));
        }

        // ---- 1. Outer sum-check: Σ eq(τ,x)·(Az·Bz − u·Cz − E)(x) = 0 --------
        uint256[] memory tau = _challenges(s, logM);
        (uint256 claim, uint256[] memory rx) = _sumcheck(s, 0, logM, 3);
        uint256[] memory claims = _take(s, 4);
        {
            uint256 rhs = addmod(
                mulmod(claims[0], claims[1], R),
                R - addmod(mulmod(acc[2], claims[2], R), claims[3], R),
                R
            );
            if (claim != mulmod(_eqPoints(tau, rx), rhs, R)) revert InvalidProof(1);
        }
        _absorb(s, claims);

        // ---- 2. Inner sum-check: Σ (A+ρB+ρ²C)(r_x,y)·Z(y) = v_A+ρv_B+ρ²v_C ---
        uint256 rho = _challenge(s);
        uint256[] memory ry;
        (claim, ry) = _sumcheck(
            s,
            addmod(
                claims[0],
                addmod(mulmod(rho, claims[1], R), mulmod(mulmod(rho, rho, R), claims[2], R), R),
                R
            ),
            logN + 1,
            2
        );
        uint256[] memory vmw = _take(s, 2); // v_M, v_W
        uint256[] memory tail = _tail(ry);
        {
            // Z(r_y) = (1 − r_y0)·W(r_y') + r_y0·IO(r_y'), IO = (u, x, 0, …).
            uint256 io = mulmod(acc[2], _eqAt(tail, 0), R);
            for (uint256 i = 5; i < acc.length; ++i) {
                io = addmod(io, mulmod(acc[i], _eqAt(tail, i - 4), R), R);
            }
            uint256 z = addmod(mulmod(addmod(1, R - ry[0], R), vmw[1], R), mulmod(ry[0], io, R), R);
            if (claim != mulmod(vmw[0], z, R)) revert InvalidProof(2);
        }
        _absorb(s, vmw);

        // ---- 3. Lookup commitments and sums ---------------------------------
        uint256[] memory comms = _take(s, 12); // e_row, e_col, h1_row, h1_col, h2_row, h2_col
        _absorb(s, _slice(comms, 0, 4));
        s.beta = _challenge(s);
        s.gamma = _challenge(s);
        _absorb(s, _slice(comms, 4, 8));
        uint256[] memory sums = _take(s, 2);
        _absorb(s, sums);

        // ---- 4. Sum-check over the matrix entries ----------------------------
        uint256[] memory rk;
        uint256[] memory evalsK;
        {
            uint256 delta = _challenge(s);
            uint256[] memory tauK = _challenges(s, logK);
            uint256 d2 = mulmod(delta, delta, R);
            (claim, rk) = _sumcheck(
                s,
                addmod(vmw[0], addmod(mulmod(delta, sums[0], R), mulmod(d2, sums[1], R), R), R),
                logK,
                3
            );
            evalsK = _take(s, 9); // val_A, val_B, val_C, row, col, e_row, e_col, h1_row, h1_col
            uint256 valRho = addmod(
                evalsK[0],
                addmod(mulmod(rho, evalsK[1], R), mulmod(mulmod(rho, rho, R), evalsK[2], R), R),
                R
            );
            uint256 eq = _eqPoints(tauK, rk);
            uint256 expected = mulmod(mulmod(valRho, evalsK[5], R), evalsK[6], R);
            expected = addmod(expected, mulmod(delta, evalsK[7], R), R);
            expected = addmod(expected, mulmod(d2, evalsK[8], R), R);
            expected = addmod(
                expected,
                mulmod(mulmod(d2, delta, R), mulmod(eq, _lookupTerm(s, evalsK[7], evalsK[3], evalsK[5], 1), R), R),
                R
            );
            expected = addmod(
                expected,
                mulmod(mulmod(d2, d2, R), mulmod(eq, _lookupTerm(s, evalsK[8], evalsK[4], evalsK[6], 1), R), R),
                R
            );
            if (claim != expected) revert InvalidProof(3);
            _absorb(s, evalsK);
        }

        // ---- 5. Sum-checks over the two lookup tables -------------------------
        (uint256[] memory rj, uint256[] memory evalsM) = _tableCheck(s, logM, sums[0], rx, 4);
        (uint256[] memory rz, uint256[] memory evalsZ) = _tableCheck(s, logN + 1, sums[1], ry, 5);

        // ---- 6. Openings, sharing one pairing check ---------------------------
        {
            // E at r_x and W at r_y', after removing the blinding r·H.
            uint256[] memory c = new uint256[](2);
            (c[0], c[1]) = _addMul(acc[0], acc[1], key[17], _neg(key[18]), rE);
            _open(s, c, rx, _slice(claims, 3, 1));
            (c[0], c[1]) = _addMul(acc[3], acc[4], key[17], _neg(key[18]), rW);
            _open(s, c, tail, _slice(vmw, 1, 1));
        }
        {
            // val_A, val_B, val_C, row, col, e_row, e_col, h1_row, h1_col at r_k.
            uint256[] memory c = new uint256[](18);
            for (uint256 i = 0; i < 6; ++i) c[i] = key[7 + i];
            for (uint256 i = 0; i < 4; ++i) c[6 + i] = key[3 + i];
            for (uint256 i = 0; i < 8; ++i) c[10 + i] = comms[i];
            _open(s, c, rk, evalsK);
        }
        {
            uint256[] memory c = new uint256[](4);
            (c[0], c[1], c[2], c[3]) = (comms[8], comms[9], key[13], key[14]);
            _open(s, c, rj, evalsM);
            (c[0], c[1], c[2], c[3]) = (comms[10], comms[11], key[15], key[16]);
            _open(s, c, rz, evalsZ);
        }
        if (s.pos != s.proof.length) revert MalformedInput();

        // The generator terms of all openings: L ← L − gAcc·G.
        (s.lx, s.ly) = _addMul(s.lx, s.ly, 1, Q - 2, s.gAcc);
        // e(L, G₂) · e(−Rt, [τ]₂) = 1
        uint256[12] memory input = [
            s.lx, s.ly, G2_X_IM, G2_X_RE, G2_Y_IM, G2_Y_RE,
            s.rx, _neg(s.ry), key[19], key[20], key[21], key[22]
        ];
        bool ok;
        uint256[1] memory out;
        assembly ("memory-safe") {
            ok := staticcall(gas(), 0x08, input, 0x180, out, 0x20)
        }
        if (!ok || out[0] != 1) revert InvalidProof(9);
        return true;
    }

    // ------------------------------------------------------------------
    // Protocol pieces
    // ------------------------------------------------------------------

    /// @dev `h·(γ + index + β·e) − sub`: the LogUp numerator constraint.
    function _lookupTerm(State memory s, uint256 h, uint256 index, uint256 e, uint256 sub)
        private
        pure
        returns (uint256)
    {
        uint256 denominator = addmod(s.gamma, addmod(index, mulmod(s.beta, e, R), R), R);
        return addmod(mulmod(h, denominator, R), R - sub, R);
    }

    /// @dev Sum-check of one lookup table (`eq(point, ·)` at indices `j`):
    /// `Σ_j [h2(j) + δ·eq(τ,j)·(h2(j)·(γ + j + β·eq(point,j)) − count(j))] = sum`.
    function _tableCheck(State memory s, uint256 log, uint256 sum, uint256[] memory point, uint256 step)
        private
        pure
        returns (uint256[] memory r, uint256[] memory evals)
    {
        uint256 delta = _challenge(s);
        uint256[] memory tau = _challenges(s, log);
        uint256 claim;
        (claim, r) = _sumcheck(s, sum, log, 3);
        evals = _take(s, 2); // h2, count
        uint256 index;
        for (uint256 i = 0; i < log; ++i) {
            index = addmod(addmod(index, index, R), r[i], R);
        }
        uint256 term = _lookupTerm(s, evals[0], index, _eqPoints(point, r), evals[1]);
        uint256 expected = addmod(evals[0], mulmod(delta, mulmod(_eqPoints(tau, r), term, R), R), R);
        if (claim != expected) revert InvalidProof(step);
        _absorb(s, evals);
    }

    /// @dev Verifies `rounds` rounds of a degree-`degree` sum-check starting
    /// from `claim`; returns the reduced claim and the challenge point.
    function _sumcheck(State memory s, uint256 claim, uint256 rounds, uint256 degree)
        private
        pure
        returns (uint256, uint256[] memory point)
    {
        point = new uint256[](rounds);
        for (uint256 i = 0; i < rounds; ++i) {
            uint256[] memory m = _take(s, degree);
            _absorb(s, m);
            uint256 r = _challenge(s);
            point[i] = r;
            // p(0) = m[0], p(1) = claim − m[0], p(2) = m[1], (p(3) = m[2]).
            uint256 e1 = addmod(claim, R - m[0] % R, R);
            uint256 r1 = addmod(r, R - 1, R);
            uint256 r2 = addmod(r, R - 2, R);
            if (degree == 2) {
                // p(r) = p0·(r−1)(r−2)/2 − p1·r(r−2) + p2·r(r−1)/2
                claim = addmod(
                    mulmod(mulmod(m[0], INV2, R), mulmod(r1, r2, R), R),
                    addmod(
                        R - mulmod(e1, mulmod(r, r2, R), R),
                        mulmod(mulmod(m[1], INV2, R), mulmod(r, r1, R), R),
                        R
                    ),
                    R
                );
            } else {
                uint256 r3 = addmod(r, R - 3, R);
                // Lagrange basis on the nodes 0, 1, 2, 3.
                uint256 l0 = R - mulmod(mulmod(mulmod(r1, r2, R), r3, R), INV6, R);
                uint256 l1 = mulmod(mulmod(mulmod(r, r2, R), r3, R), INV2, R);
                uint256 l2 = R - mulmod(mulmod(mulmod(r, r1, R), r3, R), INV2, R);
                uint256 l3 = mulmod(mulmod(mulmod(r, r1, R), r2, R), INV6, R);
                claim = addmod(
                    addmod(mulmod(m[0], l0, R), mulmod(e1, l1, R), R),
                    addmod(mulmod(m[1], l2, R), mulmod(m[2], l3, R), R),
                    R
                );
            }
        }
        return (claim, point);
    }

    /// @dev HyperKZG: verifies the evaluations `values` at `point` of the
    /// polynomials committed in `comms` (pairs of words), up to a pairing
    /// equation `e(L, G₂) = e(Rt, [τ]₂)`. The equation is added, with a fresh
    /// random weight, to the one accumulated in `s`, so that all openings of
    /// a proof are settled by a single pairing check. The weight is folded
    /// into the scalars, which costs no extra scalar multiplication.
    function _open(
        State memory s,
        uint256[] memory comms,
        uint256[] memory point,
        uint256[] memory values
    ) private view {
        uint256 ell = point.length;
        _absorb(s, point);
        _absorb(s, values);
        uint256 q = _challenge(s);
        // Random linear combination of the claimed values.
        uint256 value = values[0];
        {
            uint256 qi = q;
            for (uint256 i = 1; i < values.length; ++i) {
                value = addmod(value, mulmod(qi, values[i], R), R);
                qi = mulmod(qi, q, R);
            }
        }

        uint256[] memory folded = _take(s, 2 * (ell - 1));
        _absorb(s, folded);
        uint256 r = _challenge(s);
        if (r == 0) revert InvalidProof(6);
        uint256[] memory yPos = _take(s, ell);
        uint256[] memory yNeg = _take(s, ell);
        uint256[] memory ySq = _take(s, ell - 1);
        _absorb(s, yPos);
        _absorb(s, yNeg);
        _absorb(s, ySq);

        _foldingCheck(point, yPos, yNeg, ySq, value, r);

        // Batched KZG openings at r, −r and r²:
        //   L = (1+g)·C + (1+g+g²)·T − (b⁺ + g·b⁻ + g²·b^sq)·G + r·π₀ − g·r·π₁ + g²·r²·π₂
        //   Rt = π₀ + g·π₁ + g²·π₂
        // with C = Σ qⁱ·Cᵢ and T = Σ_{i≥1} dⁱ·Pᵢ, everything scaled by w.
        uint256[5] memory ch; // d, g, w, q, r
        ch[0] = _challenge(s);
        uint256[] memory pi = _take(s, 6);
        _absorb(s, pi);
        ch[1] = _challenge(s);
        ch[2] = _challenge(s);
        ch[3] = q;
        ch[4] = r;
        _openCommitments(s, comms, values.length, ch);
        _openFolded(s, folded, yPos, yNeg, ySq, ch);
        _openProofs(s, pi, ch);
    }

    /// @dev Folding consistency of HyperKZG:
    /// `2r·P_{i+1}(r²) = r(1−u_i)(y⁺+y⁻) + u_i(y⁺−y⁻)`, ending in `value`.
    function _foldingCheck(
        uint256[] memory point,
        uint256[] memory yPos,
        uint256[] memory yNeg,
        uint256[] memory ySq,
        uint256 value,
        uint256 r
    ) private pure {
        uint256 ell = point.length;
        for (uint256 i = 0; i < ell; ++i) {
            uint256 u = point[ell - 1 - i];
            uint256 lhs = mulmod(addmod(r, r, R), i + 1 < ell ? ySq[i] : value, R);
            uint256 rhs = addmod(
                mulmod(mulmod(r, addmod(1, R - u, R), R), addmod(yPos[i], yNeg[i], R), R),
                mulmod(u, addmod(yPos[i], R - yNeg[i] % R, R), R),
                R
            );
            if (lhs != rhs) revert InvalidProof(6);
        }
    }

    /// @dev `L += w·(1+g)·Σ qⁱ·Cᵢ`.
    function _openCommitments(State memory s, uint256[] memory comms, uint256 n, uint256[5] memory ch)
        private
        view
    {
        uint256 coeff = mulmod(ch[2], addmod(1, ch[1], R), R);
        for (uint256 i = 0; i < n; ++i) {
            (s.lx, s.ly) = _addMul(s.lx, s.ly, comms[2 * i], comms[2 * i + 1], coeff);
            coeff = mulmod(coeff, ch[3], R);
        }
    }

    /// @dev `L += w·(1+g+g²)·Σ_{i≥1} dⁱ·Pᵢ` and the generator scalar
    /// `gAcc += w·(b⁺ + g·b⁻ + g²·b^sq)`.
    function _openFolded(
        State memory s,
        uint256[] memory folded,
        uint256[] memory yPos,
        uint256[] memory yNeg,
        uint256[] memory ySq,
        uint256[5] memory ch
    ) private view {
        uint256 g2 = mulmod(ch[1], ch[1], R);
        uint256 coeff = mulmod(ch[2], addmod(addmod(1, ch[1], R), g2, R), R);
        uint256[3] memory b = [yPos[0], yNeg[0], 0];
        uint256 di = ch[0];
        for (uint256 i = 1; i < yPos.length; ++i) {
            (s.lx, s.ly) = _addMul(
                s.lx, s.ly, folded[2 * (i - 1)], folded[2 * i - 1], mulmod(coeff, di, R)
            );
            b[0] = addmod(b[0], mulmod(di, yPos[i], R), R);
            b[1] = addmod(b[1], mulmod(di, yNeg[i], R), R);
            b[2] = addmod(b[2], mulmod(di, ySq[i - 1], R), R);
            di = mulmod(di, ch[0], R);
        }
        uint256 total = addmod(b[0], addmod(mulmod(ch[1], b[1], R), mulmod(g2, b[2], R), R), R);
        s.gAcc = addmod(s.gAcc, mulmod(ch[2], total, R), R);
    }

    /// @dev `L += w·(r·π₀ − g·r·π₁ + g²·r²·π₂)`, `Rt += w·(π₀ + g·π₁ + g²·π₂)`.
    function _openProofs(State memory s, uint256[] memory pi, uint256[5] memory ch) private view {
        uint256 r = ch[4];
        uint256 w = ch[2];
        uint256 wg = mulmod(w, ch[1], R);
        uint256 wg2 = mulmod(wg, ch[1], R);
        (s.lx, s.ly) = _addMul(s.lx, s.ly, pi[0], pi[1], mulmod(w, r, R));
        (s.lx, s.ly) = _addMul(s.lx, s.ly, pi[2], pi[3], R - mulmod(wg, r, R));
        (s.lx, s.ly) = _addMul(s.lx, s.ly, pi[4], pi[5], mulmod(wg2, mulmod(r, r, R), R));
        (s.rx, s.ry) = _addMul(s.rx, s.ry, pi[0], pi[1], w);
        (s.rx, s.ry) = _addMul(s.rx, s.ry, pi[2], pi[3], wg);
        (s.rx, s.ry) = _addMul(s.rx, s.ry, pi[4], pi[5], wg2);
    }

    // ------------------------------------------------------------------
    // Multilinear helpers
    // ------------------------------------------------------------------

    /// @dev `eq(a, b) = Π (a_i·b_i + (1 − a_i)(1 − b_i))`.
    function _eqPoints(uint256[] memory a, uint256[] memory b) private pure returns (uint256 acc) {
        acc = 1;
        for (uint256 i = 0; i < a.length; ++i) {
            uint256 term = addmod(
                mulmod(a[i], b[i], R),
                mulmod(addmod(1, R - a[i], R), addmod(1, R - b[i], R), R),
                R
            );
            acc = mulmod(acc, term, R);
        }
    }

    /// @dev `eq(point, index)` for a boolean index (first variable = MSB).
    function _eqAt(uint256[] memory point, uint256 index) private pure returns (uint256 acc) {
        uint256 n = point.length;
        if (index >> n != 0) return 0;
        acc = 1;
        for (uint256 j = 0; j < n; ++j) {
            uint256 bit = (index >> (n - 1 - j)) & 1;
            acc = mulmod(acc, bit == 1 ? point[j] : addmod(1, R - point[j], R), R);
        }
    }

    function _tail(uint256[] memory v) private pure returns (uint256[] memory) {
        return _slice(v, 1, v.length - 1);
    }

    function _slice(uint256[] memory v, uint256 start, uint256 n)
        private
        pure
        returns (uint256[] memory out)
    {
        if (start + n > v.length) revert MalformedInput();
        assembly ("memory-safe") {
            out := mload(0x40)
            mstore(out, n)
            mcopy(add(out, 0x20), add(add(v, 0x20), mul(start, 0x20)), mul(n, 0x20))
            mstore(0x40, add(add(out, 0x20), mul(n, 0x20)))
        }
    }

    // ------------------------------------------------------------------
    // Transcript and proof cursor
    // ------------------------------------------------------------------

    function _next(State memory s) private pure returns (uint256 v) {
        if (s.pos >= s.proof.length) revert MalformedInput();
        v = s.proof[s.pos++];
    }

    function _take(State memory s, uint256 n) private pure returns (uint256[] memory out) {
        out = _slice(s.proof, s.pos, n);
        s.pos += n;
    }

    /// @dev `transcript ← keccak256(0 ‖ transcript ‖ words)`, hashed in
    /// scratch memory past the free pointer.
    function _absorb(State memory s, uint256[] memory words) private pure {
        bytes32 state = s.transcript;
        assembly ("memory-safe") {
            let len := mul(mload(words), 0x20)
            let ptr := mload(0x40)
            mstore(ptr, 0)
            mstore(add(ptr, 0x20), state)
            mcopy(add(ptr, 0x40), add(words, 0x20), len)
            state := keccak256(ptr, add(len, 0x40))
        }
        s.transcript = state;
    }

    /// @dev `transcript ← keccak256(1 ‖ transcript)`; returns it modulo `r`.
    function _challenge(State memory s) private pure returns (uint256) {
        bytes32 state = s.transcript;
        assembly ("memory-safe") {
            mstore(0x00, 1)
            mstore(0x20, state)
            state := keccak256(0x00, 0x40)
        }
        s.transcript = state;
        return uint256(state) % R;
    }

    function _challenges(State memory s, uint256 n) private pure returns (uint256[] memory out) {
        out = new uint256[](n);
        for (uint256 i = 0; i < n; ++i) out[i] = _challenge(s);
    }

    // ------------------------------------------------------------------
    // BN254 arithmetic through the EIP-196 precompiles
    // ------------------------------------------------------------------

    function _neg(uint256 y) private pure returns (uint256) {
        return y == 0 ? 0 : Q - y;
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
