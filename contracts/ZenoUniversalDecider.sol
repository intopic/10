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
        // The (L, R) pairs of the five openings, weighted at the end.
        uint256[20] pairs;
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
            _open(s, 0, c, rx, _slice(claims, 3, 1));
            (c[0], c[1]) = _addMul(acc[3], acc[4], key[17], _neg(key[18]), rW);
            _open(s, 1, c, tail, _slice(vmw, 1, 1));
        }
        {
            // val_A, val_B, val_C, row, col, e_row, e_col, h1_row, h1_col at r_k.
            uint256[] memory c = new uint256[](18);
            for (uint256 i = 0; i < 6; ++i) c[i] = key[7 + i];
            for (uint256 i = 0; i < 4; ++i) c[6 + i] = key[3 + i];
            for (uint256 i = 0; i < 8; ++i) c[10 + i] = comms[i];
            _open(s, 2, c, rk, evalsK);
        }
        {
            uint256[] memory c = new uint256[](4);
            (c[0], c[1], c[2], c[3]) = (comms[8], comms[9], key[13], key[14]);
            _open(s, 3, c, rj, evalsM);
            (c[0], c[1], c[2], c[3]) = (comms[10], comms[11], key[15], key[16]);
            _open(s, 4, c, rz, evalsZ);
        }
        if (s.pos != s.proof.length) revert MalformedInput();

        uint256 weight = _challenge(s);
        if (weight == 0) revert InvalidProof(8);
        uint256 w = 1;
        for (uint256 j = 0; j < 5; ++j) {
            (s.lx, s.ly) = _addMul(s.lx, s.ly, s.pairs[4 * j], s.pairs[4 * j + 1], w);
            (s.rx, s.ry) = _addMul(s.rx, s.ry, s.pairs[4 * j + 2], s.pairs[4 * j + 3], w);
            w = mulmod(w, weight, R);
        }
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
    /// polynomials committed in `comms` (pairs of words), up to the pairing
    /// equation whose two points are stored in `s.pairs[4·slot..]`.
    function _open(
        State memory s,
        uint256 slot,
        uint256[] memory comms,
        uint256[] memory point,
        uint256[] memory values
    ) private view {
        uint256 ell = point.length;
        _absorb(s, point);
        _absorb(s, values);
        uint256 q = _challenge(s);
        // Random linear combination of the commitments and of the values.
        uint256 cx = comms[0];
        uint256 cy = comms[1];
        uint256 value = values[0];
        {
            uint256 qi = q;
            for (uint256 i = 1; i < values.length; ++i) {
                (cx, cy) = _addMul(cx, cy, comms[2 * i], comms[2 * i + 1], qi);
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

        // Folding consistency: 2r·P_{i+1}(r²) = r(1−u_i)(y⁺+y⁻) + u_i(y⁺−y⁻).
        for (uint256 i = 0; i < ell; ++i) {
            uint256 u = point[ell - 1 - i];
            uint256 next = i + 1 < ell ? ySq[i] : value;
            uint256 lhs = mulmod(addmod(r, r, R), next, R);
            uint256 rhs = addmod(
                mulmod(mulmod(r, addmod(1, R - u, R), R), addmod(yPos[i], yNeg[i], R), R),
                mulmod(u, addmod(yPos[i], R - yNeg[i] % R, R), R),
                R
            );
            if (lhs != rhs) revert InvalidProof(6);
        }

        // Batched KZG openings at r, −r and r².
        uint256 d = _challenge(s);
        uint256 tailX;
        uint256 tailY;
        uint256 bPos = yPos[0];
        uint256 bNeg = yNeg[0];
        uint256 bSq;
        {
            uint256 di = d;
            for (uint256 i = 1; i < ell; ++i) {
                (tailX, tailY) = _addMul(tailX, tailY, folded[2 * (i - 1)], folded[2 * i - 1], di);
                bPos = addmod(bPos, mulmod(di, yPos[i], R), R);
                bNeg = addmod(bNeg, mulmod(di, yNeg[i], R), R);
                bSq = addmod(bSq, mulmod(di, ySq[i - 1], R), R);
                di = mulmod(di, d, R);
            }
        }
        uint256[] memory pi = _take(s, 6);
        _absorb(s, pi);
        uint256 g = _challenge(s);
        uint256 g2 = mulmod(g, g, R);

        // L = (1+g)·C + (1+g+g²)·T − (b⁺ + g·b⁻ + g²·b^sq)·G
        //     + r·π₀ − g·r·π₁ + g²·r²·π₂,        Rt = π₀ + g·π₁ + g²·π₂
        (uint256 lx, uint256 ly) = _addMul(0, 0, cx, cy, addmod(1, g, R));
        (lx, ly) = _addMul(lx, ly, tailX, tailY, addmod(addmod(1, g, R), g2, R));
        (lx, ly) = _addMul(
            lx,
            ly,
            1,
            Q - 2,
            addmod(bPos, addmod(mulmod(g, bNeg, R), mulmod(g2, bSq, R), R), R)
        );
        (lx, ly) = _addMul(lx, ly, pi[0], pi[1], r);
        (lx, ly) = _addMul(lx, ly, pi[2], pi[3], R - mulmod(g, r, R));
        (lx, ly) = _addMul(lx, ly, pi[4], pi[5], mulmod(g2, mulmod(r, r, R), R));
        (uint256 rx_, uint256 ry_) = _addMul(pi[0], pi[1], pi[2], pi[3], g);
        (rx_, ry_) = _addMul(rx_, ry_, pi[4], pi[5], g2);
        s.pairs[4 * slot] = lx;
        s.pairs[4 * slot + 1] = ly;
        s.pairs[4 * slot + 2] = rx_;
        s.pairs[4 * slot + 3] = ry_;
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
        out = new uint256[](n);
        for (uint256 i = 0; i < n; ++i) out[i] = v[start + i];
    }

    // ------------------------------------------------------------------
    // Transcript and proof cursor
    // ------------------------------------------------------------------

    function _next(State memory s) private pure returns (uint256 v) {
        if (s.pos >= s.proof.length) revert MalformedInput();
        v = s.proof[s.pos++];
    }

    function _take(State memory s, uint256 n) private pure returns (uint256[] memory out) {
        if (s.pos + n > s.proof.length) revert MalformedInput();
        out = _slice(s.proof, s.pos, n);
        s.pos += n;
    }

    function _absorb(State memory s, uint256[] memory words) private pure {
        s.transcript = keccak256(abi.encodePacked(uint256(0), s.transcript, words));
    }

    function _challenge(State memory s) private pure returns (uint256) {
        s.transcript = keccak256(abi.encodePacked(uint256(1), s.transcript));
        return uint256(s.transcript) % R;
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
