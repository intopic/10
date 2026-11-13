// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {ZenoBn254, ZenoFr} from "./lib/ZenoBn254.sol";

/// @title ZenoBatchedDecider — one universal decider proof for several circuits
/// @notice Verifies, in one argument, that several KZG-committed relaxed R1CS
/// accumulators of *different* circuits are satisfiable. The circuit keys
/// share their dimensions, so every sum-check runs once for all of them (their
/// claims combined with powers of a challenge) and five joint HyperKZG
/// openings cover every polynomial. This contract replays exactly the
/// transcript of `evm-verifier::universal::batch`; it returns the pairing
/// equation instead of checking it, so that the caller can check it.
contract ZenoBatchedDecider {
    uint256 internal constant R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    bytes32 internal constant DOMAIN = keccak256("zeno-llull/universal-batch/v1");

    error InvalidProof(uint256 step);
    error MalformedInput();

    struct State {
        bytes32 transcript;
        uint256[] proof;
        uint256 pos;
        uint256 n; // number of instances
        uint256 beta;
        uint256 gamma;
        uint256 lx;
        uint256 ly;
        uint256 rx;
        uint256 ry;
    }

    /// Values of every step, per instance (flattened).
    struct Run {
        uint256 logM;
        uint256 logN;
        uint256 logK;
        uint256[] blinds; // 2 per instance
        uint256[] claims; // 4 per instance
        uint256[] v; // 2 per instance
        uint256[] comms; // 12 words per instance: e_row, e_col, h1r, h1c, h2r, h2c
        uint256[] sums; // 2 per instance
        uint256[] evalsK; // 9 per instance
        uint256[] evalsM; // 2 per instance
        uint256[] evalsZ; // 2 per instance
        uint256[] rx;
        uint256[] ry;
        uint256[] rk;
        uint256[] rj;
        uint256[] rz;
        uint256 rho;
    }

    /// @notice Verifies a batched proof up to its pairing equation: returns
    /// `(L, Rt)` such that the proof is valid iff `e(L, G₂) = e(Rt, [τ]₂)`,
    /// with `[τ]₂` the one in every key; reverts if any other check fails.
    /// @param vks every instance's circuit identifier.
    /// @param keys every circuit's key (24 words; same dimensions and `[τ]₂`).
    /// @param accs every accumulator `[comm_E, u, comm_W, x…]`.
    function verifyDeferred(
        bytes32[] calldata vks,
        uint256[][] calldata keys,
        uint256[][] calldata accs,
        uint256[] calldata proof
    ) external view returns (uint256[4] memory lr) {
        uint256 n = vks.length;
        if (n == 0 || keys.length != n || accs.length != n) revert MalformedInput();
        Run memory run;
        for (uint256 i = 0; i < n; ++i) {
            // Exactly the circuit's public inputs (see ZenoUniversalDecider).
            if (keys[i].length != 24 || accs[i].length < 6 || accs[i].length != 5 + keys[i][23]) {
                revert MalformedInput();
            }
            for (uint256 k = 0; k < 3; ++k) {
                if (keys[i][k] != keys[0][k]) revert MalformedInput();
            }
            for (uint256 k = 19; k < 23; ++k) {
                if (keys[i][k] != keys[0][k]) revert MalformedInput();
            }
        }
        (run.logM, run.logN, run.logK) = (keys[0][0], keys[0][1], keys[0][2]);
        if (run.logM < 2 || run.logN < 2 || run.logK < 2 || run.logM > 32 || run.logN > 32 || run.logK > 32) {
            revert MalformedInput();
        }

        State memory s;
        s.proof = proof;
        s.n = n;
        s.transcript = DOMAIN;
        run.blinds = _take(s, 2 * n);
        {
            bytes memory head = abi.encodePacked(n);
            for (uint256 i = 0; i < n; ++i) {
                head = abi.encodePacked(
                    head,
                    vks[i],
                    keccak256(abi.encodePacked(keys[i])),
                    accs[i],
                    run.blinds[2 * i],
                    run.blinds[2 * i + 1]
                );
            }
            s.transcript = keccak256(abi.encodePacked(uint256(0), s.transcript, head));
        }

        _outer(s, run, accs);
        _inner(s, run, accs);
        _lookups(s, run);
        _matrixEntries(s, run);
        run.rj = _tableCheck(s, run, run.logM, 0, run.rx, 4);
        run.evalsM = _take(s, 2 * n);
        _absorb(s, run.evalsM);
        run.rz = _tableCheck(s, run, run.logN + 1, 1, run.ry, 5);
        run.evalsZ = _take(s, 2 * n);
        _absorb(s, run.evalsZ);
        _openings(s, run, keys, accs);
        if (s.pos != s.proof.length) revert MalformedInput();
        lr = [s.lx, s.ly, s.rx, s.ry];
    }

    // ------------------------------------------------------------------
    // The protocol, step by step
    // ------------------------------------------------------------------

    function _outer(State memory s, Run memory run, uint256[][] calldata accs) private pure {
        uint256[] memory tau = _challenges(s, run.logM);
        uint256 alpha = _challenge(s);
        uint256 claim;
        (claim, run.rx) = _sumcheck(s, 0, run.logM, 3);
        run.claims = _take(s, 4 * s.n);
        uint256 rhs;
        uint256 a = 1;
        for (uint256 i = 0; i < s.n; ++i) {
            uint256 b = 4 * i;
            uint256 term = addmod(
                mulmod(run.claims[b], run.claims[b + 1], R),
                R - addmod(mulmod(accs[i][2], run.claims[b + 2], R), run.claims[b + 3], R),
                R
            );
            rhs = addmod(rhs, mulmod(a, term, R), R);
            a = mulmod(a, alpha, R);
        }
        if (claim != mulmod(ZenoFr.eqPoints(tau, run.rx), rhs, R)) revert InvalidProof(1);
        _absorb(s, run.claims);
    }

    function _inner(State memory s, Run memory run, uint256[][] calldata accs) private pure {
        run.rho = _challenge(s);
        uint256 alpha2 = _challenge(s);
        uint256 rho2 = mulmod(run.rho, run.rho, R);
        uint256 start;
        uint256 a = 1;
        for (uint256 i = 0; i < s.n; ++i) {
            uint256 b = 4 * i;
            uint256 c = addmod(
                run.claims[b],
                addmod(mulmod(run.rho, run.claims[b + 1], R), mulmod(rho2, run.claims[b + 2], R), R),
                R
            );
            start = addmod(start, mulmod(a, c, R), R);
            a = mulmod(a, alpha2, R);
        }
        uint256 claim;
        (claim, run.ry) = _sumcheck(s, start, run.logN + 1, 2);
        run.v = _take(s, 2 * s.n);
        uint256[] memory tail = _slice(run.ry, 1, run.ry.length - 1);
        uint256 ry0 = run.ry[0];
        uint256 expected;
        a = 1;
        for (uint256 i = 0; i < s.n; ++i) {
            // Z_i(r_y) = (1 − r_y0)·W_i(r_y') + r_y0·IO_i(r_y').
            uint256 z = addmod(
                mulmod(addmod(1, R - ry0, R), run.v[2 * i + 1], R),
                mulmod(ry0, _ioEval(accs[i], tail), R),
                R
            );
            expected = addmod(expected, mulmod(a, mulmod(run.v[2 * i], z, R), R), R);
            a = mulmod(a, alpha2, R);
        }
        if (claim != expected) revert InvalidProof(2);
        _absorb(s, run.v);
    }

    function _lookups(State memory s, Run memory run) private pure {
        uint256 n = s.n;
        uint256[] memory first = _take(s, 4 * n); // e_row, e_col per instance
        _absorb(s, first);
        s.beta = _challenge(s);
        s.gamma = _challenge(s);
        uint256[] memory second = _take(s, 8 * n); // h1_row, h1_col, h2_row, h2_col per instance
        _absorb(s, second);
        run.comms = new uint256[](12 * n);
        for (uint256 i = 0; i < n; ++i) {
            for (uint256 j = 0; j < 4; ++j) run.comms[12 * i + j] = first[4 * i + j];
            for (uint256 j = 0; j < 8; ++j) run.comms[12 * i + 4 + j] = second[8 * i + j];
        }
        run.sums = _take(s, 2 * n);
        _absorb(s, run.sums);
    }

    function _matrixEntries(State memory s, Run memory run) private pure {
        uint256 delta = _challenge(s);
        uint256 deltaB = _challenge(s);
        uint256[] memory tauK = _challenges(s, run.logK);
        uint256 d2 = mulmod(delta, delta, R);
        uint256 start;
        uint256 a = 1;
        for (uint256 i = 0; i < s.n; ++i) {
            uint256 c = addmod(
                run.v[2 * i],
                addmod(mulmod(delta, run.sums[2 * i], R), mulmod(d2, run.sums[2 * i + 1], R), R),
                R
            );
            start = addmod(start, mulmod(a, c, R), R);
            a = mulmod(a, deltaB, R);
        }
        uint256 claim;
        (claim, run.rk) = _sumcheck(s, start, run.logK, 3);
        run.evalsK = _take(s, 9 * s.n);
        uint256 eq = ZenoFr.eqPoints(tauK, run.rk);
        uint256 expected;
        a = 1;
        for (uint256 i = 0; i < s.n; ++i) {
            expected = addmod(expected, mulmod(a, _summandK(s, run, i, eq, delta), R), R);
            a = mulmod(a, deltaB, R);
        }
        if (claim != expected) revert InvalidProof(3);
        _absorb(s, run.evalsK);
    }

    /// @dev `val_ρ·e_row·e_col + δ·h1_row + δ²·h1_col + δ³·eq·(h1_row·(γ+row+β·e_row) − 1)
    /// + δ⁴·eq·(h1_col·(γ+col+β·e_col) − 1)` for instance `i`.
    function _summandK(State memory s, Run memory run, uint256 i, uint256 eq, uint256 delta)
        private
        pure
        returns (uint256 acc)
    {
        uint256 b = 9 * i;
        uint256[] memory e = run.evalsK;
        uint256 rho = run.rho;
        uint256 valRho = addmod(
            e[b],
            addmod(mulmod(rho, e[b + 1], R), mulmod(mulmod(rho, rho, R), e[b + 2], R), R),
            R
        );
        uint256 d2 = mulmod(delta, delta, R);
        acc = mulmod(mulmod(valRho, e[b + 5], R), e[b + 6], R);
        acc = addmod(acc, mulmod(delta, e[b + 7], R), R);
        acc = addmod(acc, mulmod(d2, e[b + 8], R), R);
        acc = addmod(
            acc,
            mulmod(mulmod(d2, delta, R), mulmod(eq, _lookupTerm(s, e[b + 7], e[b + 3], e[b + 5], 1), R), R),
            R
        );
        acc = addmod(
            acc,
            mulmod(mulmod(d2, d2, R), mulmod(eq, _lookupTerm(s, e[b + 8], e[b + 4], e[b + 6], 1), R), R),
            R
        );
    }

    /// @dev Batched sum-check of one lookup table; `which` selects the
    /// instances' LogUp sums (0: rows, 1: columns). Leaves the evaluations
    /// to the caller, which reads them right after.
    function _tableCheck(
        State memory s,
        Run memory run,
        uint256 log,
        uint256 which,
        uint256[] memory point,
        uint256 step
    ) private pure returns (uint256[] memory r) {
        uint256 delta = _challenge(s);
        uint256 db = _challenge(s);
        uint256[] memory tau = _challenges(s, log);
        uint256 start;
        uint256 a = 1;
        for (uint256 i = 0; i < s.n; ++i) {
            start = addmod(start, mulmod(a, run.sums[2 * i + which], R), R);
            a = mulmod(a, db, R);
        }
        uint256 claim;
        (claim, r) = _sumcheck(s, start, log, 3);
        // The evaluations follow in the proof; peek at them.
        uint256 eqTau = ZenoFr.eqPoints(tau, r);
        uint256 eqPt = ZenoFr.eqPoints(point, r);
        uint256 index;
        for (uint256 i = 0; i < log; ++i) index = addmod(addmod(index, index, R), r[i], R);
        uint256 expected;
        a = 1;
        for (uint256 i = 0; i < s.n; ++i) {
            uint256 h2 = s.proof[s.pos + 2 * i];
            uint256 count = s.proof[s.pos + 2 * i + 1];
            uint256 term = _lookupTerm(s, h2, index, eqPt, count);
            expected = addmod(expected, mulmod(a, addmod(h2, mulmod(delta, mulmod(eqTau, term, R), R), R), R), R);
            a = mulmod(a, db, R);
        }
        if (claim != expected) revert InvalidProof(step);
    }

    function _openings(
        State memory s,
        Run memory run,
        uint256[][] calldata keys,
        uint256[][] calldata accs
    ) private view {
        uint256 n = s.n;
        Claim[] memory c = new Claim[](5);
        c[0].comms = new uint256[](2 * n);
        c[1].comms = new uint256[](2 * n);
        c[2].comms = new uint256[](18 * n);
        c[3].comms = new uint256[](4 * n);
        c[4].comms = new uint256[](4 * n);
        c[0].values = new uint256[](n);
        c[1].values = new uint256[](n);
        for (uint256 i = 0; i < n; ++i) {
            uint256[] calldata key = keys[i];
            uint256[] calldata acc = accs[i];
            // E and W after removing the blinding r·H.
            (c[0].comms[2 * i], c[0].comms[2 * i + 1]) =
                ZenoBn254.addMul(acc[0], acc[1], key[17], ZenoBn254.neg(key[18]), run.blinds[2 * i + 1]);
            (c[1].comms[2 * i], c[1].comms[2 * i + 1]) =
                ZenoBn254.addMul(acc[3], acc[4], key[17], ZenoBn254.neg(key[18]), run.blinds[2 * i]);
            c[0].values[i] = run.claims[4 * i + 3];
            c[1].values[i] = run.v[2 * i + 1];
            // val_A, val_B, val_C, row, col, e_row, e_col, h1_row, h1_col.
            uint256 b = 18 * i;
            for (uint256 j = 0; j < 6; ++j) c[2].comms[b + j] = key[7 + j];
            for (uint256 j = 0; j < 4; ++j) c[2].comms[b + 6 + j] = key[3 + j];
            for (uint256 j = 0; j < 8; ++j) c[2].comms[b + 10 + j] = run.comms[12 * i + j];
            // h2_row, count_row; h2_col, count_col.
            c[3].comms[4 * i] = run.comms[12 * i + 8];
            c[3].comms[4 * i + 1] = run.comms[12 * i + 9];
            c[3].comms[4 * i + 2] = key[13];
            c[3].comms[4 * i + 3] = key[14];
            c[4].comms[4 * i] = run.comms[12 * i + 10];
            c[4].comms[4 * i + 1] = run.comms[12 * i + 11];
            c[4].comms[4 * i + 2] = key[15];
            c[4].comms[4 * i + 3] = key[16];
        }
        c[0].point = run.rx;
        c[1].point = _slice(run.ry, 1, run.ry.length - 1);
        (c[2].point, c[2].values) = (run.rk, run.evalsK);
        (c[3].point, c[3].values) = (run.rj, run.evalsM);
        (c[4].point, c[4].values) = (run.rz, run.evalsZ);
        _openAll(s, c);
    }

    // ------------------------------------------------------------------
    // Protocol pieces shared with ZenoUniversalDecider
    // ------------------------------------------------------------------

    function _lookupTerm(State memory s, uint256 h, uint256 index, uint256 e, uint256 sub)
        private
        pure
        returns (uint256)
    {
        uint256 denominator = addmod(s.gamma, addmod(index, mulmod(s.beta, e, R), R), R);
        return addmod(mulmod(h, denominator, R), R - sub, R);
    }

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
            uint256 e1 = addmod(claim, R - m[0] % R, R);
            claim = degree == 2 ? ZenoFr.interp2(m[0], e1, m[1], r) : ZenoFr.interp3(m[0], e1, m[1], m[2], r);
        }
        return (claim, point);
    }

    struct Claim {
        uint256[] comms;
        uint256[] point;
        uint256[] values;
        uint256 q;
        uint256 value;
        uint256[] folded;
        uint256[] yPos;
        uint256[] yNeg;
        uint256[] ySq;
    }

    struct Batch {
        uint256 r;
        uint256 dBase;
        uint256 d;
        uint256 g;
        uint256 g2;
        uint256 bPos;
        uint256 bNeg;
        uint256 bSq;
    }

    function _openAll(State memory s, Claim[] memory c) private view {
        for (uint256 j = 0; j < c.length; ++j) _claimHead(s, c[j]);
        Batch memory b;
        b.r = _challenge(s);
        if (b.r == 0) revert InvalidProof(6);
        for (uint256 j = 0; j < c.length; ++j) _claimEvals(s, c[j], b.r);
        b.dBase = _challenge(s);
        b.d = 1;
        uint256[] memory pi = _take(s, 6);
        _absorb(s, pi);
        b.g = _challenge(s);
        b.g2 = mulmod(b.g, b.g, R);
        for (uint256 j = 0; j < c.length; ++j) _accumulate(s, b, c[j]);
        (s.lx, s.ly) = ZenoBn254.addMul(
            s.lx,
            s.ly,
            1,
            Q - 2,
            addmod(b.bPos, addmod(mulmod(b.g, b.bNeg, R), mulmod(b.g2, b.bSq, R), R), R)
        );
        (s.lx, s.ly) = ZenoBn254.addMul(s.lx, s.ly, pi[0], pi[1], b.r);
        (s.lx, s.ly) = ZenoBn254.addMul(s.lx, s.ly, pi[2], pi[3], R - mulmod(b.g, b.r, R));
        (s.lx, s.ly) = ZenoBn254.addMul(s.lx, s.ly, pi[4], pi[5], mulmod(b.g2, mulmod(b.r, b.r, R), R));
        (s.rx, s.ry) = ZenoBn254.addMul(pi[0], pi[1], pi[2], pi[3], b.g);
        (s.rx, s.ry) = ZenoBn254.addMul(s.rx, s.ry, pi[4], pi[5], b.g2);
    }

    function _claimHead(State memory s, Claim memory c) private pure {
        _absorb(s, c.point);
        _absorb(s, c.values);
        c.q = _challenge(s);
        uint256 value = c.values[0];
        uint256 qi = c.q;
        for (uint256 i = 1; i < c.values.length; ++i) {
            value = addmod(value, mulmod(qi, c.values[i], R), R);
            qi = mulmod(qi, c.q, R);
        }
        c.value = value;
        c.folded = _take(s, 2 * (c.point.length - 1));
        _absorb(s, c.folded);
    }

    function _claimEvals(State memory s, Claim memory c, uint256 r) private pure {
        uint256 ell = c.point.length;
        c.yPos = _take(s, ell);
        c.yNeg = _take(s, ell);
        c.ySq = _take(s, ell - 1);
        _absorb(s, c.yPos);
        _absorb(s, c.yNeg);
        _absorb(s, c.ySq);
        for (uint256 i = 0; i < ell; ++i) {
            uint256 u = c.point[ell - 1 - i];
            uint256 lhs = mulmod(addmod(r, r, R), i + 1 < ell ? c.ySq[i] : c.value, R);
            uint256 rhs = addmod(
                mulmod(mulmod(r, addmod(1, R - u, R), R), addmod(c.yPos[i], c.yNeg[i], R), R),
                mulmod(u, addmod(c.yPos[i], R - c.yNeg[i] % R, R), R),
                R
            );
            if (lhs != rhs) revert InvalidProof(6);
        }
    }

    function _accumulate(State memory s, Batch memory b, Claim memory c) private view {
        {
            uint256 coeff = mulmod(b.d, addmod(1, b.g, R), R);
            for (uint256 i = 0; 2 * i < c.comms.length; ++i) {
                (s.lx, s.ly) = ZenoBn254.addMul(s.lx, s.ly, c.comms[2 * i], c.comms[2 * i + 1], coeff);
                coeff = mulmod(coeff, c.q, R);
            }
        }
        uint256 weight = addmod(addmod(1, b.g, R), b.g2, R);
        for (uint256 i = 0; i < c.yPos.length; ++i) {
            if (i > 0) {
                (s.lx, s.ly) = ZenoBn254.addMul(
                    s.lx, s.ly, c.folded[2 * (i - 1)], c.folded[2 * i - 1], mulmod(weight, b.d, R)
                );
                b.bSq = addmod(b.bSq, mulmod(b.d, c.ySq[i - 1], R), R);
            }
            b.bPos = addmod(b.bPos, mulmod(b.d, c.yPos[i], R), R);
            b.bNeg = addmod(b.bNeg, mulmod(b.d, c.yNeg[i], R), R);
            b.d = mulmod(b.d, b.dBase, R);
        }
    }

    // ------------------------------------------------------------------
    // Multilinear helpers, transcript and BN254 arithmetic
    // ------------------------------------------------------------------

    /// @dev `Σ_i IO_i·eq(point, i)` for `IO = (u, x…)`, with an `eq` table
    /// over the low variables only.
    function _ioEval(uint256[] calldata acc, uint256[] memory point) private pure returns (uint256 sum) {
        uint256 count = acc.length - 4;
        uint256 b;
        while ((1 << b) < count) ++b;
        uint256 n = point.length;
        if (b > n) revert MalformedInput();
        uint256[] memory t = new uint256[](1 << b);
        t[0] = 1;
        for (uint256 i = 0; i < b; ++i) {
            uint256 r = point[n - b + i];
            for (uint256 j = 1 << i; j > 0; --j) {
                uint256 hi = mulmod(t[j - 1], r, R);
                t[2 * j - 1] = hi;
                t[2 * j - 2] = addmod(t[j - 1], R - hi, R);
            }
        }
        sum = mulmod(acc[2], t[0], R);
        for (uint256 i = 5; i < acc.length; ++i) {
            sum = addmod(sum, mulmod(acc[i], t[i - 4], R), R);
        }
        for (uint256 j = 0; j < n - b; ++j) {
            sum = mulmod(sum, addmod(1, R - point[j], R), R);
        }
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

    function _take(State memory s, uint256 n) private pure returns (uint256[] memory out) {
        out = _slice(s.proof, s.pos, n);
        s.pos += n;
    }

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

}
