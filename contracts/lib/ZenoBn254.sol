// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/// @title ZenoBn254 — BN254 arithmetic through the EIP-196/197 precompiles
/// @notice Shared by every Zeno–Llull verifier contract. The functions are
/// `internal`: they are compiled into the calling contract.
library ZenoBn254 {
    /// Modulus of the BN254 base field.
    uint256 internal constant Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    // Generator of G2, in the precompile's (imaginary, real) coordinate order.
    uint256 internal constant G2_X_IM =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 internal constant G2_X_RE =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 internal constant G2_Y_IM =
        4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 internal constant G2_Y_RE =
        8495653923123431417604973247489272438418190587263600148770280649306958101930;

    error InvalidPoint();

    /// @dev Negation of a G1 point's y-coordinate; the identity stays `(0, 0)`.
    function neg(uint256 y) internal pure returns (uint256) {
        return y == 0 ? 0 : Q - y;
    }

    /// @dev Returns `(ax, ay) + k·(bx, by)`. The precompiles reject points
    /// that are not on the curve and coordinates that are not below `Q`; the
    /// identity is encoded as `(0, 0)`.
    function addMul(uint256 ax, uint256 ay, uint256 bx, uint256 by, uint256 k)
        internal
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

    /// @dev `e(L, G₂) · e(−Rt, T₂) = 1`, i.e. `e(L, G₂) = e(Rt, T₂)`, with
    /// `T₂ = (t0, t1, t2, t3)` in the precompile's coordinate order.
    function pairingEquals(
        uint256 lx,
        uint256 ly,
        uint256 rx,
        uint256 ry,
        uint256 t0,
        uint256 t1,
        uint256 t2,
        uint256 t3
    ) internal view returns (bool) {
        uint256[12] memory input = [lx, ly, G2_X_IM, G2_X_RE, G2_Y_IM, G2_Y_RE, rx, neg(ry), t0, t1, t2, t3];
        bool ok;
        uint256[1] memory out;
        assembly ("memory-safe") {
            ok := staticcall(gas(), 0x08, input, 0x180, out, 0x20)
        }
        return ok && out[0] == 1;
    }
}

/// @title ZenoField — sum-check helpers over a prime field of modulus `m`
/// @notice Used over the scalar field of BN254 (the universal deciders) and
/// over its base field (the CycleFold argument).
library ZenoField {
    /// @dev `p(r)` for the quadratic with `p(0), p(1), p(2) = p0, p1, p2`:
    /// `p0·(r−1)(r−2)/2 − p1·r(r−2) + p2·r(r−1)/2`. `inv2 = 1/2 mod m`.
    function interp2(uint256 p0, uint256 p1, uint256 p2, uint256 r, uint256 m, uint256 inv2)
        internal
        pure
        returns (uint256)
    {
        uint256 r1 = addmod(r, m - 1, m);
        uint256 r2 = addmod(r, m - 2, m);
        return addmod(
            mulmod(mulmod(p0, inv2, m), mulmod(r1, r2, m), m),
            addmod(m - mulmod(p1, mulmod(r, r2, m), m), mulmod(mulmod(p2, inv2, m), mulmod(r, r1, m), m), m),
            m
        );
    }

    /// @dev `p(r)` for the cubic with values `p0…p3` at `0…3` (Lagrange
    /// basis). `inv2 = 1/2`, `inv6 = 1/6 mod m`.
    function interp3(
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3,
        uint256 r,
        uint256 m,
        uint256 inv2,
        uint256 inv6
    ) internal pure returns (uint256) {
        uint256 r1 = addmod(r, m - 1, m);
        uint256 r2 = addmod(r, m - 2, m);
        uint256 r3 = addmod(r, m - 3, m);
        uint256 acc = mulmod(p0, m - mulmod(mulmod(mulmod(r1, r2, m), r3, m), inv6, m), m);
        acc = addmod(acc, mulmod(p1, mulmod(mulmod(mulmod(r, r2, m), r3, m), inv2, m), m), m);
        acc = addmod(acc, mulmod(p2, m - mulmod(mulmod(mulmod(r, r1, m), r3, m), inv2, m), m), m);
        return addmod(acc, mulmod(p3, mulmod(mulmod(mulmod(r, r1, m), r2, m), inv6, m), m), m);
    }

    /// @dev `eq(a, b) = Π (a_i·b_i + (1 − a_i)(1 − b_i))`.
    function eqPoints(uint256[] memory a, uint256[] memory b, uint256 m) internal pure returns (uint256 acc) {
        acc = 1;
        for (uint256 i = 0; i < a.length; ++i) {
            uint256 term = addmod(mulmod(a[i], b[i], m), mulmod(addmod(1, m - a[i], m), addmod(1, m - b[i], m), m), m);
            acc = mulmod(acc, term, m);
        }
    }
}
