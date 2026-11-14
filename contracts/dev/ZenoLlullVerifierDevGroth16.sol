// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {ZenoLlullVerifier, IZenoUniversalDecider} from "../ZenoLlullVerifier.sol";
import {ZenoBn254} from "../lib/ZenoBn254.sol";

/// @title ZenoLlullVerifierDevGroth16 — DEVELOPMENT ONLY (mode C)
/// @notice `ZenoLlullVerifier` plus the Groth16 decider of early development
/// (`finalizeWithProof`). Its keys are circuit-specific, come from a setup
/// with a trapdoor, and are registered by the contract owner, who is trusted
/// for every session of that circuit. Do not deploy it for anything of value:
/// production uses `finalizeUniversal` (no per-circuit key, no registry).
contract ZenoLlullVerifierDevGroth16 is ZenoLlullVerifier {
    uint256 internal constant TAG_POINT = 5;
    uint256 internal constant TAG_BATCH = 6;

    /// Hash of the Groth16 decider key registered for each circuit `vk`.
    mapping(bytes32 => bytes32) public deciderKeyHash;

    event CircuitRegistered(bytes32 indexed vk, bytes32 keyHash);

    error CircuitAlreadyRegistered();

    constructor(uint256 fee, uint256 maxFee_, IZenoUniversalDecider decider)
        ZenoLlullVerifier(fee, maxFee_, decider)
    {}

    /// @notice Closes the session like `finalize` and verifies on-chain that
    /// the final accumulator is satisfiable, marking the session `decided`.
    /// @param proof `[W(c), E(c), r_W, r_E, π_W, π_E, A, B, C, d]`: the two
    /// evaluations, the commitment blindings, the two KZG opening proofs, the
    /// Groth16 proof and the digest `d` of the witness inside that proof.
    /// The evaluation point is derived from `d`, so the Groth16 witness is
    /// fixed before the point at which it is compared with the commitments.
    /// @param key the decider key registered for the session's circuit:
    /// `[H, [τ]₂, α, β, γ, δ, IC…]`.
    function finalizeWithProof(
        bytes32 sessionId,
        bytes calldata maskProof,
        uint256[17] calldata proof,
        uint256[] calldata key
    ) external payable {
        Session storage s = _foldMask(sessionId, maskProof);
        bytes32 keyHash = deciderKeyHash[s.vk];
        if (keyHash == bytes32(0) || keccak256(abi.encodePacked(key)) != keyHash) {
            revert UnknownDeciderKey();
        }
        uint256[] memory x = s.x;
        if (key.length != 20 + 2 * (x.length + 6)) revert UnknownDeciderKey();
        if (proof[0] >= R || proof[1] >= R || proof[2] >= R || proof[3] >= R || proof[16] >= R) {
            revert ScalarOutOfRange();
        }

        // Evaluation point and batching challenge.
        uint256 c = uint256(
            keccak256(abi.encodePacked(TAG_POINT, s.vk, s.ex, s.ey, s.u, s.wx, s.wy, x, proof[16]))
        ) % R;
        uint256 g = uint256(
            keccak256(
                abi.encodePacked(TAG_BATCH, c, proof[0], proof[1], proof[4], proof[5], proof[6], proof[7])
            )
        ) % R;

        uint256[36] memory pairs;
        // KZG, both openings batched with g:
        //   P = comm_W + g·comm_E − (r_W + g·r_E)·H − (W(c) + g·E(c))·G + c·π,   π = π_W + g·π_E
        //   e(P, G₂) · e(−π, [τ]₂) = 1
        {
            (uint256 px, uint256 py) = ZenoBn254.addMul(s.wx, s.wy, s.ex, s.ey, g);
            (px, py) = ZenoBn254.addMul(px, py, key[0], ZenoBn254.neg(key[1]), addmod(proof[2], mulmod(g, proof[3], R), R));
            (px, py) = ZenoBn254.addMul(px, py, 1, Q - 2, addmod(proof[0], mulmod(g, proof[1], R), R));
            (uint256 qx, uint256 qy) = ZenoBn254.addMul(proof[4], proof[5], proof[6], proof[7], g);
            (px, py) = ZenoBn254.addMul(px, py, qx, qy, c);
            pairs[0] = px;
            pairs[1] = py;
            pairs[2] = ZenoBn254.G2_X_IM;
            pairs[3] = ZenoBn254.G2_X_RE;
            pairs[4] = ZenoBn254.G2_Y_IM;
            pairs[5] = ZenoBn254.G2_Y_RE;
            pairs[6] = qx;
            pairs[7] = ZenoBn254.neg(qy);
            for (uint256 i = 0; i < 4; ++i) pairs[8 + i] = key[2 + i];
        }
        // Groth16 with public inputs (u, x, d, c, W(c), E(c)):
        //   e(−A, B) · e(α, β) · e(IC₀ + Σ inᵢ·ICᵢ, γ) · e(C, δ) = 1
        {
            (uint256 vx, uint256 vy) = ZenoBn254.addMul(key[20], key[21], key[22], key[23], s.u);
            uint256 n = x.length;
            for (uint256 i = 0; i < n; ++i) {
                (vx, vy) = ZenoBn254.addMul(vx, vy, key[24 + 2 * i], key[25 + 2 * i], x[i]);
            }
            (vx, vy) = ZenoBn254.addMul(vx, vy, key[24 + 2 * n], key[25 + 2 * n], proof[16]);
            (vx, vy) = ZenoBn254.addMul(vx, vy, key[26 + 2 * n], key[27 + 2 * n], c);
            (vx, vy) = ZenoBn254.addMul(vx, vy, key[28 + 2 * n], key[29 + 2 * n], proof[0]);
            (vx, vy) = ZenoBn254.addMul(vx, vy, key[30 + 2 * n], key[31 + 2 * n], proof[1]);
            pairs[12] = proof[8];
            pairs[13] = ZenoBn254.neg(proof[9]);
            for (uint256 i = 0; i < 4; ++i) pairs[14 + i] = proof[10 + i];
            pairs[18] = key[6];
            pairs[19] = key[7];
            for (uint256 i = 0; i < 4; ++i) pairs[20 + i] = key[8 + i];
            pairs[24] = vx;
            pairs[25] = vy;
            for (uint256 i = 0; i < 4; ++i) pairs[26 + i] = key[12 + i];
            pairs[30] = proof[14];
            pairs[31] = proof[15];
            for (uint256 i = 0; i < 4; ++i) pairs[32 + i] = key[16 + i];
        }
        bool ok;
        uint256[1] memory out;
        assembly ("memory-safe") {
            ok := staticcall(gas(), 0x08, pairs, 0x480, out, 0x20)
        }
        if (!ok || out[0] != 1) revert InvalidDeciderProof();

        s.decided = true;
        emit SessionFinalized(sessionId, s.steps, accumulatorHash(sessionId));
        emit SessionDecided(sessionId, s.steps);
    }

    /// @notice Development mode only (Groth16 decider, whose keys are
    /// circuit-specific and come from a setup the owner vouches for).
    /// Registers the decider key of a circuit: the blinding generator
    /// `H`, `[τ]₂` of the KZG reference string and the Groth16 verifying key
    /// of the circuit's decider. Only its hash is stored; the key itself is
    /// passed with `finalizeWithProof`. Registration is permanent.
    /// @dev The owner vouches that `keyHash` belongs to `vk`; sessions of a
    /// circuit are only as sound as its registered key.
    function registerDevDeciderKey(bytes32 vk, bytes32 keyHash) external onlyOwner {
        if (deciderKeyHash[vk] != bytes32(0)) revert CircuitAlreadyRegistered();
        if (keyHash == bytes32(0)) revert UnknownDeciderKey();
        deciderKeyHash[vk] = keyHash;
        emit CircuitRegistered(vk, keyHash);
    }
}
