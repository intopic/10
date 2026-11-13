// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {ZenoBn254} from "./lib/ZenoBn254.sol";

/// @title ZenoLlullVerifier — on-chain folding verifier (BN254)
/// @notice Each call to `verifyFoldedProof` folds one step instance into a
/// constant-size accumulator `U = (comm_E, u, comm_W, x)` with exactly two
/// scalar multiplications (`ecMul`, precompile 0x07) and two additions
/// (`ecAdd`, precompile 0x06):
///
///     comm_E ← comm_E + r·comm_T      u ← u + r
///     comm_W ← comm_W + r·comm_W'     x ← x + r·x'
///
/// with `r = keccak256(vk, U, step, comm_T) mod 2^128`.
///
/// @dev TRUST MODEL. Folding alone guarantees that the stored accumulator is
/// the correct fold of the submitted step instances and that their public
/// states chain (`z_out` of a step is `z_in` of the next). Whether the
/// accumulated witness satisfies the circuit is decided at the end, in one of
/// two modes:
///
/// - `finalizeUniversal` (mode B, on-chain decider): the universal decider
///   contract fixed at deployment verifies the final accumulator against the
///   circuit key the session was opened for, and the session is marked
///   `decided`. A decided session's `state` is the result of `steps` valid
///   applications of the step function to `z0`: the key fixes the circuit's
///   number of public inputs, and the decider accepts no other.
/// - `finalize` (mode A, transparent): the session is only closed; a succinct
///   transparent proof is verified off-chain against the final accumulator
///   (`evm-verifier::verify_final`). Such a session is never `decided`.
///
/// The Groth16 decider of early development (mode C) lives in
/// `dev/ZenoLlullVerifierDevGroth16.sol` and is not part of this contract.
interface IZenoUniversalDecider {
    function verify(
        bytes32 vk,
        uint256[] calldata key,
        uint256[] calldata acc,
        uint256[] calldata proof
    ) external view returns (bool);
}

contract ZenoLlullVerifier {
    /// Order of the BN254 scalar field.
    uint256 internal constant R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant CHALLENGE_MASK = (1 << 128) - 1;
    uint256 internal constant TAG_FOLD = 1;
    uint256 internal constant TAG_MASK = 3;

    /// Modulus of the BN254 base field.
    uint256 internal constant Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct Session {
        address prover;
        uint64 steps;
        bool finalized;
        bool decided;
        bytes32 vk;
        // Accumulator: comm_E = (ex, ey), u, comm_W = (wx, wy), x.
        uint256 ex;
        uint256 ey;
        uint256 u;
        uint256 wx;
        uint256 wy;
        uint256[] x;
        // Current public state z_i of the computation.
        uint256[] state;
    }

    address public owner;
    /// Fee in wei charged for every folded step.
    uint256 public protocolFee;
    uint256 public sessionCount;
    mapping(bytes32 => Session) internal sessions;
    /// The universal decider verifier contract, fixed at deployment: nobody
    /// can replace the code that decides sessions.
    IZenoUniversalDecider public immutable universalDecider;

    event SessionOpened(bytes32 indexed sessionId, address indexed prover, bytes32 vk);
    event StepFolded(bytes32 indexed sessionId, uint64 step);
    event SessionFinalized(bytes32 indexed sessionId, uint64 steps, bytes32 accumulatorHash);
    event SessionDecided(bytes32 indexed sessionId, uint64 steps);
    event CircuitAnnounced(bytes32 indexed circuitId, address indexed by, uint256[] key);
    event ProtocolFeeChanged(uint256 fee);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error NotSessionProver();
    error SessionClosed();
    error WrongFee();
    error MalformedProof();
    error ScalarOutOfRange();
    error StateMismatch();
    error TransferFailed();
    error UnknownDeciderKey();
    error InvalidDeciderProof();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(uint256 fee, IZenoUniversalDecider decider) {
        if (address(decider).code.length == 0) revert UnknownDeciderKey();
        universalDecider = decider;
        owner = msg.sender;
        protocolFee = fee;
        emit OwnershipTransferred(address(0), msg.sender);
        emit ProtocolFeeChanged(fee);
    }

    // ------------------------------------------------------------------
    // Sessions
    // ------------------------------------------------------------------

    /// @notice Opens a computation for the circuit identified by `vk`,
    /// starting at public state `z0`. Only the caller may fold steps into it.
    function openSession(bytes32 vk, uint256[] calldata z0) external returns (bytes32 sessionId) {
        uint256 k = z0.length;
        if (k == 0) revert MalformedProof();
        for (uint256 i = 0; i < k; ++i) {
            if (z0[i] >= R) revert ScalarOutOfRange();
        }
        sessionId = keccak256(abi.encode(block.chainid, address(this), msg.sender, sessionCount++));
        Session storage s = sessions[sessionId];
        s.prover = msg.sender;
        s.vk = vk;
        s.state = z0;
        s.x = new uint256[](2 * k);
        emit SessionOpened(sessionId, msg.sender, vk);
    }

    /// @notice Folds one step into the session's accumulator.
    /// @param proof `sessionId ‖ comm_W.x ‖ comm_W.y ‖ comm_T.x ‖ comm_T.y` (160 bytes).
    /// @param publicInputs `z_in ‖ z_out` of the step; `z_in` must equal the
    /// session's current state, which then advances to `z_out`.
    function verifyFoldedProof(bytes calldata proof, uint256[] calldata publicInputs)
        external
        payable
        returns (bytes32 sessionId)
    {
        if (msg.value != protocolFee) revert WrongFee();
        if (proof.length != 160) revert MalformedProof();
        sessionId = bytes32(proof[0:32]);
        Session storage s = sessions[sessionId];
        if (s.prover != msg.sender) revert NotSessionProver();
        if (s.finalized) revert SessionClosed();

        uint256 k = s.state.length;
        if (publicInputs.length != 2 * k) revert MalformedProof();
        for (uint256 i = 0; i < k; ++i) {
            if (publicInputs[i] != s.state[i]) revert StateMismatch();
            if (publicInputs[k + i] >= R) revert ScalarOutOfRange();
        }

        uint256[4] memory pts = abi.decode(proof[32:160], (uint256[4]));
        uint256[] memory x = s.x;
        uint256 r = uint256(
            keccak256(
                abi.encodePacked(TAG_FOLD, s.vk, s.ex, s.ey, s.u, s.wx, s.wy, x, pts, publicInputs)
            )
        ) & CHALLENGE_MASK;

        // Exactly two scalar multiplications: r·comm_W' and r·comm_T.
        (s.wx, s.wy) = ZenoBn254.addMul(s.wx, s.wy, pts[0], pts[1], r);
        (s.ex, s.ey) = ZenoBn254.addMul(s.ex, s.ey, pts[2], pts[3], r);
        s.u = addmod(s.u, r, R);
        for (uint256 i = 0; i < 2 * k; ++i) {
            s.x[i] = addmod(x[i], mulmod(r, publicInputs[i], R), R);
        }
        for (uint256 i = 0; i < k; ++i) {
            s.state[i] = publicInputs[k + i];
        }
        uint64 step = ++s.steps;
        emit StepFolded(sessionId, step);
    }

    /// @notice Folds many steps in one transaction. Storage is read and
    /// written once, so the marginal cost of a step is its two scalar
    /// multiplications, one hash and its calldata.
    /// @param steps for each step, in order:
    /// `comm_W.x, comm_W.y, comm_T.x, comm_T.y, z_in…, z_out…`.
    function verifyFoldedProofBatch(bytes32 sessionId, uint256[] calldata steps) external payable {
        Session storage s = sessions[sessionId];
        if (s.prover != msg.sender) revert NotSessionProver();
        if (s.finalized) revert SessionClosed();
        uint256 k = s.state.length;
        uint256 stride = 4 + 2 * k;
        uint256 count = steps.length / stride;
        if (count == 0 || steps.length != count * stride) revert MalformedProof();
        if (msg.value != protocolFee * count) revert WrongFee();

        // Accumulator and state in memory: [ex, ey, u, wx, wy], x, state.
        uint256[5] memory a = [s.ex, s.ey, s.u, s.wx, s.wy];
        uint256[] memory x = s.x;
        uint256[] memory state = s.state;
        bytes32 vk = s.vk;
        for (uint256 n = 0; n < count; ++n) {
            uint256 at = n * stride;
            for (uint256 i = 0; i < k; ++i) {
                if (steps[at + 4 + i] != state[i]) revert StateMismatch();
                if (steps[at + 4 + k + i] >= R) revert ScalarOutOfRange();
                state[i] = steps[at + 4 + k + i];
            }
            uint256 r = uint256(
                keccak256(
                    abi.encodePacked(
                        TAG_FOLD, vk, a, x, steps[at:at + 4], steps[at + 4:at + stride]
                    )
                )
            ) & CHALLENGE_MASK;
            (a[3], a[4]) = ZenoBn254.addMul(a[3], a[4], steps[at], steps[at + 1], r);
            (a[0], a[1]) = ZenoBn254.addMul(a[0], a[1], steps[at + 2], steps[at + 3], r);
            a[2] = addmod(a[2], r, R);
            for (uint256 i = 0; i < 2 * k; ++i) {
                x[i] = addmod(x[i], mulmod(r, steps[at + 4 + i], R), R);
            }
        }
        (s.ex, s.ey, s.u, s.wx, s.wy) = (a[0], a[1], a[2], a[3], a[4]);
        for (uint256 i = 0; i < 2 * k; ++i) s.x[i] = x[i];
        for (uint256 i = 0; i < k; ++i) s.state[i] = state[i];
        s.steps += uint64(count);
        emit StepFolded(sessionId, s.steps);
    }

    /// @notice Closes the session by folding a random relaxed instance into
    /// the accumulator (zero-knowledge masking). The decider proof is then
    /// checked off-chain against the resulting accumulator.
    /// @param maskProof `comm_E ‖ u ‖ comm_W ‖ x ‖ comm_T` of the mask.
    function finalize(bytes32 sessionId, bytes calldata maskProof) external {
        Session storage s = _foldMask(sessionId, maskProof);
        emit SessionFinalized(sessionId, s.steps, accumulatorHash(sessionId));
    }

    /// @notice Closes the session like `finalize` and verifies on-chain, with
    /// the universal decider, that the final accumulator is satisfiable.
    /// No circuit-specific key or setup is involved: `key` holds the public
    /// commitments to the circuit's matrices and its number of public
    /// inputs, and the session must have been opened with
    /// `vk = keccak256(key)` and a state of the circuit's arity.
    function finalizeUniversal(
        bytes32 sessionId,
        bytes calldata maskProof,
        uint256[] calldata key,
        uint256[] calldata proof
    ) external {
        Session storage s = _foldMask(sessionId, maskProof);
        // The session's `vk` is the hash of the circuit key it was opened
        // for: only that key can decide it. No registry, no administrator.
        if (keccak256(abi.encodePacked(key)) != s.vk) revert UnknownDeciderKey();
        uint256 n = s.x.length;
        uint256[] memory acc = new uint256[](5 + n);
        (acc[0], acc[1], acc[2], acc[3], acc[4]) = (s.ex, s.ey, s.u, s.wx, s.wy);
        for (uint256 i = 0; i < n; ++i) acc[5 + i] = s.x[i];
        if (!universalDecider.verify(s.vk, key, acc, proof)) revert InvalidDeciderProof();

        s.decided = true;
        emit SessionFinalized(sessionId, s.steps, accumulatorHash(sessionId));
        emit SessionDecided(sessionId, s.steps);
    }

    /// @notice Publishes a circuit key so that others can find and audit it.
    /// Permissionless and purely informational: a key is a deterministic,
    /// public function of the circuit and the reference string, and a
    /// session is bound to its key by `vk = keccak256(key)` when it is
    /// opened, so nothing depends on this call.
    function announceCircuit(uint256[] calldata key) external returns (bytes32 circuitId) {
        circuitId = keccak256(abi.encodePacked(key));
        emit CircuitAnnounced(circuitId, msg.sender, key);
    }

    function _foldMask(bytes32 sessionId, bytes calldata maskProof)
        internal
        returns (Session storage s)
    {
        s = sessions[sessionId];
        if (s.prover != msg.sender) revert NotSessionProver();
        if (s.finalized) revert SessionClosed();
        uint256 n = s.x.length;
        if (maskProof.length != 32 * (7 + n)) revert MalformedProof();

        uint256[] memory m = new uint256[](7 + n);
        for (uint256 i = 0; i < 7 + n; ++i) {
            m[i] = uint256(bytes32(maskProof[32 * i:32 * i + 32]));
        }
        // m = [ex, ey, u, wx, wy, x[0..n], tx, ty]
        if (m[2] >= R) revert ScalarOutOfRange();
        uint256[] memory x = s.x;
        uint256 r = uint256(
            keccak256(abi.encodePacked(TAG_MASK, s.vk, s.ex, s.ey, s.u, s.wx, s.wy, x, m))
        ) & CHALLENGE_MASK;

        // comm_E ← comm_E + r·comm_T + r²·comm_E_mask
        (uint256 ex, uint256 ey) = ZenoBn254.addMul(s.ex, s.ey, m[5 + n], m[6 + n], r);
        (s.ex, s.ey) = ZenoBn254.addMul(ex, ey, m[0], m[1], mulmod(r, r, R));
        (s.wx, s.wy) = ZenoBn254.addMul(s.wx, s.wy, m[3], m[4], r);
        s.u = addmod(s.u, mulmod(r, m[2], R), R);
        for (uint256 i = 0; i < n; ++i) {
            if (m[5 + i] >= R) revert ScalarOutOfRange();
            s.x[i] = addmod(x[i], mulmod(r, m[5 + i], R), R);
        }
        s.finalized = true;
    }

    // ------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------

    /// @return acc `[ex, ey, u, wx, wy]`, the accumulator's points and scalar.
    /// @return x the accumulated public inputs.
    /// @return state the current public state of the computation.
    function getAccumulator(bytes32 sessionId)
        external
        view
        returns (
            uint256[5] memory acc,
            uint256[] memory x,
            uint256[] memory state,
            uint64 steps,
            bool finalized,
            bytes32 vk,
            bool decided
        )
    {
        Session storage s = sessions[sessionId];
        acc = [s.ex, s.ey, s.u, s.wx, s.wy];
        return (acc, s.x, s.state, s.steps, s.finalized, s.vk, s.decided);
    }

    function accumulatorHash(bytes32 sessionId) public view returns (bytes32) {
        Session storage s = sessions[sessionId];
        return keccak256(abi.encodePacked(s.vk, s.ex, s.ey, s.u, s.wx, s.wy, s.x, s.state, s.steps));
    }

    // ------------------------------------------------------------------
    // Protocol fee
    // ------------------------------------------------------------------

    function setProtocolFee(uint256 fee) external onlyOwner {
        protocolFee = fee;
        emit ProtocolFeeChanged(fee);
    }

    function withdrawFees(address payable to) external onlyOwner {
        (bool ok, ) = to.call{value: address(this).balance}("");
        if (!ok) revert TransferFailed();
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert NotOwner();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // ------------------------------------------------------------------
    // BN254 arithmetic through the EIP-196 precompiles
    // ------------------------------------------------------------------

}
