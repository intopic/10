// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

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
/// @dev TRUST MODEL. The contract guarantees that the stored accumulator is
/// the correct fold of the submitted step instances and that their public
/// states chain (`z_out` of a step is `z_in` of the next). It does NOT decide
/// whether the accumulated witness satisfies the circuit. That is established
/// by the succinct decider proof, which is verified off-chain against the
/// accumulator of a finalized session (`evm-verifier::verify_final`). A
/// session's `state` must only be relied upon by parties that have verified
/// that proof.
contract ZenoLlullVerifier {
    /// Order of the BN254 scalar field.
    uint256 internal constant R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant CHALLENGE_MASK = (1 << 128) - 1;
    uint256 internal constant TAG_FOLD = 1;
    uint256 internal constant TAG_MASK = 3;

    struct Session {
        address prover;
        uint64 steps;
        bool finalized;
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
    mapping(bytes32 => Session) private sessions;

    event SessionOpened(bytes32 indexed sessionId, address indexed prover, bytes32 vk);
    event StepFolded(bytes32 indexed sessionId, uint64 step);
    event SessionFinalized(bytes32 indexed sessionId, uint64 steps, bytes32 accumulatorHash);
    event ProtocolFeeChanged(uint256 fee);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error NotSessionProver();
    error SessionClosed();
    error WrongFee();
    error MalformedProof();
    error ScalarOutOfRange();
    error StateMismatch();
    error InvalidPoint();
    error TransferFailed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(uint256 fee) {
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
        (s.wx, s.wy) = _addMul(s.wx, s.wy, pts[0], pts[1], r);
        (s.ex, s.ey) = _addMul(s.ex, s.ey, pts[2], pts[3], r);
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

    /// @notice Closes the session by folding a random relaxed instance into
    /// the accumulator (zero-knowledge masking). The decider proof is then
    /// checked off-chain against the resulting accumulator.
    /// @param maskProof `comm_E ‖ u ‖ comm_W ‖ x ‖ comm_T` of the mask.
    function finalize(bytes32 sessionId, bytes calldata maskProof) external {
        Session storage s = sessions[sessionId];
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
        (uint256 ex, uint256 ey) = _addMul(s.ex, s.ey, m[5 + n], m[6 + n], r);
        (s.ex, s.ey) = _addMul(ex, ey, m[0], m[1], mulmod(r, r, R));
        (s.wx, s.wy) = _addMul(s.wx, s.wy, m[3], m[4], r);
        s.u = addmod(s.u, mulmod(r, m[2], R), R);
        for (uint256 i = 0; i < n; ++i) {
            if (m[5 + i] >= R) revert ScalarOutOfRange();
            s.x[i] = addmod(x[i], mulmod(r, m[5 + i], R), R);
        }
        s.finalized = true;
        emit SessionFinalized(sessionId, s.steps, accumulatorHash(sessionId));
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
            bytes32 vk
        )
    {
        Session storage s = sessions[sessionId];
        acc = [s.ex, s.ey, s.u, s.wx, s.wy];
        return (acc, s.x, s.state, s.steps, s.finalized, s.vk);
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
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // ------------------------------------------------------------------
    // BN254 arithmetic through the EIP-196 precompiles
    // ------------------------------------------------------------------

    /// @dev Returns `(ax, ay) + s·(bx, by)`. The precompiles reject points
    /// that are not on the curve; the identity is encoded as `(0, 0)`.
    function _addMul(uint256 ax, uint256 ay, uint256 bx, uint256 by, uint256 s)
        private
        view
        returns (uint256, uint256)
    {
        uint256[4] memory buf;
        bool ok;
        buf[0] = bx;
        buf[1] = by;
        buf[2] = s;
        assembly {
            ok := staticcall(gas(), 0x07, buf, 0x60, buf, 0x40)
        }
        if (!ok) revert InvalidPoint();
        buf[2] = ax;
        buf[3] = ay;
        assembly {
            ok := staticcall(gas(), 0x06, buf, 0x80, buf, 0x40)
        }
        if (!ok) revert InvalidPoint();
        return (buf[0], buf[1]);
    }
}
