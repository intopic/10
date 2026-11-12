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
/// @dev TRUST MODEL. Folding alone guarantees that the stored accumulator is
/// the correct fold of the submitted step instances and that their public
/// states chain (`z_out` of a step is `z_in` of the next). Whether the
/// accumulated witness satisfies the circuit is decided at the end, in one of
/// two modes:
///
/// - `finalizeWithProof` (on-chain decider): the contract itself verifies two
///   KZG openings and one Groth16 proof against the final accumulator and
///   marks the session `decided`. A decided session's `state` is the result
///   of `steps` valid applications of the step function to `z0`.
/// - `finalize` (transparent mode): the session is only closed; a succinct
///   transparent proof is verified off-chain against the final accumulator
///   (`evm-verifier::verify_final`). Such a session is never `decided`.
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
    uint256 internal constant TAG_POINT = 5;
    uint256 internal constant TAG_BATCH = 6;

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
    mapping(bytes32 => Session) private sessions;
    /// Hash of the Groth16 decider key registered for each circuit `vk`
    /// (development mode: these keys are circuit-specific).
    mapping(bytes32 => bytes32) public deciderKeyHash;
    /// The universal decider verifier contract.
    IZenoUniversalDecider public universalDecider;

    event SessionOpened(bytes32 indexed sessionId, address indexed prover, bytes32 vk);
    event StepFolded(bytes32 indexed sessionId, uint64 step);
    event SessionFinalized(bytes32 indexed sessionId, uint64 steps, bytes32 accumulatorHash);
    event SessionDecided(bytes32 indexed sessionId, uint64 steps);
    event CircuitRegistered(bytes32 indexed vk, bytes32 keyHash);
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
    error InvalidPoint();
    error TransferFailed();
    error CircuitAlreadyRegistered();
    error UnknownDeciderKey();
    error InvalidDeciderProof();

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
            (a[3], a[4]) = _addMul(a[3], a[4], steps[at], steps[at + 1], r);
            (a[0], a[1]) = _addMul(a[0], a[1], steps[at + 2], steps[at + 3], r);
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
    ) external {
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
            (uint256 px, uint256 py) = _addMul(s.wx, s.wy, s.ex, s.ey, g);
            (px, py) = _addMul(px, py, key[0], _neg(key[1]), addmod(proof[2], mulmod(g, proof[3], R), R));
            (px, py) = _addMul(px, py, 1, Q - 2, addmod(proof[0], mulmod(g, proof[1], R), R));
            (uint256 qx, uint256 qy) = _addMul(proof[4], proof[5], proof[6], proof[7], g);
            (px, py) = _addMul(px, py, qx, qy, c);
            pairs[0] = px;
            pairs[1] = py;
            pairs[2] = G2_X_IM;
            pairs[3] = G2_X_RE;
            pairs[4] = G2_Y_IM;
            pairs[5] = G2_Y_RE;
            pairs[6] = qx;
            pairs[7] = _neg(qy);
            for (uint256 i = 0; i < 4; ++i) pairs[8 + i] = key[2 + i];
        }
        // Groth16 with public inputs (u, x, d, c, W(c), E(c)):
        //   e(−A, B) · e(α, β) · e(IC₀ + Σ inᵢ·ICᵢ, γ) · e(C, δ) = 1
        {
            (uint256 vx, uint256 vy) = _addMul(key[20], key[21], key[22], key[23], s.u);
            uint256 n = x.length;
            for (uint256 i = 0; i < n; ++i) {
                (vx, vy) = _addMul(vx, vy, key[24 + 2 * i], key[25 + 2 * i], x[i]);
            }
            (vx, vy) = _addMul(vx, vy, key[24 + 2 * n], key[25 + 2 * n], proof[16]);
            (vx, vy) = _addMul(vx, vy, key[26 + 2 * n], key[27 + 2 * n], c);
            (vx, vy) = _addMul(vx, vy, key[28 + 2 * n], key[29 + 2 * n], proof[0]);
            (vx, vy) = _addMul(vx, vy, key[30 + 2 * n], key[31 + 2 * n], proof[1]);
            pairs[12] = proof[8];
            pairs[13] = _neg(proof[9]);
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

    /// @notice Closes the session like `finalize` and verifies on-chain, with
    /// the universal decider, that the final accumulator is satisfiable.
    /// No circuit-specific key or setup is involved: `key` holds the public
    /// commitments to the circuit's matrices, and the session must have been
    /// opened with `vk = keccak256(key)`.
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

    function setUniversalDecider(IZenoUniversalDecider decider) external onlyOwner {
        universalDecider = decider;
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

    function _foldMask(bytes32 sessionId, bytes calldata maskProof)
        private
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
        (uint256 ex, uint256 ey) = _addMul(s.ex, s.ey, m[5 + n], m[6 + n], r);
        (s.ex, s.ey) = _addMul(ex, ey, m[0], m[1], mulmod(r, r, R));
        (s.wx, s.wy) = _addMul(s.wx, s.wy, m[3], m[4], r);
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
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // ------------------------------------------------------------------
    // BN254 arithmetic through the EIP-196 precompiles
    // ------------------------------------------------------------------

    /// @dev Negation of a G1 point's y-coordinate; the identity stays `(0, 0)`.
    function _neg(uint256 y) private pure returns (uint256) {
        return y == 0 ? 0 : Q - y;
    }

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
