// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/// @title ZenoFees — the protocol fees of the Zeno–Llull verifiers
/// @notice Two fees: `stepFee` for every step folded on-chain (mode B) and
/// `decisionFee` for every decision (`finalize`, `finalizeUniversal`,
/// `finalizeRecursive`). Steps already pay gas, so the step fee is meant to
/// be zero or small and the decision fee to carry the price.
/// An owner sets the fees and withdraws what was paid; nothing else. The
/// owner cannot touch verification: no function here reads or changes keys,
/// transcripts or results. Neither fee can ever exceed `maxFee`, fixed at
/// deployment, so the owner cannot price verification out of reach.
abstract contract ZenoFees {
    address public owner;
    /// Fee in wei for every step folded on-chain.
    uint256 public stepFee;
    /// Fee in wei for every decision.
    uint256 public decisionFee;
    /// Upper bound of both fees, fixed at deployment.
    uint256 public immutable maxFee;

    event FeesChanged(uint256 stepFee, uint256 decisionFee);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error WrongFee();
    error FeeAboveCap();
    error TransferFailed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(uint256 stepFee_, uint256 decisionFee_, uint256 maxFee_) {
        if (stepFee_ > maxFee_ || decisionFee_ > maxFee_) revert FeeAboveCap();
        maxFee = maxFee_;
        owner = msg.sender;
        stepFee = stepFee_;
        decisionFee = decisionFee_;
        emit OwnershipTransferred(address(0), msg.sender);
        emit FeesChanged(stepFee_, decisionFee_);
    }

    /// Reverts unless exactly `steps` step fees were paid with the call.
    function _chargeSteps(uint256 steps) internal view {
        if (msg.value != stepFee * steps) revert WrongFee();
    }

    /// Reverts unless exactly one decision fee was paid with the call.
    function _chargeDecision() internal view {
        if (msg.value != decisionFee) revert WrongFee();
    }

    function setFees(uint256 stepFee_, uint256 decisionFee_) external onlyOwner {
        if (stepFee_ > maxFee || decisionFee_ > maxFee) revert FeeAboveCap();
        stepFee = stepFee_;
        decisionFee = decisionFee_;
        emit FeesChanged(stepFee_, decisionFee_);
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
}
