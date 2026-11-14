// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/// @title ZenoFees — the protocol fee of the Zeno–Llull verifiers
/// @notice An owner sets the fee and withdraws what was paid; nothing else.
/// The owner cannot touch verification: no function here reads or changes
/// keys, transcripts or results. The fee can never exceed `maxFee`, fixed at
/// deployment, so the owner cannot price verification out of reach.
abstract contract ZenoFees {
    address public owner;
    /// Fee in wei for every paying call (see the inheriting contract).
    uint256 public protocolFee;
    /// Upper bound of `protocolFee`, fixed at deployment.
    uint256 public immutable maxFee;

    event ProtocolFeeChanged(uint256 fee);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error WrongFee();
    error FeeAboveCap();
    error TransferFailed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(uint256 fee, uint256 maxFee_) {
        if (fee > maxFee_) revert FeeAboveCap();
        maxFee = maxFee_;
        owner = msg.sender;
        protocolFee = fee;
        emit OwnershipTransferred(address(0), msg.sender);
        emit ProtocolFeeChanged(fee);
    }

    /// Reverts unless exactly `units` fees were paid with the call.
    function _chargeFee(uint256 units) internal view {
        if (msg.value != protocolFee * units) revert WrongFee();
    }

    function setProtocolFee(uint256 fee) external onlyOwner {
        if (fee > maxFee) revert FeeAboveCap();
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
}
