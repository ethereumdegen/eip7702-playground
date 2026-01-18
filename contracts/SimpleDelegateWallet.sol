// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SimpleDelegateWallet
/// @notice A minimal smart wallet that EOAs can delegate to via EIP-7702
/// @dev After delegation, the EOA's code points to this implementation
contract SimpleDelegateWallet {
    /// @notice Execute a single call from the delegated EOA
    /// @param target The address to call
    /// @param value The ETH value to send
    /// @param data The calldata to send
    /// @return result The return data from the call
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external payable returns (bytes memory result) {
        // In delegated context, address(this) is the EOA address
        // Only the EOA itself (via direct transaction) can call execute
        require(msg.sender == address(this), "SimpleDelegateWallet: unauthorized");

        bool success;
        (success, result) = target.call{value: value}(data);
        require(success, "SimpleDelegateWallet: call failed");
    }

    /// @notice Receive ETH
    receive() external payable {}
}
