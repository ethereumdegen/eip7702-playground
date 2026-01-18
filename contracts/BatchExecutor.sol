// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BatchExecutor
/// @notice A smart wallet with batched transaction support for EIP-7702 delegation
/// @dev Enables atomic execution of multiple calls in a single transaction
contract BatchExecutor {
    /// @notice A single call to execute
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    /// @notice Execute a batch of calls atomically
    /// @param calls Array of calls to execute
    /// @return results Array of return data from each call
    function executeBatch(Call[] calldata calls) external payable returns (bytes[] memory results) {
        // In delegated context, address(this) is the EOA address
        require(msg.sender == address(this), "BatchExecutor: unauthorized");

        results = new bytes[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            (bool success, bytes memory result) = calls[i].target.call{value: calls[i].value}(
                calls[i].data
            );
            require(success, "BatchExecutor: call failed");
            results[i] = result;
        }
    }

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
        require(msg.sender == address(this), "BatchExecutor: unauthorized");

        bool success;
        (success, result) = target.call{value: value}(data);
        require(success, "BatchExecutor: call failed");
    }

    /// @notice Receive ETH
    receive() external payable {}
}
