// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SponsoredWallet
/// @notice A smart wallet that supports gas sponsorship via signed messages
/// @dev Anyone can submit transactions on behalf of the EOA if they have a valid signature from the EOA
contract SponsoredWallet {
    /// @notice Nonce for replay protection
    mapping(address => uint256) public nonces;

    /// @notice Execute a call with signature verification (allows gas sponsorship)
    /// @param target The address to call
    /// @param value The ETH value to send
    /// @param data The calldata to send
    /// @param signature The EOA's signature authorizing this call
    function executeWithSignature(
        address target,
        uint256 value,
        bytes calldata data,
        bytes calldata signature
    ) external returns (bytes memory result) {
        // Build the message hash
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode(
                    block.chainid,
                    address(this), // The EOA's address (delegated)
                    nonces[address(this)]++,
                    target,
                    value,
                    keccak256(data)
                ))
            )
        );

        // Recover signer from signature
        address signer = _recover(messageHash, signature);

        // Verify the signer is the EOA itself
        require(signer == address(this), "SponsoredWallet: invalid signature");

        // Execute the call
        bool success;
        (success, result) = target.call{value: value}(data);
        require(success, "SponsoredWallet: call failed");
    }

    /// @notice Execute directly (caller must be the EOA itself)
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external payable returns (bytes memory result) {
        require(msg.sender == address(this), "SponsoredWallet: unauthorized");

        bool success;
        (success, result) = target.call{value: value}(data);
        require(success, "SponsoredWallet: call failed");
    }

    /// @notice Recover signer from signature
    function _recover(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "SponsoredWallet: invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }

        if (v < 27) v += 27;

        return ecrecover(hash, v, r, s);
    }

    /// @notice Receive ETH
    receive() external payable {}
}
