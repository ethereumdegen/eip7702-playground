// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/SponsoredWallet.sol";
import "../contracts/mocks/MockERC20.sol";

contract SponsoredWalletTest is Test {
    SponsoredWallet public implementation;
    MockERC20 public token;

    uint256 constant EOA_PRIVATE_KEY = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
    address payable eoaAddress;

    address sponsor = address(0x5904508);
    address recipient = address(0xBEEF);

    function setUp() public {
        // Deploy the implementation contract
        implementation = new SponsoredWallet();

        // Deploy mock token
        token = new MockERC20("Test Token", "TEST");

        // Derive EOA address from private key
        eoaAddress = payable(vm.addr(EOA_PRIVATE_KEY));

        // Fund the SPONSOR, not the EOA
        vm.deal(sponsor, 100 ether);

        // EOA has 0 ETH!
        assertEq(eoaAddress.balance, 0);
    }

    function test_SponsoredERC20Transfer_EOAHasZeroETH() public {
        // Give the EOA some tokens (but still 0 ETH)
        token.mint(eoaAddress, 1000e18);

        // Delegate EOA to the implementation
        vm.signAndAttachDelegation(address(implementation), EOA_PRIVATE_KEY);

        // Verify EOA still has 0 ETH
        assertEq(eoaAddress.balance, 0);

        // Build the call data for token transfer
        bytes memory transferData = abi.encodeCall(token.transfer, (recipient, 100e18));

        // EOA signs authorization for this specific call
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode(
                    block.chainid,
                    eoaAddress,
                    uint256(0), // nonce
                    address(token),
                    uint256(0), // value
                    keccak256(transferData)
                ))
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(EOA_PRIVATE_KEY, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // SPONSOR submits the transaction (pays for gas)
        // EOA still has 0 ETH!
        vm.prank(sponsor);
        SponsoredWallet(eoaAddress).executeWithSignature(
            address(token),
            0,
            transferData,
            signature
        );

        // Verify the transfer succeeded
        assertEq(token.balanceOf(recipient), 100e18);
        assertEq(token.balanceOf(eoaAddress), 900e18);

        // EOA still has 0 ETH - sponsor paid for everything
        assertEq(eoaAddress.balance, 0);
    }

    function test_SponsoredBatchTransfers() public {
        // Give the EOA tokens
        token.mint(eoaAddress, 1000e18);

        // Delegate EOA to the implementation
        vm.signAndAttachDelegation(address(implementation), EOA_PRIVATE_KEY);

        // First sponsored transfer
        bytes memory transfer1 = abi.encodeCall(token.transfer, (recipient, 100e18));
        bytes32 hash1 = _buildMessageHash(eoaAddress, 0, address(token), 0, transfer1);
        bytes memory sig1 = _sign(EOA_PRIVATE_KEY, hash1);

        vm.prank(sponsor);
        SponsoredWallet(eoaAddress).executeWithSignature(address(token), 0, transfer1, sig1);

        // Second sponsored transfer (nonce incremented)
        bytes memory transfer2 = abi.encodeCall(token.transfer, (recipient, 200e18));
        bytes32 hash2 = _buildMessageHash(eoaAddress, 1, address(token), 0, transfer2);
        bytes memory sig2 = _sign(EOA_PRIVATE_KEY, hash2);

        vm.prank(sponsor);
        SponsoredWallet(eoaAddress).executeWithSignature(address(token), 0, transfer2, sig2);

        assertEq(token.balanceOf(recipient), 300e18);
        assertEq(eoaAddress.balance, 0); // Still 0 ETH
    }

    function test_ReplayAttackPrevented() public {
        token.mint(eoaAddress, 1000e18);
        vm.signAndAttachDelegation(address(implementation), EOA_PRIVATE_KEY);

        bytes memory transferData = abi.encodeCall(token.transfer, (recipient, 100e18));
        bytes32 hash = _buildMessageHash(eoaAddress, 0, address(token), 0, transferData);
        bytes memory sig = _sign(EOA_PRIVATE_KEY, hash);

        // First execution succeeds
        vm.prank(sponsor);
        SponsoredWallet(eoaAddress).executeWithSignature(address(token), 0, transferData, sig);

        // Replay with same signature fails (nonce incremented)
        vm.prank(sponsor);
        vm.expectRevert("SponsoredWallet: invalid signature");
        SponsoredWallet(eoaAddress).executeWithSignature(address(token), 0, transferData, sig);
    }

    function test_InvalidSignatureReverts() public {
        token.mint(eoaAddress, 1000e18);
        vm.signAndAttachDelegation(address(implementation), EOA_PRIVATE_KEY);

        bytes memory transferData = abi.encodeCall(token.transfer, (recipient, 100e18));

        // Sign with wrong private key
        uint256 wrongKey = 0xdeadbeef;
        bytes32 hash = _buildMessageHash(eoaAddress, 0, address(token), 0, transferData);
        bytes memory badSig = _sign(wrongKey, hash);

        vm.prank(sponsor);
        vm.expectRevert("SponsoredWallet: invalid signature");
        SponsoredWallet(eoaAddress).executeWithSignature(address(token), 0, transferData, badSig);
    }

    function test_DirectExecuteStillWorks() public {
        // Fund the EOA for this test
        vm.deal(eoaAddress, 1 ether);
        token.mint(eoaAddress, 1000e18);

        vm.signAndAttachDelegation(address(implementation), EOA_PRIVATE_KEY);

        bytes memory transferData = abi.encodeCall(token.transfer, (recipient, 100e18));

        // Direct execute (EOA pays for gas)
        vm.prank(eoaAddress);
        SponsoredWallet(eoaAddress).execute(address(token), 0, transferData);

        assertEq(token.balanceOf(recipient), 100e18);
    }

    // Helper functions
    function _buildMessageHash(
        address wallet,
        uint256 nonce,
        address target,
        uint256 value,
        bytes memory data
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode(
                    block.chainid,
                    wallet,
                    nonce,
                    target,
                    value,
                    keccak256(data)
                ))
            )
        );
    }

    function _sign(uint256 privateKey, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        return abi.encodePacked(r, s, v);
    }
}
