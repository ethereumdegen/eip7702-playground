// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/BatchExecutor.sol";
import "../contracts/mocks/MockERC20.sol";

contract BatchExecutorTest is Test {
    BatchExecutor public implementation;
    MockERC20 public token;

    uint256 constant EOA_PRIVATE_KEY = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
    address payable eoaAddress;

    address recipient1 = address(0xBEEF);
    address recipient2 = address(0xCAFE);
    address recipient3 = address(0xDEAD);

    function setUp() public {
        // Deploy the implementation contract
        implementation = new BatchExecutor();

        // Deploy mock token
        token = new MockERC20("Test Token", "TEST");

        // Derive EOA address from private key
        eoaAddress = payable(vm.addr(EOA_PRIVATE_KEY));

        // Fund the EOA
        vm.deal(eoaAddress, 10 ether);
    }

    function test_BatchETHTransfers() public {
        // Delegate EOA to the implementation
        vm.signAndAttachDelegation(address(implementation), EOA_PRIVATE_KEY);

        // Create batch of ETH transfers
        BatchExecutor.Call[] memory calls = new BatchExecutor.Call[](3);
        calls[0] = BatchExecutor.Call({target: recipient1, value: 1 ether, data: ""});
        calls[1] = BatchExecutor.Call({target: recipient2, value: 2 ether, data: ""});
        calls[2] = BatchExecutor.Call({target: recipient3, value: 0.5 ether, data: ""});

        // Execute batch
        vm.prank(eoaAddress);
        BatchExecutor(eoaAddress).executeBatch(calls);

        assertEq(recipient1.balance, 1 ether);
        assertEq(recipient2.balance, 2 ether);
        assertEq(recipient3.balance, 0.5 ether);
        assertEq(eoaAddress.balance, 6.5 ether);
    }

    function test_BatchERC20Transfers() public {
        // Mint tokens to the EOA
        token.mint(eoaAddress, 1000e18);

        // Delegate EOA to the implementation
        vm.signAndAttachDelegation(address(implementation), EOA_PRIVATE_KEY);

        // Create batch of token transfers
        BatchExecutor.Call[] memory calls = new BatchExecutor.Call[](3);
        calls[0] = BatchExecutor.Call({
            target: address(token),
            value: 0,
            data: abi.encodeCall(token.transfer, (recipient1, 100e18))
        });
        calls[1] = BatchExecutor.Call({
            target: address(token),
            value: 0,
            data: abi.encodeCall(token.transfer, (recipient2, 200e18))
        });
        calls[2] = BatchExecutor.Call({
            target: address(token),
            value: 0,
            data: abi.encodeCall(token.transfer, (recipient3, 50e18))
        });

        // Execute batch
        vm.prank(eoaAddress);
        BatchExecutor(eoaAddress).executeBatch(calls);

        assertEq(token.balanceOf(recipient1), 100e18);
        assertEq(token.balanceOf(recipient2), 200e18);
        assertEq(token.balanceOf(recipient3), 50e18);
        assertEq(token.balanceOf(eoaAddress), 650e18);
    }

    function test_BatchMixedOperations() public {
        // Mint tokens to the EOA
        token.mint(eoaAddress, 1000e18);

        // Delegate EOA to the implementation
        vm.signAndAttachDelegation(address(implementation), EOA_PRIVATE_KEY);

        // Create batch with mixed ETH and token transfers
        BatchExecutor.Call[] memory calls = new BatchExecutor.Call[](2);
        calls[0] = BatchExecutor.Call({target: recipient1, value: 1 ether, data: ""});
        calls[1] = BatchExecutor.Call({
            target: address(token),
            value: 0,
            data: abi.encodeCall(token.transfer, (recipient2, 100e18))
        });

        // Execute batch
        vm.prank(eoaAddress);
        BatchExecutor(eoaAddress).executeBatch(calls);

        assertEq(recipient1.balance, 1 ether);
        assertEq(token.balanceOf(recipient2), 100e18);
    }

    function test_BatchAtomicRollbackOnFailure() public {
        // Mint tokens to the EOA - not enough for all transfers
        token.mint(eoaAddress, 100e18);

        // Delegate EOA to the implementation
        vm.signAndAttachDelegation(address(implementation), EOA_PRIVATE_KEY);

        // Create batch where second call will fail
        BatchExecutor.Call[] memory calls = new BatchExecutor.Call[](2);
        calls[0] = BatchExecutor.Call({
            target: address(token),
            value: 0,
            data: abi.encodeCall(token.transfer, (recipient1, 50e18))
        });
        calls[1] = BatchExecutor.Call({
            target: address(token),
            value: 0,
            data: abi.encodeCall(token.transfer, (recipient2, 100e18)) // This will fail - insufficient balance
        });

        // Execute batch - should revert
        vm.prank(eoaAddress);
        vm.expectRevert("BatchExecutor: call failed");
        BatchExecutor(eoaAddress).executeBatch(calls);

        // Verify no transfers occurred (atomic rollback)
        assertEq(token.balanceOf(recipient1), 0);
        assertEq(token.balanceOf(recipient2), 0);
        assertEq(token.balanceOf(eoaAddress), 100e18);
    }

    function test_BatchUnauthorizedCallerReverts() public {
        // Delegate EOA to the implementation
        vm.signAndAttachDelegation(address(implementation), EOA_PRIVATE_KEY);

        // Create batch
        BatchExecutor.Call[] memory calls = new BatchExecutor.Call[](1);
        calls[0] = BatchExecutor.Call({target: recipient1, value: 1 ether, data: ""});

        // Try to execute from a different address
        address attacker = address(0xBAD);
        vm.prank(attacker);
        vm.expectRevert("BatchExecutor: unauthorized");
        BatchExecutor(eoaAddress).executeBatch(calls);
    }

    function test_SingleExecuteWorks() public {
        // Delegate EOA to the implementation
        vm.signAndAttachDelegation(address(implementation), EOA_PRIVATE_KEY);

        // Execute single call
        vm.prank(eoaAddress);
        BatchExecutor(eoaAddress).execute(recipient1, 1 ether, "");

        assertEq(recipient1.balance, 1 ether);
    }

    function test_EmptyBatchSucceeds() public {
        // Delegate EOA to the implementation
        vm.signAndAttachDelegation(address(implementation), EOA_PRIVATE_KEY);

        // Create empty batch
        BatchExecutor.Call[] memory calls = new BatchExecutor.Call[](0);

        // Execute empty batch - should succeed
        vm.prank(eoaAddress);
        BatchExecutor(eoaAddress).executeBatch(calls);
    }
}
