// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/SimpleDelegateWallet.sol";
import "../contracts/mocks/MockERC20.sol";



contract SimpleDelegateWalletTest is Test {
    SimpleDelegateWallet public implementation;
    MockERC20 public token;

    uint256 constant EOA_PRIVATE_KEY = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
    address payable eoaAddress;

    address recipient = address(0xBEEF);

    function setUp() public {
        // Deploy the implementation contract
        implementation = new SimpleDelegateWallet();

        // Deploy mock token
        token = new MockERC20("Test Token", "TEST");

        // Derive EOA address from private key
        eoaAddress = payable(vm.addr(EOA_PRIVATE_KEY));

        // Fund the EOA
        vm.deal(eoaAddress, 10 ether);
    }



/*  test_EOACanExecuteAfterDelegation
    how this looks on the frontend with viem...

      import { walletClient } from './config'                                                                            
                                                                                                                         
      // 1. EOA signs the authorization    Just an offchain sig!                                                                               
      const authorization = await walletClient.signAuthorization({                                                       
        contractAddress: '0x...SponsoredWallet',                                                                         
      })                                                                                                                 
                                                                                                                         
      // 2. Sponsor submits tx with the authorization attached                                                           
      const hash = await sponsorClient.sendTransaction({                                                                 
        to: eoaAddress,                                                                                                  
        data: encodeFunctionData({                                                                                       
          abi: sponsoredWalletAbi,                                                                                       
          functionName: 'executeWithSignature',                                                                          
          args: [target, value, data, signature]                                                                         
        }),                                                                                                              
        authorizationList: [authorization],                                                                              
      })                                                                                                                 
        
*/ 

    function test_EOACanExecuteAfterDelegation() public {
        // Delegate EOA to the implementation
        vm.signAndAttachDelegation(address(implementation), EOA_PRIVATE_KEY);



        // Now the EOA has the implementation's code
        // Execute a call through the delegated wallet
        vm.prank(eoaAddress);
        SimpleDelegateWallet(eoaAddress).execute(recipient, 1 ether, "");

        assertEq(recipient.balance, 1 ether);
        assertEq(eoaAddress.balance, 9 ether);
    }

    function test_EOACanInteractWithContracts() public {
        // Mint tokens to the EOA
        token.mint(eoaAddress, 1000e18);

        // Delegate EOA to the implementation
        vm.signAndAttachDelegation(address(implementation), EOA_PRIVATE_KEY);

        // Transfer tokens through the delegated wallet
        bytes memory transferData = abi.encodeCall(token.transfer, (recipient, 100e18));

        vm.prank(eoaAddress);
        SimpleDelegateWallet(eoaAddress).execute(address(token), 0, transferData);

        assertEq(token.balanceOf(recipient), 100e18);
        assertEq(token.balanceOf(eoaAddress), 900e18);
    }

    function test_UnauthorizedCallerReverts() public {
        // Delegate EOA to the implementation
        vm.signAndAttachDelegation(address(implementation), EOA_PRIVATE_KEY);

        // Try to execute from a different address
        address attacker = address(0xBAD);
        vm.prank(attacker);
        vm.expectRevert("SimpleDelegateWallet: unauthorized");
        SimpleDelegateWallet(eoaAddress).execute(recipient, 1 ether, "");
    }

    function test_EOACanReceiveETH() public {
        // Delegate EOA to the implementation
        vm.signAndAttachDelegation(address(implementation), EOA_PRIVATE_KEY);

        // Send ETH to the delegated EOA
        address sender = address(0xCAFE);
        vm.deal(sender, 5 ether);

        vm.prank(sender);
        (bool success, ) = eoaAddress.call{value: 2 ether}("");
        assertTrue(success);

        assertEq(eoaAddress.balance, 12 ether);
    }

    function test_FailedCallReverts() public {
        // Delegate EOA to the implementation
        vm.signAndAttachDelegation(address(implementation), EOA_PRIVATE_KEY);

        // Try to transfer more tokens than the EOA has
        bytes memory transferData = abi.encodeCall(token.transfer, (recipient, 100e18));

        vm.prank(eoaAddress);
        vm.expectRevert("SimpleDelegateWallet: call failed");
        SimpleDelegateWallet(eoaAddress).execute(address(token), 0, transferData);
    }
}
