// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;




/*



● Kernel is ZeroDev's modular smart account implementation. Here's how it fits in:                                   
                                                                                                                     
  What Kernel Is                                                                                                     
                                                                                                                     
  Kernel is a production-grade smart wallet that implements ERC-4337 (the UserOperation-based account abstraction    
  standard). It provides:                                                                                            
                                                                                                                     
  - Modular validators - Pluggable signature validation (ECDSA, passkeys, multisig, etc.)                            
  - Modular executors - Custom execution logic (session keys, spending limits, etc.)                                 
  - Hooks - Pre/post execution checks                                                                                
  - Fallback handlers - Extend functionality dynamically                                                             
                                                                                                                     
  Kernel vs. Our Simple Implementations                                                                              
  ┌──────────────────┬─────────────────────────────┬──────────────────────────────────────────┐                      
  │     Feature      │    SimpleDelegateWallet     │                  Kernel                  │                      
  ├──────────────────┼─────────────────────────────┼──────────────────────────────────────────┤                      
  │ Execution        │ Basic execute()             │ Full ERC-4337 validateUserOp + execution │                      
  ├──────────────────┼─────────────────────────────┼──────────────────────────────────────────┤                      
  │ Auth             │ msg.sender == address(this) │ Pluggable validators                     │                      
  ├──────────────────┼─────────────────────────────┼──────────────────────────────────────────┤                      
  │ Modularity       │ None                        │ Validators, executors, hooks             │                      
  ├──────────────────┼─────────────────────────────┼──────────────────────────────────────────┤                      
  │ Gas sponsorship  │ Not built-in                │ Via ERC-4337 paymasters                  │                      
  ├──────────────────┼─────────────────────────────┼──────────────────────────────────────────┤                      
  │ Production ready │ Demo only                   │ Yes                                      │                      
  └──────────────────┴─────────────────────────────┴──────────────────────────────────────────┘                      
  EIP-7702 + Kernel                                                                                                  
                                                                                                                     
  With EIP-7702, an EOA can delegate to Kernel's implementation address. This gives the EOA:                         
                                                                                                                     
  1. Modular validation - Use passkeys, session keys, etc. instead of just the EOA's private key                     
  2. Paymaster support - Gas sponsorship through the 4337 infrastructure                                             
  3. Batch operations - Already built into Kernel                                                                    
  4. Upgradability - Can change which implementation the EOA delegates to                                            
                                                                                                                     
  Architecture                                                                                                       
                                                                                                                     
  EOA (your address)                                                                                                 
    │                                                                                                                
    ├─ EIP-7702 delegation ──► Kernel Implementation (deployed contract)                                             
    │                              │                                                                                 
    │                              ├─ Validator Module (e.g., ECDSAValidator)                                        
    │                              ├─ Executor Module (e.g., SessionKeyExecutor)                                     
    │                              └─ Hooks (e.g., SpendingLimitHook)       

*/


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
