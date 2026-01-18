### EIP7702 Playground 


                                                                                                       
  Summary       
  
```

                                                               
                                                                                                                   
                                                                                                                     
                                                       
  - contracts/SimpleDelegateWallet.sol - Minimal smart wallet with execute() function                                
  - contracts/BatchExecutor.sol - Smart wallet with executeBatch() for atomic multi-calls                            
  - contracts/mocks/MockERC20.sol - Test ERC20 token                                                                 
  - tests/SimpleDelegateWallet.t.sol - 5 tests for single execution wallet                                           
  - tests/BatchExecutor.t.sol - 7 tests for batch executor                                                           
                                                                                                                     
  Key features demonstrated:                                                                                         
  - EOA delegation using vm.signAndAttachDelegation() cheatcode                                                      
  - Authorization via msg.sender == address(this) pattern                                                            
  - Single call execution through delegated code                                                                     
  - Atomic batch execution with rollback on failure                                                                  
  - ETH and ERC20 transfers through delegated wallets           



```





#### Deploying 
 

yarn deploy --network mainnet 
yarn deploy --network base 



 yarn hardhat verify --network base 0x1082d89364765ED958c830F4E77D001837984E31
