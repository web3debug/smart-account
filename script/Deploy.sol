// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {SmartAccount} from "../src/SmartAccount.sol";
import {NonceTracker} from "../src/NonceTracker.sol";
import {TestERC20} from "../src/TestERC20.sol";

contract DeployScript is Script {
    NonceTracker public nonceTracker;
    SmartAccount public smartAccount;
    TestERC20 public testERC20;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        // 先部署 NonceTracker
        nonceTracker = new NonceTracker();
        console.log("NonceTracker deployed at:", address(nonceTracker));

        // 然后部署 SmartAccount，传入 NonceTracker 地址
        smartAccount = new SmartAccount(address(nonceTracker));
        console.log("SmartAccount deployed at:", address(smartAccount));

        // 如果是本地网络，部署测试用的 ERC20 token
        uint256 chainId = block.chainid;
        if (chainId == 31337 || chainId == 1337 || address(msg.sender) == 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266) {
            // 部署测试 ERC20 token，初始供应量为 1000000 * 10^18
            testERC20 = new TestERC20("Test Token", "TEST", 1000000 * 10 ** 18);
            console.log("TestERC20 deployed at:", address(testERC20));
            console.log("TestERC20 name: Test Token");
            console.log("TestERC20 symbol: TEST");
            console.log("TestERC20 initial supply: 1000000");
        }

        vm.stopBroadcast();
    }
}
