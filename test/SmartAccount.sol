// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {SmartAccount} from "../src/SmartAccount.sol";
import {NonceTracker} from "../src/NonceTracker.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

contract SmartAccountTest is Test {
    using ECDSA for bytes32;

    // EIP-712 相关常量，与 SmartAccount 合约中的定义保持一致
    bytes32 internal constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    bytes32 internal constant _DOMAIN_NAME = keccak256("SmartAccount");
    bytes32 internal constant _DOMAIN_VERSION = keccak256("1");

    SmartAccount public smartAccount;
    NonceTracker public nonceTracker;
    TestTarget public target;

    // 用于 EIP-7702 测试的用户地址和私钥
    // 使用一个已知的私钥，对应的地址可以通过 vm.addr() 获取
    uint256 public userPrivateKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    address public user;

    // 事件
    event Executed(address indexed sender, address indexed account, uint256 indexed nonce);
    event NonceUsed(address indexed account, uint256 nonce);

    function setUp() public {
        // 从私钥获取用户地址
        user = vm.addr(userPrivateKey);

        // 部署 NonceTracker
        nonceTracker = new NonceTracker();

        // 部署 SmartAccount 合约（用于获取代码）
        // 在 EIP-7702 场景下，合约代码会被挂载到用户地址
        // 由于 NONCE_TRACKER 是 immutable 变量，它会在编译时内联到代码中
        // 所以我们需要先部署一个实例，确保代码中包含正确的 nonceTracker 地址
        smartAccount = new SmartAccount(address(nonceTracker));

        // 部署测试目标合约
        target = new TestTarget();

        // 给用户地址分配 ETH
        vm.deal(user, 100 ether);

        // 在 EIP-7702 场景下，合约代码会被挂载到用户地址
        // 这里我们使用 vm.etch 来模拟 EIP-7702 的效果
        // 注意：在实际的 EIP-7702 实现中，这应该通过特殊的交易类型来完成
        // EIP-7702 格式：0xef0100 (3字节) + 合约地址 (20字节)
        bytes memory code = abi.encodePacked(bytes3(0xef0100), address(smartAccount));
        vm.etch(user, code);
    }

    function test_IsNonceUsed() public view {
        // Test that nonce 0 is not used initially
        bool isUsed = nonceTracker.isNonceUsed(user, 0);
        assertFalse(isUsed, "Initial nonce should not be used");

        // Test that a random nonce is not used
        bool isRandomUsed = nonceTracker.isNonceUsed(user, 12345);
        assertFalse(isRandomUsed, "Random nonce should not be used");
    }

    function test_DomainSeparator() public view {
        bytes32 domain = SmartAccount(payable(user)).domainSeparator();
        // EIP-7702: 代码来自 smartAccount，verifyingContract 为部署时的合约地址，salt 为当前执行地址 user
        bytes32 expectedDomain = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH,
                _DOMAIN_NAME,
                _DOMAIN_VERSION,
                block.chainid,
                address(smartAccount),
                bytes32(uint256(uint160(user)))
            )
        );
        assertTrue(domain == expectedDomain, "Domain separator should be the same as the expected domain");
    }

    function test_makeExecuteHash() public view {
        SmartAccount.Execution[] memory executions = new SmartAccount.Execution[](2);
        executions[0] = SmartAccount.Execution({
            target: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266, value: 1000, callData: bytes("test data")
        });
        executions[1] = SmartAccount.Execution({
            target: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8, value: 2000, callData: bytes("another test data")
        });
        bytes32 hash = SmartAccount(payable(user)).makeExecuteHash(1, 2, executions);
        assertTrue(hash != bytes32(0), "Hash should not be zero");
    }

    function test_NONCE_TRACKER() public view {
        assertEq(
            address(SmartAccount(payable(user)).NONCE_TRACKER()),
            address(nonceTracker),
            "NONCE_TRACKER should be the same as the deployed nonceTracker"
        );
    }

    function test_Execute() public {
        SmartAccount.Execution[] memory executions = new SmartAccount.Execution[](1);
        executions[0] = SmartAccount.Execution({
            target: address(target), value: 0, callData: abi.encodeWithSelector(TestTarget.setValue.selector, 42)
        });

        vm.expectEmit(true, true, true, true);
        emit Executed(user, user, 0);

        vm.prank(user);
        SmartAccount(payable(user)).execute(executions);

        assertEq(target.value(), 42, "Target value should be set to 42");
    }

    function test_ExecuteWithSignature_FromUser() public {
        uint256 nonce = 0;
        uint256 expiry = block.timestamp + 1 hours;

        SmartAccount.Execution[] memory executions = new SmartAccount.Execution[](2);
        executions[0] = SmartAccount.Execution({
            target: address(target), value: 0, callData: abi.encodeWithSelector(TestTarget.setValue.selector, 41)
        });
        executions[1] = SmartAccount.Execution({
            target: address(target), value: 0, callData: abi.encodeWithSelector(TestTarget.setValue.selector, 42)
        });

        bytes32 hash = SmartAccount(payable(user)).makeExecuteHash(nonce, expiry, executions);
        bytes32 messageHash = SmartAccount(payable(user)).toEip712Hash(hash);
        bytes memory signature = _sign(userPrivateKey, messageHash);

        vm.expectEmit(true, true, false, false);
        emit NonceUsed(user, nonce);

        vm.expectEmit(true, true, true, true);
        emit Executed(user, user, nonce);

        vm.prank(user);
        SmartAccount(payable(user)).execute(nonce, expiry, executions, signature);

        assertEq(target.value(), 42, "Target value should be set to 42");
        // Verify that nonce 0 is now used
        assertTrue(nonceTracker.isNonceUsed(user, nonce), "Nonce should be marked as used");
    }

    function test_ExecuteWithSignature_FromRelayer() public {
        uint256 nonce = 0;
        uint256 expiry = block.timestamp + 1 hours;

        SmartAccount.Execution[] memory executions = new SmartAccount.Execution[](2);
        executions[0] = SmartAccount.Execution({
            target: address(target), value: 0, callData: abi.encodeWithSelector(TestTarget.setValue.selector, 41)
        });
        executions[1] = SmartAccount.Execution({
            target: address(target), value: 0, callData: abi.encodeWithSelector(TestTarget.setValue.selector, 42)
        });

        bytes32 hash = SmartAccount(payable(user)).makeExecuteHash(nonce, expiry, executions);
        bytes32 messageHash = SmartAccount(payable(user)).toEip712Hash(hash);
        bytes memory signature = _sign(userPrivateKey, messageHash);

        vm.expectEmit(true, true, false, false);
        emit NonceUsed(user, nonce);

        vm.expectEmit(true, true, true, true);
        emit Executed(address(this), address(user), nonce);

        SmartAccount(payable(user)).execute(nonce, expiry, executions, signature);

        assertEq(target.value(), 42, "Target value should be set to 42");
        // Verify that nonce 0 is now used
        assertTrue(nonceTracker.isNonceUsed(user, nonce), "Nonce should be marked as used");
    }

    function test_IsValidSignature() public view {
        bytes32 hash = keccak256("test message");
        bytes32 messageHash = SmartAccount(payable(user)).toEip712Hash(hash);
        bytes memory signature = _sign(userPrivateKey, messageHash);

        bool isValid = SmartAccount(payable(user)).isValidSignature(messageHash, signature);
        assertTrue(isValid, "Signature should be valid");

        bytes memory invalidSignature = _sign(0x5678, messageHash);
        bool isInvalid = SmartAccount(payable(user)).isValidSignature(messageHash, invalidSignature);
        assertFalse(isInvalid, "Invalid signature should return false");
    }

    function test_RandomNonce() public {
        // Test using a random nonce value
        uint256 randomNonce = 123456789;
        uint256 expiry = block.timestamp + 1 hours;

        SmartAccount.Execution[] memory executions = new SmartAccount.Execution[](1);
        executions[0] = SmartAccount.Execution({
            target: address(target), value: 0, callData: abi.encodeWithSelector(TestTarget.setValue.selector, 99)
        });

        bytes32 hash = SmartAccount(payable(user)).makeExecuteHash(randomNonce, expiry, executions);
        bytes32 messageHash = SmartAccount(payable(user)).toEip712Hash(hash);
        bytes memory signature = _sign(userPrivateKey, messageHash);

        vm.expectEmit(true, true, false, false);
        emit NonceUsed(user, randomNonce);

        vm.expectEmit(true, true, true, true);
        emit Executed(user, user, randomNonce);

        vm.prank(user);
        SmartAccount(payable(user)).execute(randomNonce, expiry, executions, signature);

        assertEq(target.value(), 99, "Target value should be set to 99");
        assertTrue(nonceTracker.isNonceUsed(user, randomNonce), "Random nonce should be marked as used");

        // Try to use the same nonce again - should fail
        vm.expectRevert();
        SmartAccount(payable(user)).execute(randomNonce, expiry, executions, signature);
    }

    function _sign(uint256 privateKey, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        return abi.encodePacked(r, s, v);
    }
}

// 测试目标合约
contract TestTarget {
    uint256 public value;

    function setValue(uint256 _value) external payable {
        value = _value;
    }

    function reset() external {
        value = 0;
    }

    function fail() external pure {
        revert("Test failure");
    }

    receive() external payable {}
}
