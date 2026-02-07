// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {Receiver} from "solady/accounts/Receiver.sol";
import {INonceTracker} from "./NonceTracker.sol";

/**
 * @title SmartAccount
 * @notice Core implementation of a smart contract account with EIP-712 signature verification
 * @dev This contract allows batch execution via EIP-712 structured signatures, with random nonce and expiry validation
 *
 * Main features:
 * - Batch execution of multiple external calls
 * - EIP-712 based signature verification
 * - Random nonce management to prevent replay attacks
 * - Optional signature expiry validation
 * - Direct calls from the contract itself (no signature required)
 */
contract SmartAccount is Receiver {
    using ECDSA for bytes32;

    /// @notice EIP-712 typehash for the Execution struct
    bytes32 internal constant _EXECUTION_TYPEHASH = keccak256("Execution(address target,uint256 value,bytes callData)");

    /// @notice EIP-712 typehash for the Execute message
    bytes32 internal constant _EXECUTE_TYPEHASH = keccak256(
        "Execute(address account,uint256 nonce,uint256 expiry,Execution[] executions)Execution(address target,uint256 value,bytes callData)"
    );

    /// @notice EIP-712 domain separator typehash
    bytes32 internal constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");

    /// @notice Hash of EIP-712 domain name
    bytes32 internal constant _DOMAIN_NAME = keccak256("SmartAccount");

    /// @notice Hash of EIP-712 domain version
    bytes32 internal constant _DOMAIN_VERSION = keccak256("1");

    /// @notice NonceTracker contract instance for managing nonce usage state
    INonceTracker public immutable NONCE_TRACKER;

    /// @notice SmartAccount contract address used to generate EIP-712 domain separator
    address public immutable SMART_ACCOUNT_CONTRACT_ADDRESS;

    /// @notice Emitted when execution succeeds
    /// @param sender Address that initiated execution (contract itself or external caller)
    /// @param account Account address that was executed (this contract address)
    /// @param nonce Nonce value used (0 for internal calls)
    event Executed(address indexed sender, address indexed account, uint256 indexed nonce);

    /// @notice Reverts when caller is not the contract itself
    error NotSelf();

    /// @notice Reverts when signature verification fails
    error InvalidSignature();

    /// @notice Reverts when signature has expired
    error SignatureExpired();

    /// @notice Reverts when nonce is invalid (currently unused, reserved for future extension)
    error InvalidNonce();

    /// @notice Reverts when execution fails
    /// @param index Index of the failed execution
    error ExecutionFailed(uint256 index);

    /// @notice Reverts when address is zero
    error ZeroAddress();

    /// @notice Reverts when executions are invalid
    error InvalidExecutions();

    /// @notice Constructor, initializes NonceTracker contract address
    /// @param nonceTracker_ NonceTracker contract address, must not be zero
    constructor(address nonceTracker_) {
        if (nonceTracker_ == address(0)) revert ZeroAddress();
        NONCE_TRACKER = INonceTracker(nonceTracker_);
        SMART_ACCOUNT_CONTRACT_ADDRESS = address(this);
    }

    /// @notice Execution struct defining a single external call
    /// @param target Target contract address
    /// @param value Amount of ether to send (wei)
    /// @param callData Call data (function selector and arguments)
    struct Execution {
        address target;
        uint256 value;
        bytes callData;
    }

    /// @notice Modifier: allows only the contract itself to call
    modifier onlySelf() {
        _onlySelf();
        _;
    }

    /// @notice Internal: checks if caller is the contract itself
    /// @dev Reverts if caller is not the contract itself
    function _onlySelf() internal view {
        if (msg.sender != address(this)) revert NotSelf();
    }

    /// @notice Internal execution function, callable only by the contract itself (no signature verification)
    /// @dev Used for internal calls, e.g. from the signature-verified execute function
    /// @param _executions Array of calls to execute
    /// @custom:security Only callable by the contract itself, protected by onlySelf modifier
    function execute(Execution[] calldata _executions) external payable onlySelf {
        if (_executions.length == 0) revert InvalidExecutions();

        for (uint256 i = 0; i < _executions.length; i++) {
            if (_executions[i].target == address(0)) revert ZeroAddress();
            (bool success,) = _executions[i].target.call{value: _executions[i].value}(_executions[i].callData);
            if (!success) revert ExecutionFailed(i);
        }

        emit Executed(msg.sender, address(this), 0);
    }

    /// @notice Executes batch transactions with EIP-712 signature verification
    /// @dev Allows external callers to execute batch transactions with a valid EIP-712 signature.
    ///      If caller is the contract itself, signature verification is skipped (for internal calls).
    /// @param _nonce Random nonce to prevent replay attacks (any uint256 value supported)
    /// @param _expiry Signature expiry timestamp (Unix), 0 means never expires
    /// @param _executions Array of calls to execute
    /// @param _signature EIP-712 structured signature from the account private key
    /// @custom:security Signature verification ensures only the account owner can execute
    /// @custom:security Nonce mechanism prevents replay attacks
    /// @custom:security Expiry prevents long-term use of signatures
    function execute(uint256 _nonce, uint256 _expiry, Execution[] calldata _executions, bytes calldata _signature)
        external
        payable
    {
        if (_expiry > 0 && block.timestamp >= _expiry) revert SignatureExpired();
        if (_executions.length == 0) revert InvalidExecutions();

        bytes32 hash = makeExecuteHash(_nonce, _expiry, _executions);

        bytes32 messageHash = toEip712Hash(hash);
        // To estimate gas
        if (msg.sender != address(this) && !isValidSignature(messageHash, _signature)) revert InvalidSignature();

        // Mark the nonce as used (supports random nonce values)
        NONCE_TRACKER.useNonce(_nonce);

        for (uint256 i = 0; i < _executions.length; i++) {
            if (_executions[i].target == address(0)) revert ZeroAddress();
            (bool success,) = _executions[i].target.call{value: _executions[i].value}(_executions[i].callData);
            if (!success) revert ExecutionFailed(i);
        }

        emit Executed(msg.sender, address(this), _nonce);
    }

    /// @notice Produces the EIP-712 struct hash of the Execute message
    /// @dev Computes the struct hash containing all execution data for signature verification.
    ///      First hashes each Execution, then hashes the full Execute message.
    /// @param _nonce Random nonce value
    /// @param _expiry Signature expiry timestamp
    /// @param _executions Array of calls to execute
    /// @return Struct hash of the Execute message
    function makeExecuteHash(uint256 _nonce, uint256 _expiry, Execution[] calldata _executions)
        public
        view
        returns (bytes32)
    {
        uint256 length = _executions.length;
        bytes32[] memory executionHashes = new bytes32[](length);
        for (uint256 i = 0; i < length;) {
            executionHashes[i] = keccak256(
                abi.encode(
                    _EXECUTION_TYPEHASH, _executions[i].target, _executions[i].value, keccak256(_executions[i].callData)
                )
            );
            unchecked {
                ++i;
            }
        }

        return keccak256(
            abi.encode(_EXECUTE_TYPEHASH, address(this), _nonce, _expiry, keccak256(abi.encodePacked(executionHashes)))
        );
    }

    /// @notice Validates whether the signature is valid
    /// @dev Recovers signer via ECDSA and checks it matches the contract address
    /// @param hash Message hash to verify (should be EIP-712 hash)
    /// @param signature Signature bytes
    /// @return true if signature is valid (signer is this contract address), false otherwise
    function isValidSignature(bytes32 hash, bytes calldata signature) public view returns (bool) {
        address signer = ECDSA.recover(hash, signature);
        return signer == address(this);
    }

    /// @notice Returns the EIP-712 domain separator
    /// @dev Domain separator distinguishes signatures across contracts and chains, preventing cross-chain replay
    /// @return EIP-712 domain separator for this contract
    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH,
                _DOMAIN_NAME,
                _DOMAIN_VERSION,
                block.chainid,
                SMART_ACCOUNT_CONTRACT_ADDRESS,
                bytes32(uint256(uint160(address(this))))
            )
        );
    }

    /// @notice Converts struct hash to EIP-712 message hash
    /// @dev Per EIP-712, prepends domain separator and "\x19\x01" prefix to the struct hash
    /// @param structHash Struct hash (from makeExecuteHash)
    /// @return Final message hash for ECDSA signing
    function toEip712Hash(bytes32 structHash) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    /// @notice Checks whether the given nonce has been used
    /// @dev Queries NonceTracker to determine if the nonce is marked as used
    /// @param nonce Nonce value to check
    /// @return true if nonce has been used, false otherwise
    function isNonceUsed(uint256 nonce) public view returns (bool) {
        return NONCE_TRACKER.isNonceUsed(address(this), nonce);
    }
}
