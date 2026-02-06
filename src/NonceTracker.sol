// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {BitMaps} from "openzeppelin-contracts/contracts/utils/structs/BitMaps.sol";

/**
 * @title INonceTracker
 * @notice Nonce tracker interface for managing smart contract account nonce state
 * @dev Implementers must provide useNonce and isNonceUsed for SmartAccount and other account contracts
 */
interface INonceTracker {
    /// @notice Marks the caller's given nonce as used
    /// @param nonce Nonce value to mark as used
    function useNonce(uint256 nonce) external;

    /// @notice Checks whether the given account's nonce has been used
    /// @param account Account address to check
    /// @param nonce Nonce value to check
    /// @return true if nonce has been used, false otherwise
    function isNonceUsed(address account, uint256 nonce) external view returns (bool);
}

/**
 * @title NonceTracker
 * @notice Singleton contract for managing smart contract account nonce state and preventing replay attacks
 * @dev Separates nonce storage from account contracts so other delegates cannot accidentally revert state
 *
 * Main features:
 * - Gas-efficient nonce tracking via BitMaps
 * - Random (non-sequential) nonce values for flexibility
 * - Singleton design; multiple account contracts share one NonceTracker instance
 * - Suitable for EIP-7702 accounts and ERC-1967 implementation override scenarios
 */
contract NonceTracker is INonceTracker {
    using BitMaps for BitMaps.BitMap;

    /// @notice Tracks used nonces per account via BitMaps for gas-efficient storage
    mapping(address account => BitMaps.BitMap) private _usedNonces;

    /// @notice Emitted when an account's nonce is used
    /// @param account Account address that used the nonce
    /// @param nonce Nonce value that was used
    event NonceUsed(address indexed account, uint256 nonce);

    /// @notice Marks the caller's given nonce as used
    /// @dev Reverts if the nonce is already used. Supports arbitrary random nonces (no sequential requirement).
    /// @param nonce Nonce value to mark as used (may be any random value)
    /// @custom:security Prevents replay attacks; each nonce can only be used once
    function useNonce(uint256 nonce) external {
        if (isNonceUsed(msg.sender, nonce)) {
            revert NonceAlreadyUsed(msg.sender, nonce);
        }
        _markNonceUsed(msg.sender, nonce);
        emit NonceUsed(msg.sender, nonce);
    }

    /// @notice Checks whether the given account's nonce has been used
    /// @dev Efficient lookup via BitMaps with low gas cost
    /// @param account Account address to check
    /// @param nonce Nonce value to check
    /// @return true if nonce has been used, false otherwise
    function isNonceUsed(address account, uint256 nonce) public view returns (bool) {
        return _usedNonces[account].get(nonce);
    }

    /// @notice Internal: marks the given account's nonce as used
    /// @dev Directly updates the BitMap without duplicate check. Caller must ensure nonce is unused (e.g. via useNonce).
    /// @param account Account address
    /// @param nonce Nonce value to mark as used
    function _markNonceUsed(address account, uint256 nonce) internal {
        _usedNonces[account].set(nonce);
    }

    /// @notice Reverts when attempting to use an already-used nonce
    /// @param account Account that attempted to use the nonce
    /// @param nonce Nonce value that was already used
    error NonceAlreadyUsed(address account, uint256 nonce);
}
