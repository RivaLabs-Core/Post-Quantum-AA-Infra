// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev Shared domain separators for deterministic account salts and first-signer leaves.
library InitialSignerCommitment {
    bytes32 internal constant ACCOUNT_SALT_TYPEHASH =
        keccak256("NiceTryAccountSalt:v2(bytes32 initialSignerRoot,bytes32 backupSignerLeaf,uint256 salt)");

    bytes32 internal constant BACKUP_SIGNER_LEAF_TYPEHASH =
        keccak256("NiceTryBackupSignerLeaf:v1(bytes32 pkSeed,bytes32 pkRoot)");

    bytes32 internal constant INITIAL_SIGNER_LEAF_TYPEHASH =
        keccak256("NiceTryInitialSignerLeaf:v1(uint256 chainId,address signer)");

    uint8 internal constant ACTIVATION_SIGNATURE_VERSION = 1;

    /// @notice Deterministic CREATE2 salt binding BOTH the per-chain initial-signer root AND the
    ///         (chain-independent) SPHINCS- backup key, so the multichain address commits to the
    ///         recovery key — a deploy-race cannot install a different backup key at the same address.
    function accountSalt(bytes32 initialSignerRoot, bytes32 backupSignerLeaf, uint256 salt)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(ACCOUNT_SALT_TYPEHASH, initialSignerRoot, backupSignerLeaf, salt));
    }

    /// @notice Leaf committing the durable SPHINCS- backup public key (chain-independent).
    function backupSignerLeaf(bytes32 pkSeed, bytes32 pkRoot) internal pure returns (bytes32) {
        return keccak256(abi.encode(BACKUP_SIGNER_LEAF_TYPEHASH, pkSeed, pkRoot));
    }

    function initialSignerLeaf(uint256 chainId, address signer) internal pure returns (bytes32) {
        return keccak256(abi.encode(INITIAL_SIGNER_LEAF_TYPEHASH, chainId, signer));
    }
}
