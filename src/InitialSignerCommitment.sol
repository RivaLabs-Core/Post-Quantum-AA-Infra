// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev Shared domain separators for deterministic account salts and first-signer leaves.
library InitialSignerCommitment {
    bytes32 internal constant ACCOUNT_SALT_TYPEHASH =
        keccak256("NiceTryAccountSalt:v1(bytes32 initialSignerRoot,uint256 salt)");

    bytes32 internal constant INITIAL_SIGNER_LEAF_TYPEHASH =
        keccak256("NiceTryInitialSignerLeaf:v1(uint256 chainId,address signer)");

    uint8 internal constant ACTIVATION_SIGNATURE_VERSION = 1;

    function accountSalt(bytes32 initialSignerRoot, uint256 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(ACCOUNT_SALT_TYPEHASH, initialSignerRoot, salt));
    }

    function initialSignerLeaf(uint256 chainId, address signer) internal pure returns (bytes32) {
        return keccak256(abi.encode(INITIAL_SIGNER_LEAF_TYPEHASH, chainId, signer));
    }
}
