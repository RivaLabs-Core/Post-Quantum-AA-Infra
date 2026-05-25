// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev Shared domain separators for deterministic account salts and first-signer leaves.
library InitialSignerCommitment {
    bytes32 internal constant ACCOUNT_SALT_TYPEHASH =
        keccak256("NiceTryAccountSalt:v1(bytes32 initialSignerRoot,uint256 salt)");

    bytes32 internal constant INITIAL_SIGNER_LEAF_TYPEHASH = keccak256(
        "NiceTryInitialSignerLeaf:v1(uint256 chainId,address signer,bytes32 derivationPathHash,uint8 schemeId,uint64 signerIndex)"
    );

    uint8 internal constant ACTIVATION_SIGNATURE_VERSION = 1;
    uint8 internal constant SCHEME_FORS = 1;
    uint64 internal constant INITIAL_SIGNER_INDEX = 0;

    function accountSalt(bytes32 initialSignerRoot, uint256 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(ACCOUNT_SALT_TYPEHASH, initialSignerRoot, salt));
    }

    function initialSignerLeaf(
        uint256 chainId,
        address signer,
        bytes32 derivationPathHash,
        uint8 schemeId,
        uint64 signerIndex
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(INITIAL_SIGNER_LEAF_TYPEHASH, chainId, signer, derivationPathHash, schemeId, signerIndex)
        );
    }
}
