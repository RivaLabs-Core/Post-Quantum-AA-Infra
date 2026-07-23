// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SphincsPublicKey} from "./SphincsProfiles.sol";

/// @dev Shared domain separators for deterministic account salts and first-signer leaves.
library InitialSignerCommitment {
    bytes32 internal constant ACCOUNT_SALT_TYPEHASH =
        keccak256("NiceTryAccountSalt:v3(bytes32 initialSignerRoot,bytes32 sphincsKeysCommitment,uint256 salt)");

    bytes32 internal constant SPHINCS_KEYS_COMMITMENT_TYPEHASH = keccak256(
        "NiceTrySphincsKeys:v1(bytes32 fastTradePlusPkSeed,bytes32 fastTradePlusPkRoot,bytes32 defaultMinusPkSeed,bytes32 defaultMinusPkRoot,bytes32 gasSaverPkSeed,bytes32 gasSaverPkRoot,bytes32 sphincsPlus128sPkSeed,bytes32 sphincsPlus128sPkRoot)"
    );

    bytes32 internal constant INITIAL_SIGNER_LEAF_TYPEHASH =
        keccak256("NiceTryInitialSignerLeaf:v1(uint256 chainId,address signer)");

    uint8 internal constant ACTIVATION_SIGNATURE_VERSION = 1;

    /// @notice Deterministic CREATE2 salt binding the initial-signer root and all SPHINCS keys.
    function accountSalt(bytes32 initialSignerRoot, bytes32 keysCommitment, uint256 salt)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(ACCOUNT_SALT_TYPEHASH, initialSignerRoot, keysCommitment, salt));
    }

    /// @notice Ordered commitment to the four profile-specific SPHINCS public keys.
    function sphincsKeysCommitment(SphincsPublicKey[4] calldata keys) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                SPHINCS_KEYS_COMMITMENT_TYPEHASH,
                keys[0].pkSeed,
                keys[0].pkRoot,
                keys[1].pkSeed,
                keys[1].pkRoot,
                keys[2].pkSeed,
                keys[2].pkRoot,
                keys[3].pkSeed,
                keys[3].pkRoot
            )
        );
    }

    function initialSignerLeaf(uint256 chainId, address signer) internal pure returns (bytes32) {
        return keccak256(abi.encode(INITIAL_SIGNER_LEAF_TYPEHASH, chainId, signer));
    }
}
