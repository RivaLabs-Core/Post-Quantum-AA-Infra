// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    SPHINCS_DEFAULT_MINUS_SIG_LEN,
    SPHINCS_FAST_TRADE_PLUS_SIG_LEN,
    SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_SIG_LEN,
    SPHINCS_PLUS_128S_SIG_LEN
} from "./Verifiers/SphincsParameterSetVerifiers.sol";

uint256 constant SPHINCS_PROFILE_COUNT = 4;

/// @dev Profile order is part of the account-address commitment and must not be reordered.
enum SphincsProfile {
    FastTradePlus,
    DefaultMinus,
    GasSaverMinusQ18Aggressive,
    SphincsPlus128s
}

struct SphincsPublicKey {
    bytes32 pkSeed;
    bytes32 pkRoot;
}

library SphincsProfiles {
    function signatureLength(SphincsProfile profile) internal pure returns (uint256) {
        if (profile == SphincsProfile.FastTradePlus) return SPHINCS_FAST_TRADE_PLUS_SIG_LEN;
        if (profile == SphincsProfile.DefaultMinus) return SPHINCS_DEFAULT_MINUS_SIG_LEN;
        if (profile == SphincsProfile.GasSaverMinusQ18Aggressive) {
            return SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_SIG_LEN;
        }
        return SPHINCS_PLUS_128S_SIG_LEN;
    }
}
