// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SphincsWotscAccount} from "./SphincsWotscAccount.sol";
import {ISphincsVerifier} from "./Interfaces/ISphincsVerifier.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {SPHINCS_V5_SIG_LEN} from "./Verifiers/SphincsVerifier_v5.sol";

/// @title SphincsAccount_v5
/// @notice SPHINCS--only ERC-4337 account for `SphincsVerifier_v5`: n=16 h=26 d=3 (subtrees 10, 8,
///         8 from the top) a=10 k=24 w=4, WOTS+C, 7,740-byte signature.
/// @dev    SIGNATURE BUDGET. 2^26 FORS instances of k=24 a=10 keep FORS at the 128-bit cap up to
///         about 2^30 signatures per key (~94 bits at 2^32).
///
///         COST. Verification is ~81K gas and the signature is 7,740 calldata bytes (~124K gas at
///         16/byte), so budget roughly 205K gas per UserOp before the call itself. Set
///         `verificationGasLimit` accordingly and confirm the bundler accepts a signature field
///         this large.
contract SphincsAccount_v5 is SphincsWotscAccount {
    constructor(IEntryPoint _entryPoint, ISphincsVerifier _verifier) SphincsWotscAccount(_entryPoint, _verifier) {}

    function _sigLen() internal pure override returns (uint256) {
        return SPHINCS_V5_SIG_LEN;
    }
}
