// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SphincsWotscAccount} from "./SphincsWotscAccount.sol";
import {ISphincsVerifier} from "./Interfaces/ISphincsVerifier.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {SPHINCS_V6_SIG_LEN} from "./Verifiers/SphincsVerifier_v6.sol";

/// @title SphincsAccount_v6
/// @notice SPHINCS--only ERC-4337 account for `SphincsVerifier_v6`: n=16 h=24 d=3 (subtrees 10, 7,
///         7 from the top) a=9 k=19 w=4, WOTS+C, 6,524-byte signature.
/// @dev    SIGNATURE BUDGET. 2^24 FORS instances keep FORS at the 128-bit cap up to about 2^24
///         signatures per key (~110 bits at 2^26).
///
///         COST. Verification is ~70K gas and the signature is 6,524 calldata bytes (~104K gas at
///         16/byte), so budget roughly 175K gas per UserOp before the call itself. Set
///         `verificationGasLimit` accordingly and confirm the bundler accepts a signature field
///         this large.
contract SphincsAccount_v6 is SphincsWotscAccount {
    constructor(IEntryPoint _entryPoint, ISphincsVerifier _verifier) SphincsWotscAccount(_entryPoint, _verifier) {}

    function _sigLen() internal pure override returns (uint256) {
        return SPHINCS_V6_SIG_LEN;
    }
}
