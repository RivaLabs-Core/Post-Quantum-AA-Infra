// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SphincsWotscAccountFactory} from "./SphincsWotscAccountFactory.sol";
import {SphincsAccount_v6} from "./SphincsAccount_v6.sol";
import {ISphincsVerifier} from "./Interfaces/ISphincsVerifier.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

/// @title SphincsAccountFactory_v6
/// @notice Deploys `SphincsAccount_v6` clones (6,524-byte `SphincsVerifier_v6` signatures).
contract SphincsAccountFactory_v6 is SphincsWotscAccountFactory {
    constructor(IEntryPoint _entryPoint, ISphincsVerifier _verifier) SphincsWotscAccountFactory(_entryPoint, _verifier) {}

    function _deployImplementation(IEntryPoint _entryPoint, ISphincsVerifier _verifier)
        internal
        override
        returns (address)
    {
        return address(new SphincsAccount_v6(_entryPoint, _verifier));
    }
}
