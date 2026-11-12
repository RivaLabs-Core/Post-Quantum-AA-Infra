// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SphincsWotscAccountFactory} from "./SphincsWotscAccountFactory.sol";
import {SphincsAccount_v5} from "./SphincsAccount_v5.sol";
import {ISphincsVerifier} from "./Interfaces/ISphincsVerifier.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

/// @title SphincsAccountFactory_v5
/// @notice Deploys `SphincsAccount_v5` clones (7,740-byte `SphincsVerifier_v5` signatures).
contract SphincsAccountFactory_v5 is SphincsWotscAccountFactory {
    constructor(IEntryPoint _entryPoint, ISphincsVerifier _verifier) SphincsWotscAccountFactory(_entryPoint, _verifier) {}

    function _deployImplementation(IEntryPoint _entryPoint, ISphincsVerifier _verifier)
        internal
        override
        returns (address)
    {
        return address(new SphincsAccount_v5(_entryPoint, _verifier));
    }
}
