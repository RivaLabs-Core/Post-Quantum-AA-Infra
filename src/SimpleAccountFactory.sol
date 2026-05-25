// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SimpleAccount} from "./SimpleAccount.sol";
import {ISignatureVerifier} from "./Interfaces/ISignatureVerifier.sol";
import {InitialSignerCommitment} from "./InitialSignerCommitment.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {LibClone} from "solady/utils/LibClone.sol";

/// @title SimpleAccountFactory
/// @notice Deploys FORS-backed accounts as EIP-1167 minimal proxies pointing at
///         a single implementation contract.
contract SimpleAccountFactory {
    IEntryPoint public immutable ENTRY_POINT;
    ISignatureVerifier public immutable VERIFIER;
    address public immutable ACCOUNT_IMPL;

    event AccountCreated(address indexed account, bytes32 indexed initialSignerRoot, uint256 salt);

    constructor(IEntryPoint _entryPoint, ISignatureVerifier _verifier) {
        ENTRY_POINT = _entryPoint;
        VERIFIER = _verifier;
        ACCOUNT_IMPL = address(new SimpleAccount(_entryPoint, _verifier));
    }

    function createAccount(bytes32 initialSignerRoot, uint256 salt) external returns (address accountAddr) {
        require(initialSignerRoot != bytes32(0), "SimpleAccountFactory: zero root");

        bytes32 fullSalt = _salt(initialSignerRoot, salt);

        address predicted = LibClone.predictDeterministicAddress(ACCOUNT_IMPL, fullSalt, address(this));
        if (predicted.code.length > 0) return predicted;

        accountAddr = LibClone.cloneDeterministic(ACCOUNT_IMPL, fullSalt);
        SimpleAccount(payable(accountAddr)).initialize(initialSignerRoot);

        emit AccountCreated(accountAddr, initialSignerRoot, salt);
    }

    function getAddress(bytes32 initialSignerRoot, uint256 salt) public view returns (address) {
        return LibClone.predictDeterministicAddress(ACCOUNT_IMPL, _salt(initialSignerRoot, salt), address(this));
    }

    function _salt(bytes32 initialSignerRoot, uint256 salt) internal pure returns (bytes32) {
        return InitialSignerCommitment.accountSalt(initialSignerRoot, salt);
    }
}
