// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SimpleAccount} from "./SimpleAccount.sol";
import {ISignatureVerifier} from "./Interfaces/ISignatureVerifier.sol";
import {ISphincsParamVerifier} from "./Interfaces/ISphincsParamVerifier.sol";
import {InitialSignerCommitment} from "./InitialSignerCommitment.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {LibClone} from "solady/utils/LibClone.sol";

/// @title SimpleAccountFactory
/// @notice Deploys FORS-backed accounts (with durable SPHINCS- backup signers) as EIP-1167 minimal
///         proxies pointing at a single implementation contract. The account address binds BOTH the
///         per-chain initial-signer root AND the (chain-independent) INITIAL SPHINCS- backup key via
///         the CREATE2 salt, so a deploy-race cannot install a different backup key at the same
///         address; that key is registered with the canonical parameter set at initialize().
///         Additional SPHINCS- signers (each with its own parameter set) are enrolled post-deploy
///         by the account itself via addSphincsSigner and are intentionally NOT address-committed.
contract SimpleAccountFactory {
    IEntryPoint public immutable ENTRY_POINT;
    ISignatureVerifier public immutable VERIFIER;
    ISphincsParamVerifier public immutable SPHINCS_PARAM_VERIFIER;
    address public immutable ACCOUNT_IMPL;

    event AccountCreated(address indexed account, bytes32 indexed initialSignerRoot, uint256 salt);

    constructor(IEntryPoint _entryPoint, ISignatureVerifier _verifier, ISphincsParamVerifier _sphincsParamVerifier) {
        ENTRY_POINT = _entryPoint;
        VERIFIER = _verifier;
        SPHINCS_PARAM_VERIFIER = _sphincsParamVerifier;
        ACCOUNT_IMPL = address(new SimpleAccount(_entryPoint, _verifier, _sphincsParamVerifier));
    }

    function createAccount(bytes32 initialSignerRoot, bytes32 backupPkSeed, bytes32 backupPkRoot, uint256 salt)
        external
        returns (address accountAddr)
    {
        bytes32 fullSalt = _salt(initialSignerRoot, backupPkSeed, backupPkRoot, salt);

        address predicted = LibClone.predictDeterministicAddress(ACCOUNT_IMPL, fullSalt, address(this));
        if (predicted.code.length > 0) return predicted;

        accountAddr = LibClone.cloneDeterministic(ACCOUNT_IMPL, fullSalt);
        SimpleAccount(payable(accountAddr)).initialize(initialSignerRoot, backupPkSeed, backupPkRoot);

        emit AccountCreated(accountAddr, initialSignerRoot, salt);
    }

    function getAddress(bytes32 initialSignerRoot, bytes32 backupPkSeed, bytes32 backupPkRoot, uint256 salt)
        public
        view
        returns (address)
    {
        return LibClone.predictDeterministicAddress(
            ACCOUNT_IMPL, _salt(initialSignerRoot, backupPkSeed, backupPkRoot, salt), address(this)
        );
    }

    function _salt(bytes32 initialSignerRoot, bytes32 backupPkSeed, bytes32 backupPkRoot, uint256 salt)
        internal
        pure
        returns (bytes32)
    {
        require(initialSignerRoot != bytes32(0), "SimpleAccountFactory: zero root");
        require(backupPkSeed != bytes32(0) && backupPkRoot != bytes32(0), "SimpleAccountFactory: zero backup key");
        bytes32 backupLeaf = InitialSignerCommitment.backupSignerLeaf(backupPkSeed, backupPkRoot);
        return InitialSignerCommitment.accountSalt(initialSignerRoot, backupLeaf, salt);
    }
}
