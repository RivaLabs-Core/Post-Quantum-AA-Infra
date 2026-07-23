// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SimpleAccount} from "./SimpleAccount.sol";
import {ISignatureVerifier} from "./Interfaces/ISignatureVerifier.sol";
import {ISphincsVerifier} from "./Interfaces/ISphincsVerifier.sol";
import {InitialSignerCommitment} from "./InitialSignerCommitment.sol";
import {SPHINCS_PROFILE_COUNT, SphincsPublicKey} from "./SphincsProfiles.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {LibClone} from "solady/utils/LibClone.sol";

/// @title SimpleAccountFactory
/// @notice Deploys FORS-backed accounts (with four durable SPHINCS signers) as EIP-1167 minimal
///         proxies pointing at a single implementation contract. The account address binds BOTH the
///         per-chain initial-signer root AND all SPHINCS keys via the CREATE2 salt.
contract SimpleAccountFactory {
    bytes32 private constant SPHINCS_PK_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000;

    IEntryPoint public immutable ENTRY_POINT;
    ISignatureVerifier public immutable VERIFIER;
    ISphincsVerifier public immutable FAST_TRADE_PLUS_VERIFIER;
    ISphincsVerifier public immutable DEFAULT_MINUS_VERIFIER;
    ISphincsVerifier public immutable GAS_SAVER_MINUS_Q18_AGGRESSIVE_VERIFIER;
    ISphincsVerifier public immutable SPHINCS_PLUS_128S_VERIFIER;
    address public immutable ACCOUNT_IMPL;

    event AccountCreated(
        address indexed account, bytes32 indexed initialSignerRoot, bytes32 indexed sphincsKeysCommitment, uint256 salt
    );

    constructor(
        IEntryPoint _entryPoint,
        ISignatureVerifier _verifier,
        ISphincsVerifier _fastTradePlusVerifier,
        ISphincsVerifier _defaultMinusVerifier,
        ISphincsVerifier _gasSaverMinusQ18AggressiveVerifier,
        ISphincsVerifier _sphincsPlus128sVerifier
    ) {
        ENTRY_POINT = _entryPoint;
        VERIFIER = _verifier;
        FAST_TRADE_PLUS_VERIFIER = _fastTradePlusVerifier;
        DEFAULT_MINUS_VERIFIER = _defaultMinusVerifier;
        GAS_SAVER_MINUS_Q18_AGGRESSIVE_VERIFIER = _gasSaverMinusQ18AggressiveVerifier;
        SPHINCS_PLUS_128S_VERIFIER = _sphincsPlus128sVerifier;
        ACCOUNT_IMPL = address(
            new SimpleAccount(
                _entryPoint,
                _verifier,
                _fastTradePlusVerifier,
                _defaultMinusVerifier,
                _gasSaverMinusQ18AggressiveVerifier,
                _sphincsPlus128sVerifier
            )
        );
    }

    function createAccount(
        bytes32 initialSignerRoot,
        SphincsPublicKey[SPHINCS_PROFILE_COUNT] calldata sphincsKeys,
        uint256 salt
    ) external returns (address accountAddr) {
        (bytes32 fullSalt, bytes32 keysCommitment) = _salt(initialSignerRoot, sphincsKeys, salt);

        address predicted = LibClone.predictDeterministicAddress(ACCOUNT_IMPL, fullSalt, address(this));
        if (predicted.code.length > 0) return predicted;

        accountAddr = LibClone.cloneDeterministic(ACCOUNT_IMPL, fullSalt);
        SimpleAccount(payable(accountAddr)).initialize(initialSignerRoot, sphincsKeys);

        emit AccountCreated(accountAddr, initialSignerRoot, keysCommitment, salt);
    }

    function getAddress(
        bytes32 initialSignerRoot,
        SphincsPublicKey[SPHINCS_PROFILE_COUNT] calldata sphincsKeys,
        uint256 salt
    ) public view returns (address) {
        (bytes32 fullSalt,) = _salt(initialSignerRoot, sphincsKeys, salt);
        return LibClone.predictDeterministicAddress(ACCOUNT_IMPL, fullSalt, address(this));
    }

    function _salt(
        bytes32 initialSignerRoot,
        SphincsPublicKey[SPHINCS_PROFILE_COUNT] calldata sphincsKeys,
        uint256 salt
    ) internal pure returns (bytes32 fullSalt, bytes32 keysCommitment) {
        require(initialSignerRoot != bytes32(0), "SimpleAccountFactory: zero root");
        for (uint256 i = 0; i < SPHINCS_PROFILE_COUNT; i++) {
            require(
                sphincsKeys[i].pkSeed != bytes32(0) && sphincsKeys[i].pkRoot != bytes32(0),
                "SimpleAccountFactory: zero sphincs key"
            );
            require(
                sphincsKeys[i].pkSeed == (sphincsKeys[i].pkSeed & SPHINCS_PK_MASK)
                    && sphincsKeys[i].pkRoot == (sphincsKeys[i].pkRoot & SPHINCS_PK_MASK),
                "SimpleAccountFactory: non-canonical sphincs key"
            );
        }
        keysCommitment = InitialSignerCommitment.sphincsKeysCommitment(sphincsKeys);
        fullSalt = InitialSignerCommitment.accountSalt(initialSignerRoot, keysCommitment, salt);
    }
}
