// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SphincsAccount} from "./SphincsAccount.sol";
import {ISphincsVerifier} from "./Interfaces/ISphincsVerifier.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {LibClone} from "solady/utils/LibClone.sol";

/// @title SphincsAccountFactory
/// @notice Deploys `SphincsAccount`s — SPHINCS--only ERC-4337 accounts — as EIP-1167 minimal
///         proxies over a single implementation. The account address binds the SPHINCS- public key
///         via the CREATE2 salt, so a deploy race cannot install a different key at the same
///         address: an attacker front-running `createAccount` can only ever produce the address
///         the honest caller already computed, holding the honest caller's key.
/// @dev    Deliberately separate from `SimpleAccountFactory` rather than a modification of it, so
///         the existing FORS-primary address family (factory / impl / accounts) is untouched.
///
///         The key is chain-independent, so the same (pkSeed, pkRoot, salt) yields the same
///         account address on every chain where this factory is deployed at the same address.
contract SphincsAccountFactory {
    /// @dev Domain-separated salt. Distinct typehash from `InitialSignerCommitment`'s so a
    ///      SPHINCS--only account can never collide with a FORS-primary `SimpleAccount` salt.
    bytes32 internal constant SPHINCS_ACCOUNT_SALT_TYPEHASH =
        keccak256("NiceTrySphincsAccountSalt:v1(bytes32 pkSeed,bytes32 pkRoot,uint256 salt)");

    /// @dev Mirrors the verifier's N_MASK: public-key words must be top-128-bit aligned.
    bytes32 private constant PK_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000;

    IEntryPoint public immutable ENTRY_POINT;
    ISphincsVerifier public immutable VERIFIER;
    address public immutable ACCOUNT_IMPL;

    event AccountCreated(address indexed account, bytes32 indexed pkSeed, bytes32 indexed pkRoot, uint256 salt);

    constructor(IEntryPoint _entryPoint, ISphincsVerifier _verifier) {
        ENTRY_POINT = _entryPoint;
        VERIFIER = _verifier;
        ACCOUNT_IMPL = address(new SphincsAccount(_entryPoint, _verifier));
    }

    /// @notice Deploy (or return, if already deployed) the account for this key. Idempotent, so it
    ///         is safe to use as ERC-4337 `initCode` on a UserOp that may be retried.
    function createAccount(bytes32 pkSeed, bytes32 pkRoot, uint256 salt) external returns (address accountAddr) {
        bytes32 fullSalt = _salt(pkSeed, pkRoot, salt);

        address predicted = LibClone.predictDeterministicAddress(ACCOUNT_IMPL, fullSalt, address(this));
        if (predicted.code.length > 0) return predicted;

        accountAddr = LibClone.cloneDeterministic(ACCOUNT_IMPL, fullSalt);
        SphincsAccount(payable(accountAddr)).initialize(pkSeed, pkRoot);

        emit AccountCreated(accountAddr, pkSeed, pkRoot, salt);
    }

    /// @notice Counterfactual address for a key, computable before deployment.
    function getAddress(bytes32 pkSeed, bytes32 pkRoot, uint256 salt) public view returns (address) {
        return LibClone.predictDeterministicAddress(ACCOUNT_IMPL, _salt(pkSeed, pkRoot, salt), address(this));
    }

    function _salt(bytes32 pkSeed, bytes32 pkRoot, uint256 salt) internal pure returns (bytes32) {
        require(pkSeed != bytes32(0) && pkRoot != bytes32(0), "SphincsAccountFactory: zero key");
        // Reject non-canonical keys here as well as in initialize(), so `getAddress` can never hand
        // back an address for a key that would brick the account on first use.
        require(
            pkSeed == (pkSeed & PK_MASK) && pkRoot == (pkRoot & PK_MASK),
            "SphincsAccountFactory: non-canonical key"
        );
        return keccak256(abi.encode(SPHINCS_ACCOUNT_SALT_TYPEHASH, pkSeed, pkRoot, salt));
    }
}
