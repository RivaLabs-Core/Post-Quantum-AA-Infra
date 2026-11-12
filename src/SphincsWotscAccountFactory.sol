// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SphincsWotscAccount} from "./SphincsWotscAccount.sol";
import {ISphincsVerifier} from "./Interfaces/ISphincsVerifier.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {LibClone} from "solady/utils/LibClone.sol";

/// @title SphincsWotscAccountFactory
/// @notice Shared logic for the factories of `SphincsWotscAccount`s: EIP-1167 minimal proxies over
///         one implementation per parameter set. The account address binds the SPHINCS- public key
///         via the CREATE2 salt, so a deploy race cannot install a different key at the same
///         address: an attacker front-running `createAccount` can only ever produce the address
///         the honest caller already computed, holding the honest caller's key.
/// @dev    Each concrete factory deploys its own account implementation through
///         `_deployImplementation`, so the v5 and v6 families never share an implementation or an
///         address space. Separate from `SphincsAccountFactory`, whose standard family is left
///         untouched.
///
///         The key is chain-independent, so the same (pkSeed, pkRoot, salt) yields the same
///         account address on every chain where this factory is deployed at the same address.
abstract contract SphincsWotscAccountFactory {
    /// @dev Domain-separated salt. Distinct typehash from `SphincsAccountFactory`'s and from
    ///      `InitialSignerCommitment`'s.
    bytes32 internal constant SPHINCS_WOTSC_ACCOUNT_SALT_TYPEHASH =
        keccak256("NiceTrySphincsWotscAccountSalt:v1(bytes32 pkSeed,bytes32 pkRoot,uint256 salt)");

    /// @dev Public-key words must be top-128-bit aligned, as the verifiers require.
    bytes32 private constant PK_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000;

    IEntryPoint public immutable ENTRY_POINT;
    ISphincsVerifier public immutable VERIFIER;
    address public immutable ACCOUNT_IMPL;

    event AccountCreated(address indexed account, bytes32 indexed pkSeed, bytes32 indexed pkRoot, uint256 salt);

    constructor(IEntryPoint _entryPoint, ISphincsVerifier _verifier) {
        ENTRY_POINT = _entryPoint;
        VERIFIER = _verifier;
        ACCOUNT_IMPL = _deployImplementation(_entryPoint, _verifier);
    }

    /// @dev Deploys the parameter set's account implementation.
    function _deployImplementation(IEntryPoint _entryPoint, ISphincsVerifier _verifier)
        internal
        virtual
        returns (address);

    /// @notice The exact `userOp.signature` length accounts from this factory accept.
    function SIG_LEN() external view returns (uint256) {
        return SphincsWotscAccount(payable(ACCOUNT_IMPL)).SIG_LEN();
    }

    /// @notice Deploy (or return, if already deployed) the account for this key. Idempotent, so it
    ///         is safe to use as ERC-4337 `initCode` on a UserOp that may be retried.
    function createAccount(bytes32 pkSeed, bytes32 pkRoot, uint256 salt) external returns (address accountAddr) {
        bytes32 fullSalt = _salt(pkSeed, pkRoot, salt);

        address predicted = LibClone.predictDeterministicAddress(ACCOUNT_IMPL, fullSalt, address(this));
        if (predicted.code.length > 0) return predicted;

        accountAddr = LibClone.cloneDeterministic(ACCOUNT_IMPL, fullSalt);
        SphincsWotscAccount(payable(accountAddr)).initialize(pkSeed, pkRoot);

        emit AccountCreated(accountAddr, pkSeed, pkRoot, salt);
    }

    /// @notice Counterfactual address for a key, computable before deployment.
    function getAddress(bytes32 pkSeed, bytes32 pkRoot, uint256 salt) public view returns (address) {
        return LibClone.predictDeterministicAddress(ACCOUNT_IMPL, _salt(pkSeed, pkRoot, salt), address(this));
    }

    function _salt(bytes32 pkSeed, bytes32 pkRoot, uint256 salt) internal pure returns (bytes32) {
        require(pkSeed != bytes32(0) && pkRoot != bytes32(0), "SphincsWotscAccountFactory: zero key");
        // Reject non-canonical keys here as well as in initialize(), so `getAddress` can never hand
        // back an address for a key that would brick the account on first use.
        require(
            pkSeed == (pkSeed & PK_MASK) && pkRoot == (pkRoot & PK_MASK),
            "SphincsWotscAccountFactory: non-canonical key"
        );
        return keccak256(abi.encode(SPHINCS_WOTSC_ACCOUNT_SALT_TYPEHASH, pkSeed, pkRoot, salt));
    }
}
