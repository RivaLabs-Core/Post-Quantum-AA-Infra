// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseAccount} from "account-abstraction/core/BaseAccount.sol";
import {SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "account-abstraction/core/Helpers.sol";
import {Exec} from "account-abstraction/utils/Exec.sol";
import {TokenCallbackHandler} from "account-abstraction/accounts/callback/TokenCallbackHandler.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {ISphincsVerifier} from "./Interfaces/ISphincsVerifier.sol";
import {SPHINCS_STANDARD_SIG_LEN} from "./Verifiers/SphincsStandardVerifier.sol";

/// @title SphincsAccount
/// @notice ERC-4337 smart account authenticated SOLELY by a standard SPHINCS- signature
///         (`SphincsStandardVerifier`, n=16 h=20 d=4 a=7 k=29 w=4 l=68, 8,400-byte blob).
///
///         `userOp.signature` is the raw blob — no envelope, no type tag, no length dispatch:
///         this account has exactly one signer type.
///         `userOp.callData` is a plain call — no trailing key material.
///
/// @dev    WHY THIS IS SO MUCH SIMPLER THAN `SimpleAccount`. That account's `authState` /
///         `activated` / `initialSignerRoot` / Merkle-activation machinery, and its
///         `[currentKey][nextOwner]` callData tail, all exist because FORS is a FEW-TIME scheme
///         whose key must be burned and rotated on every use. SPHINCS- is stateless: one
///         `(pkSeed, pkRoot)` signs indefinitely, so none of that applies here. There is no
///         rotation, no enrollment, and no per-signer state at all.
///
///         REPLAY PROTECTION comes entirely from the EntryPoint nonce. `userOpHash` binds the
///         nonce, the sender and the chain id, so a signature is valid for exactly one UserOp on
///         exactly one chain. The account keeps no nonce of its own.
///
///         SIGNATURE BUDGET. h=20 gives 2^20 FORS instances, selected per-message. Stateless
///         SPHINCS- security degrades as instances are reused: forgery probability per attempt is
///         about (gamma/2^a)^k = (gamma/128)^29 for an instance used gamma times, which holds a
///         ~128-bit margin while gamma <= 6. Balls-in-bins puts the expected maximum load near
///         that at ~2^20 signatures, so treat ~10^6 signatures per key as the budget and track the
///         count off-chain. This is a budget, not a hard stop, and not enforced on-chain.
///
///         COST. Verification is ~268K gas and the signature is 8,400 calldata bytes (~134K gas at
///         16/byte), so budget roughly 400K gas per UserOp before the call itself. Set
///         `verificationGasLimit` accordingly and confirm the bundler accepts a signature field
///         this large.
///
///         KEY LOSS IS TERMINAL. There is exactly one key, fixed at `initialize` and bound into
///         the account address via the CREATE2 salt. There is no recovery path and no way to add
///         a second signer.
///
/// @dev    The verifier is UNAUDITED research code and, as of this writing, has never verified a
///         real signature (no reference vector exists). Gate any real-funds use on both an audit
///         and end-to-end vectors.
contract SphincsAccount is BaseAccount, TokenCallbackHandler, Initializable {
    /// @dev Top-128-bit mask: SPHINCS- public-key words must be canonical (low 128 bits zero),
    ///      matching the verifier's N_MASK. `verify` REVERTS on a non-canonical key, so storing
    ///      one would brick the account permanently — rejected at `initialize` instead.
    bytes32 private constant PK_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000;

    /// @notice The account's SPHINCS- public key. Immutable in practice: set once at initialize,
    ///         committed to by the account address, and never rotated.
    bytes32 public pkSeed;
    bytes32 public pkRoot;

    IEntryPoint public immutable ENTRY_POINT;
    ISphincsVerifier public immutable VERIFIER;

    event AccountInitialized(IEntryPoint indexed entryPoint, address indexed verifier, bytes32 pkSeed, bytes32 pkRoot);

    constructor(IEntryPoint _entryPoint, ISphincsVerifier _verifier) {
        ENTRY_POINT = _entryPoint;
        VERIFIER = _verifier;
        _disableInitializers();
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return ENTRY_POINT;
    }

    /// @dev Called once by the factory after clone deployment. The key is bound into the account
    ///      address via the CREATE2 salt (see `SphincsAccountFactory`), so storing it here cannot
    ///      be front-run with a different key at the same address.
    function initialize(bytes32 _pkSeed, bytes32 _pkRoot) public virtual initializer {
        require(_pkSeed != bytes32(0) && _pkRoot != bytes32(0), "SphincsAccount: zero key");
        require(
            _pkSeed == (_pkSeed & PK_MASK) && _pkRoot == (_pkRoot & PK_MASK),
            "SphincsAccount: non-canonical key"
        );
        pkSeed = _pkSeed;
        pkRoot = _pkRoot;
        emit AccountInitialized(entryPoint(), address(VERIFIER), _pkSeed, _pkRoot);
    }

    /// @inheritdoc BaseAccount
    /// @dev A wrong-length signature returns SIG_VALIDATION_FAILED rather than reverting: the
    ///      verifier reverts on a bad length, and a revert inside validation is a bundler-level
    ///      rejection instead of the clean signature failure ERC-4337 expects. The stored key is
    ///      guaranteed canonical by `initialize`, so past this length check `verify` can only
    ///      return a bool.
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        virtual
        override
        returns (uint256 validationData)
    {
        if (userOp.signature.length != SPHINCS_STANDARD_SIG_LEN) {
            return SIG_VALIDATION_FAILED;
        }
        if (!VERIFIER.verify(pkSeed, pkRoot, userOpHash, userOp.signature)) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }

    function _payPrefund(uint256 missingAccountFunds) internal virtual override {
        if (missingAccountFunds > 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            require(ok, "SphincsAccount: prefund failed");
        }
    }

    function _requireFromEntryPoint() internal view override {
        require(msg.sender == address(entryPoint()), "SphincsAccount: not from EntryPoint");
    }

    function _requireFromEntryPointOrSelf() internal view {
        require(
            msg.sender == address(entryPoint()) || msg.sender == address(this),
            "SphincsAccount: not from EntryPoint or account"
        );
    }

    /// @inheritdoc BaseAccount
    function execute(address target, uint256 value, bytes calldata data) external override {
        _requireForExecute();

        bool ok = Exec.call(target, value, data, gasleft());
        if (!ok) {
            Exec.revertWithReturnData();
        }
    }

    /// @notice Backward-compatible batch ABI, matching `SimpleAccount`.
    ///         The upstream BaseAccount batch ABI is executeBatch(Call[]).
    function executeBatch(address[] calldata targets, uint256[] calldata values, bytes[] calldata datas) external {
        _requireForExecute();
        require(targets.length == values.length && values.length == datas.length, "SphincsAccount: length mismatch");

        for (uint256 i = 0; i < targets.length; i++) {
            bool ok = Exec.call(targets[i], values[i], datas[i], gasleft());
            if (!ok) {
                if (targets.length == 1) {
                    Exec.revertWithReturnData();
                } else {
                    revert ExecuteError(i, Exec.getReturnData(0));
                }
            }
        }
    }

    /// @notice Check this account's deposit in the EntryPoint.
    function getDeposit() public view virtual returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /// @notice Deposit more funds for this account in the EntryPoint.
    function addDeposit() public payable {
        _requireFromEntryPointOrSelf();
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    /// @notice Withdraw funds from this account's EntryPoint deposit.
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public virtual {
        _requireFromEntryPointOrSelf();
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    receive() external payable {}
}
