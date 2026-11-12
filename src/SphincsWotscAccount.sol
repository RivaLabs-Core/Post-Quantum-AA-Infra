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

/// @title SphincsWotscAccount
/// @notice Shared logic for ERC-4337 accounts authenticated SOLELY by one SPHINCS- signature
///         under a WOTS+C verifier (`SphincsVerifier_v5`, `SphincsVerifier_v6`). Each concrete
///         account pins its verifier's blob length through `_sigLen()`, so every parameter set
///         gets its own implementation bytecode, factory and address family.
///
///         `userOp.signature` is the raw blob — no envelope, no type tag, no length dispatch:
///         the account has exactly one signer type.
///         `userOp.callData` is a plain call — no trailing key material.
///
/// @dev    Same model as `SphincsAccount` (kept as a separate contract so the deployed standard
///         family is untouched): the scheme is stateless, so one `(pkSeed, pkRoot)` signs
///         indefinitely, with no rotation, enrollment or per-signer state.
///
///         REPLAY PROTECTION comes entirely from the EntryPoint nonce. `userOpHash` binds the
///         nonce, the sender and the chain id, so a signature is valid for exactly one UserOp on
///         exactly one chain. The account keeps no nonce of its own.
///
///         SIGNATURE BUDGET is per parameter set (see the concrete account). It is a budget, not a
///         hard stop, and is not enforced on-chain: track the count off-chain.
///
///         KEY LOSS IS TERMINAL. There is exactly one key, fixed at `initialize` and bound into
///         the account address via the CREATE2 salt. There is no recovery path and no way to add
///         a second signer.
///
/// @dev    The verifiers are UNAUDITED research code, checked only against vectors from an
///         off-repo signer. Gate any real-funds use on an audit.
abstract contract SphincsWotscAccount is BaseAccount, TokenCallbackHandler, Initializable {
    /// @dev Top-128-bit mask: SPHINCS- public-key words must be canonical (low 128 bits zero).
    ///      `verify` REVERTS on a non-canonical key, so storing one would brick the account
    ///      permanently — rejected at `initialize` instead.
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

    /// @dev The exact signature length the bound verifier accepts.
    function _sigLen() internal pure virtual returns (uint256);

    /// @notice The exact `userOp.signature` length this account accepts.
    function SIG_LEN() external pure returns (uint256) {
        return _sigLen();
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return ENTRY_POINT;
    }

    /// @dev Called once by the factory after clone deployment. The key is bound into the account
    ///      address via the CREATE2 salt (see `SphincsWotscAccountFactory`), so storing it here
    ///      cannot be front-run with a different key at the same address.
    function initialize(bytes32 _pkSeed, bytes32 _pkRoot) public virtual initializer {
        require(_pkSeed != bytes32(0) && _pkRoot != bytes32(0), "SphincsWotscAccount: zero key");
        require(
            _pkSeed == (_pkSeed & PK_MASK) && _pkRoot == (_pkRoot & PK_MASK),
            "SphincsWotscAccount: non-canonical key"
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
        if (userOp.signature.length != _sigLen()) {
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
            require(ok, "SphincsWotscAccount: prefund failed");
        }
    }

    function _requireFromEntryPoint() internal view override {
        require(msg.sender == address(entryPoint()), "SphincsWotscAccount: not from EntryPoint");
    }

    function _requireFromEntryPointOrSelf() internal view {
        require(
            msg.sender == address(entryPoint()) || msg.sender == address(this),
            "SphincsWotscAccount: not from EntryPoint or account"
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
        require(targets.length == values.length && values.length == datas.length, "SphincsWotscAccount: length mismatch");

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
