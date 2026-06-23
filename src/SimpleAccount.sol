// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseAccount} from "account-abstraction/core/BaseAccount.sol";
import {SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "account-abstraction/core/Helpers.sol";
import {Exec} from "account-abstraction/utils/Exec.sol";
import {TokenCallbackHandler} from "account-abstraction/accounts/callback/TokenCallbackHandler.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {MerkleProofLib} from "solady/utils/MerkleProofLib.sol";
import {InitialSignerCommitment} from "./InitialSignerCommitment.sol";
import {ISignatureVerifier} from "./Interfaces/ISignatureVerifier.sol";
import {FORS_SIG_LEN} from "./Verifiers/ForsVerifier.sol";

/// @title SimpleAccount
/// @notice ERC-4337 smart account using standalone FORS as the primary signer.
///
///         activation signature = [activation version][Merkle proof][FORS_SIG_LEN bytes FORS blob]
///         normal signature     = [FORS_SIG_LEN bytes FORS blob]
///         userOp.callData  = [... any call ...][20 bytes nextOwner]
contract SimpleAccount is BaseAccount, TokenCallbackHandler, Initializable {
    // version(1) + proofLen(2)
    uint256 private constant ACTIVATION_HEADER_LENGTH = 3;
    uint256 private constant MAX_ACTIVATION_PROOF_LENGTH = 64;

    uint8 internal constant AUTH_NONE = 0; // never authorized
    uint8 internal constant AUTH_ACTIVE = 1; // authorized, may sign exactly one UserOp
    uint8 internal constant AUTH_BURNED = 2; // already used, never valid again

    /// @notice Per-signer authorization state. Each device runs its own key chain;
    ///         a key is authorized once, signs once, then is burned.
    mapping(address => uint8) public authState;
    /// @notice False until the first signer is activated against initialSignerRoot.
    bool public activated;
    bytes32 public initialSignerRoot;
    IEntryPoint public immutable ENTRY_POINT;
    ISignatureVerifier public immutable VERIFIER;

    event AccountInitialized(
        IEntryPoint indexed entryPoint, bytes32 indexed initialSignerRoot, address indexed verifier
    );
    event AccountActivated(bytes32 indexed initialSignerRoot, address indexed initialOwner, address indexed nextOwner);
    event OwnerRotated(address indexed previousOwner, address indexed newOwner);

    constructor(IEntryPoint _entryPoint, ISignatureVerifier _verifier) {
        ENTRY_POINT = _entryPoint;
        VERIFIER = _verifier;
        _disableInitializers();
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return ENTRY_POINT;
    }

    /// @dev Called once by the factory after clone deployment.
    function initialize(bytes32 _initialSignerRoot) public virtual initializer {
        require(_initialSignerRoot != bytes32(0), "SimpleAccount: zero root");
        initialSignerRoot = _initialSignerRoot;
        emit AccountInitialized(entryPoint(), _initialSignerRoot, address(VERIFIER));
    }

    /// @inheritdoc BaseAccount
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        require(userOp.callData.length >= 24, "SimpleAccount: missing next owner"); // 4 selector + 20

        address nextOwner = address(bytes20(userOp.callData[userOp.callData.length - 20:]));

        if (!activated) {
            return _validateActivationSignature(userOp.signature, userOpHash, nextOwner);
        }

        if (userOp.signature.length != FORS_SIG_LEN) {
            return SIG_VALIDATION_FAILED;
        }

        address recovered = VERIFIER.recover(userOp.signature, userOpHash);

        if (recovered == address(0) || authState[recovered] != AUTH_ACTIVE) {
            return SIG_VALIDATION_FAILED;
        }

        _rotate(recovered, nextOwner);
        return SIG_VALIDATION_SUCCESS;
    }

    function _validateActivationSignature(bytes calldata signature, bytes32 userOpHash, address nextOwner)
        internal
        returns (uint256 validationData)
    {
        if (signature.length < ACTIVATION_HEADER_LENGTH + FORS_SIG_LEN) {
            return SIG_VALIDATION_FAILED;
        }

        uint8 version = uint8(bytes1(signature[0]));
        uint16 proofLen = uint16(bytes2(signature[1:3]));

        if (version != InitialSignerCommitment.ACTIVATION_SIGNATURE_VERSION || proofLen > MAX_ACTIVATION_PROOF_LENGTH) {
            return SIG_VALIDATION_FAILED;
        }

        uint256 proofBytesLen = uint256(proofLen) * 32;
        uint256 proofOffset = ACTIVATION_HEADER_LENGTH;
        uint256 forsOffset = proofOffset + proofBytesLen;
        if (signature.length != forsOffset + FORS_SIG_LEN) {
            return SIG_VALIDATION_FAILED;
        }

        bytes32[] memory proof = new bytes32[](proofLen);
        for (uint256 i = 0; i < proofLen; i++) {
            uint256 offset = proofOffset + i * 32;
            proof[i] = bytes32(signature[offset:offset + 32]);
        }

        bytes calldata forsSignature = signature[forsOffset:];
        address recovered = VERIFIER.recover(forsSignature, userOpHash);
        if (recovered == address(0)) {
            return SIG_VALIDATION_FAILED;
        }

        bytes32 leaf = InitialSignerCommitment.initialSignerLeaf(block.chainid, recovered);
        if (!MerkleProofLib.verify(proof, initialSignerRoot, leaf)) {
            return SIG_VALIDATION_FAILED;
        }

        require(nextOwner != address(0), "SimpleAccount: zero next owner");
        require(authState[nextOwner] == AUTH_NONE, "SimpleAccount: next owner not fresh");

        activated = true;
        authState[nextOwner] = AUTH_ACTIVE;

        emit AccountActivated(initialSignerRoot, recovered, nextOwner);
        emit OwnerRotated(address(0), nextOwner);
        return SIG_VALIDATION_SUCCESS;
    }

    function _payPrefund(uint256 missingAccountFunds) internal virtual override {
        if (missingAccountFunds > 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            require(ok, "SimpleAccount: prefund failed");
        }
    }

    function _requireFromEntryPoint() internal view override {
        require(msg.sender == address(entryPoint()), "SimpleAccount: not from EntryPoint");
    }

    function _requireFromEntryPointOrSelf() internal view {
        require(
            msg.sender == address(entryPoint()) || msg.sender == address(this),
            "SimpleAccount: not from EntryPoint or account"
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

    /// @notice Backward-compatible batch ABI kept for existing callers.
    ///         The upstream BaseAccount batch ABI is executeBatch(Call[]).
    function executeBatch(address[] calldata targets, uint256[] calldata values, bytes[] calldata datas) external {
        _requireForExecute();
        require(targets.length == values.length && values.length == datas.length, "SimpleAccount: length mismatch");

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

    /// @dev Strict rotation: burn the signer that authorized this op and activate the
    ///      appended next key. `next` must be fresh (AUTH_NONE) to prevent re-authorizing
    ///      a burned key or clobbering an already-active one.
    function _rotate(address current, address next) internal {
        require(next != address(0), "SimpleAccount: zero next owner");
        require(authState[next] == AUTH_NONE, "SimpleAccount: next owner not fresh");
        authState[current] = AUTH_BURNED;
        authState[next] = AUTH_ACTIVE;
        emit OwnerRotated(current, next);
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
