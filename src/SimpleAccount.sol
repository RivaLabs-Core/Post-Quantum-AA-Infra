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
import {ISphincsVerifier} from "./Interfaces/ISphincsVerifier.sol";
import {SPHINCS_PROFILE_COUNT, SphincsProfile, SphincsPublicKey} from "./SphincsProfiles.sol";
import {FORS_SIG_LEN} from "./Verifiers/ForsVerifier.sol";
import {
    SPHINCS_DEFAULT_MINUS_SIG_LEN,
    SPHINCS_FAST_TRADE_PLUS_SIG_LEN,
    SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_SIG_LEN,
    SPHINCS_PLUS_128S_SIG_LEN
} from "./Verifiers/SphincsParameterSetVerifiers.sol";

/// @title SimpleAccount
/// @notice ERC-4337 smart account using standalone FORS as the primary signer, with four durable,
///         co-equal SPHINCS signers for recovery, trading and cross-chain bootstrap.
///
///         Signatures are dispatched purely by length (no type tag):
///           FORS normal  = [FORS_SIG_LEN bytes FORS blob]                       (owner != 0)
///           activation   = [version(1)][proofLen(2)][Merkle proof][FORS blob]   (owner == 0)
///           SPHINCS      = [one of four profile-specific signature lengths]      (either state)
///         Every signature-length class is kept disjoint (constructor guard).
///         userOp.callData  = [... any call ...][20 bytes nextOwner]
contract SimpleAccount is BaseAccount, TokenCallbackHandler, Initializable {
    // version(1) + proofLen(2)
    uint256 private constant ACTIVATION_HEADER_LENGTH = 3;
    uint256 private constant MAX_ACTIVATION_PROOF_LENGTH = 64;
    // Top-128-bit mask: SPHINCS public-key words must be canonical (low 128 bits zero), matching
    // the verifiers' N_MASK; a non-canonical key would make the selected signature path revert.
    bytes32 private constant SPHINCS_PK_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000;

    address public owner;
    bytes32 public initialSignerRoot;
    // Profile order is fixed by SphincsProfile and is part of the CREATE2 address commitment.
    SphincsPublicKey[SPHINCS_PROFILE_COUNT] private _sphincsKeys;
    IEntryPoint public immutable ENTRY_POINT;
    ISignatureVerifier public immutable VERIFIER;
    ISphincsVerifier public immutable FAST_TRADE_PLUS_VERIFIER;
    ISphincsVerifier public immutable DEFAULT_MINUS_VERIFIER;
    ISphincsVerifier public immutable GAS_SAVER_MINUS_Q18_AGGRESSIVE_VERIFIER;
    ISphincsVerifier public immutable SPHINCS_PLUS_128S_VERIFIER;

    event AccountInitialized(
        IEntryPoint indexed entryPoint, bytes32 indexed initialSignerRoot, address indexed verifier
    );
    event AccountActivated(bytes32 indexed initialSignerRoot, address indexed initialOwner, address indexed nextOwner);
    event OwnerRotated(address indexed previousOwner, address indexed newOwner);
    event SphincsSignerUsed(SphincsProfile indexed profile, address indexed previousOwner, address indexed nextOwner);

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
        owner = address(this);

        require(
            address(_fastTradePlusVerifier) != address(0) && address(_defaultMinusVerifier) != address(0)
                && address(_gasSaverMinusQ18AggressiveVerifier) != address(0)
                && address(_sphincsPlus128sVerifier) != address(0),
            "SimpleAccount: zero sphincs verifier"
        );

        _requireSphincsLengthDisjoint(SPHINCS_FAST_TRADE_PLUS_SIG_LEN);
        _requireSphincsLengthDisjoint(SPHINCS_DEFAULT_MINUS_SIG_LEN);
        _requireSphincsLengthDisjoint(SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_SIG_LEN);
        _requireSphincsLengthDisjoint(SPHINCS_PLUS_128S_SIG_LEN);
        require(
            SPHINCS_FAST_TRADE_PLUS_SIG_LEN != SPHINCS_DEFAULT_MINUS_SIG_LEN
                && SPHINCS_FAST_TRADE_PLUS_SIG_LEN != SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_SIG_LEN
                && SPHINCS_FAST_TRADE_PLUS_SIG_LEN != SPHINCS_PLUS_128S_SIG_LEN
                && SPHINCS_DEFAULT_MINUS_SIG_LEN != SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_SIG_LEN
                && SPHINCS_DEFAULT_MINUS_SIG_LEN != SPHINCS_PLUS_128S_SIG_LEN
                && SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_SIG_LEN != SPHINCS_PLUS_128S_SIG_LEN,
            "SimpleAccount: sphincs len clash"
        );

        _disableInitializers();
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return ENTRY_POINT;
    }

    /// @dev Called once by the factory in the clone-deployment transaction. All four SPHINCS keys
    ///      are bound into the CREATE2 salt, so the initialization cannot be front-run at this address.
    function initialize(bytes32 _initialSignerRoot, SphincsPublicKey[SPHINCS_PROFILE_COUNT] calldata sphincsKeys)
        public
        virtual
        initializer
    {
        require(_initialSignerRoot != bytes32(0), "SimpleAccount: zero root");
        for (uint256 i = 0; i < SPHINCS_PROFILE_COUNT; i++) {
            SphincsPublicKey calldata key = sphincsKeys[i];
            require(key.pkSeed != bytes32(0) && key.pkRoot != bytes32(0), "SimpleAccount: zero sphincs key");
            require(
                key.pkSeed == (key.pkSeed & SPHINCS_PK_MASK) && key.pkRoot == (key.pkRoot & SPHINCS_PK_MASK),
                "SimpleAccount: non-canonical sphincs key"
            );
            _sphincsKeys[i] = key;
        }
        initialSignerRoot = _initialSignerRoot;
        owner = address(0);
        emit AccountInitialized(entryPoint(), _initialSignerRoot, address(VERIFIER));
    }

    function sphincsKey(SphincsProfile profile) external view returns (bytes32 pkSeed, bytes32 pkRoot) {
        SphincsPublicKey storage key = _sphincsKeys[uint256(profile)];
        return (key.pkSeed, key.pkRoot);
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

        // SPHINCS paths are valid in both inactive and active states. The four lengths are unique,
        // so no profile byte is needed in the signature.
        uint256 signatureLength = userOp.signature.length;
        if (signatureLength == SPHINCS_FAST_TRADE_PLUS_SIG_LEN) {
            return _validateSphincsSignature(
                SphincsProfile.FastTradePlus, FAST_TRADE_PLUS_VERIFIER, userOp.signature, userOpHash, nextOwner
            );
        }
        if (signatureLength == SPHINCS_DEFAULT_MINUS_SIG_LEN) {
            return _validateSphincsSignature(
                SphincsProfile.DefaultMinus, DEFAULT_MINUS_VERIFIER, userOp.signature, userOpHash, nextOwner
            );
        }
        if (signatureLength == SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_SIG_LEN) {
            return _validateSphincsSignature(
                SphincsProfile.GasSaverMinusQ18Aggressive,
                GAS_SAVER_MINUS_Q18_AGGRESSIVE_VERIFIER,
                userOp.signature,
                userOpHash,
                nextOwner
            );
        }
        if (signatureLength == SPHINCS_PLUS_128S_SIG_LEN) {
            return _validateSphincsSignature(
                SphincsProfile.SphincsPlus128s, SPHINCS_PLUS_128S_VERIFIER, userOp.signature, userOpHash, nextOwner
            );
        }

        if (owner == address(0)) {
            return _validateActivationSignature(userOp.signature, userOpHash, nextOwner);
        }

        if (userOp.signature.length != FORS_SIG_LEN) {
            return SIG_VALIDATION_FAILED;
        }

        address recovered = VERIFIER.recover(userOp.signature, userOpHash);

        if (recovered == address(0) || recovered != owner) {
            return SIG_VALIDATION_FAILED;
        }

        _rotateOwner(nextOwner);
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

        emit AccountActivated(initialSignerRoot, recovered, nextOwner);
        _rotateOwner(nextOwner);
        return SIG_VALIDATION_SUCCESS;
    }

    function _validateSphincsSignature(
        SphincsProfile profile,
        ISphincsVerifier verifier,
        bytes calldata signature,
        bytes32 userOpHash,
        address nextOwner
    ) internal returns (uint256 validationData) {
        SphincsPublicKey storage key = _sphincsKeys[uint256(profile)];
        if (!verifier.verify(key.pkSeed, key.pkRoot, userOpHash, signature)) {
            return SIG_VALIDATION_FAILED;
        }
        emit SphincsSignerUsed(profile, owner, nextOwner);
        _rotateOwner(nextOwner);
        return SIG_VALIDATION_SUCCESS;
    }

    function _requireSphincsLengthDisjoint(uint256 signatureLength) private pure {
        require(signatureLength != FORS_SIG_LEN, "SimpleAccount: fors/sphincs len clash");
        uint256 minEnvelope = ACTIVATION_HEADER_LENGTH + FORS_SIG_LEN;
        require(
            signatureLength < minEnvelope || (signatureLength - minEnvelope) % 32 != 0
                || (signatureLength - minEnvelope) / 32 > MAX_ACTIVATION_PROOF_LENGTH,
            "SimpleAccount: sphincs len in envelope"
        );
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

    function _rotateOwner(address nextOwner) internal {
        require(nextOwner != address(0), "SimpleAccount: zero next owner");
        address previous = owner;
        owner = nextOwner;
        emit OwnerRotated(previous, nextOwner);
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
