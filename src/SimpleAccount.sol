// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseAccount} from "account-abstraction/core/BaseAccount.sol";
import {SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "account-abstraction/core/Helpers.sol";
import {Exec} from "account-abstraction/utils/Exec.sol";
import {TokenCallbackHandler} from "account-abstraction/accounts/callback/TokenCallbackHandler.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {InitialSignerCommitment} from "./InitialSignerCommitment.sol";
import {ISignatureVerifier} from "./Interfaces/ISignatureVerifier.sol";
import {FORS_SIG_LEN} from "./Verifiers/ForsVerifier.sol";

/// @title SimpleAccount
/// @notice ERC-4337 smart account using standalone FORS as the primary signer.
///
///         activation signature = [activation header][Merkle proof][FORS_SIG_LEN bytes FORS blob]
///         normal signature     = [FORS_SIG_LEN bytes FORS blob]
///         userOp.callData  = [... any call ...][20 bytes nextOwner]
contract SimpleAccount is BaseAccount, TokenCallbackHandler, Initializable {
    // version(1) + scheme(1) + signerIndex(8) + derivationPathHash(32) + proofLen(2)
    uint256 private constant ACTIVATION_HEADER_LENGTH = 44;
    uint256 private constant MAX_ACTIVATION_PROOF_LENGTH = 64;

    address public owner;
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
        owner = address(this);
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
        owner = address(0);
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
        uint8 schemeId = uint8(bytes1(signature[1]));
        uint64 signerIndex = uint64(bytes8(signature[2:10]));
        bytes32 derivationPathHash = bytes32(signature[10:42]);
        uint16 proofLen = uint16(bytes2(signature[42:44]));

        if (
            version != InitialSignerCommitment.ACTIVATION_SIGNATURE_VERSION
                || schemeId != InitialSignerCommitment.SCHEME_FORS
                || signerIndex != InitialSignerCommitment.INITIAL_SIGNER_INDEX || proofLen > MAX_ACTIVATION_PROOF_LENGTH
        ) {
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

        bytes32 leaf = InitialSignerCommitment.initialSignerLeaf(
            block.chainid, recovered, derivationPathHash, schemeId, signerIndex
        );
        if (!MerkleProof.verify(proof, initialSignerRoot, leaf)) {
            return SIG_VALIDATION_FAILED;
        }

        emit AccountActivated(initialSignerRoot, recovered, nextOwner);
        _rotateOwner(nextOwner);
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
