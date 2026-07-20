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
import {FORS_SIG_LEN} from "./Verifiers/ForsVerifier.sol";
import {SPHINCS_SIG_LEN} from "./Verifiers/SphincsVerifier.sol";

/// @title SimpleAccount
/// @notice ERC-4337 smart account using standalone FORS as the primary signer, with a durable,
///         co-equal SPHINCS- backup signer for recovery and cross-chain bootstrap. Multiple devices
///         are supported via per-signer authState; new devices are enrolled with addSigner().
///
///         Signatures are dispatched purely by length (no type tag):
///           FORS normal  = [FORS_SIG_LEN bytes FORS blob]                       (activated)
///           activation   = [version(1)][proofLen(2)][Merkle proof][FORS blob]   (!activated)
///           SPHINCS-     = [SPHINCS_SIG_LEN bytes SPHINCS- blob]                 (either state)
///         The three length classes are kept disjoint (constructor guard).
///         userOp.callData  = [... any call ...][20 bytes nextOwner]                      (FORS / activation)
///                          = [... any call ...][20 bytes currentKey][20 bytes nextOwner] (SPHINCS-)
contract SimpleAccount is BaseAccount, TokenCallbackHandler, Initializable {
    // version(1) + proofLen(2)
    uint256 private constant ACTIVATION_HEADER_LENGTH = 3;
    uint256 private constant MAX_ACTIVATION_PROOF_LENGTH = 64;
    // Top-128-bit mask: SPHINCS- public-key words must be canonical (low 128 bits zero), matching
    // the verifier's N_MASK; a non-canonical key would make verify() revert on every backup op.
    bytes32 private constant BACKUP_PK_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000;

    uint8 internal constant AUTH_NONE = 0; // never authorized
    uint8 internal constant AUTH_ACTIVE = 1; // authorized, may sign exactly one UserOp
    uint8 internal constant AUTH_BURNED = 2; // already used, never valid again

    /// @notice Per-signer authorization state. Each device runs its own key chain;
    ///         a key is authorized once, signs once, then is burned.
    mapping(address => uint8) public authState;
    /// @notice False until the first signer is activated against initialSignerRoot.
    bool public activated;
    bytes32 public initialSignerRoot;
    // Durable SPHINCS- backup public key (chain-independent), committed into the account address via
    // the CREATE2 salt and stored at initialize(). The key itself is never rotated.
    bytes32 public backupPkSeed;
    bytes32 public backupPkRoot;
    IEntryPoint public immutable ENTRY_POINT;
    ISignatureVerifier public immutable VERIFIER;
    ISphincsVerifier public immutable SPHINCS_VERIFIER;

    event AccountInitialized(
        IEntryPoint indexed entryPoint, bytes32 indexed initialSignerRoot, address indexed verifier
    );
    event AccountActivated(bytes32 indexed initialSignerRoot, address indexed initialOwner, address indexed nextOwner);
    event OwnerRotated(address indexed previousOwner, address indexed newOwner);
    /// @notice Emitted when a SPHINCS- backup signature authorizes an op (recovery, bootstrap, or co-equal use).
    event BackupSignerUsed(bytes32 indexed userOpHash);
    /// @notice Emitted when a new signer (device) is authorized via addSigner().
    event SignerAdded(address indexed signer);

    constructor(IEntryPoint _entryPoint, ISignatureVerifier _verifier, ISphincsVerifier _sphincsVerifier) {
        ENTRY_POINT = _entryPoint;
        VERIFIER = _verifier;
        SPHINCS_VERIFIER = _sphincsVerifier;

        // Length-dispatch disjointness invariant (see _validateSignature): the FORS, SPHINCS-, and
        // activation-envelope length classes must never collide, else a signature could be routed to
        // the wrong verifier. Checked once, at implementation-contract deploy time.
        require(SPHINCS_SIG_LEN != FORS_SIG_LEN, "SimpleAccount: fors/sphincs len clash");
        uint256 minEnvelope = ACTIVATION_HEADER_LENGTH + FORS_SIG_LEN;
        require(
            SPHINCS_SIG_LEN < minEnvelope || (SPHINCS_SIG_LEN - minEnvelope) % 32 != 0
                || (SPHINCS_SIG_LEN - minEnvelope) / 32 > MAX_ACTIVATION_PROOF_LENGTH,
            "SimpleAccount: sphincs len in envelope"
        );

        _disableInitializers();
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return ENTRY_POINT;
    }

    /// @dev Called once by the factory after clone deployment. The backup key is bound into the
    ///      account address via the CREATE2 salt (see SimpleAccountFactory + InitialSignerCommitment),
    ///      so storing it here cannot be front-run with a different key at the same address.
    function initialize(bytes32 _initialSignerRoot, bytes32 _backupPkSeed, bytes32 _backupPkRoot)
        public
        virtual
        initializer
    {
        require(_initialSignerRoot != bytes32(0), "SimpleAccount: zero root");
        require(_backupPkSeed != bytes32(0) && _backupPkRoot != bytes32(0), "SimpleAccount: zero backup key");
        // Reject non-canonical backup keys up front (low 128 bits must be zero) so verify() — which
        // reverts on non-canonical pubkeys — can never brick the backup path.
        require(
            _backupPkSeed == (_backupPkSeed & BACKUP_PK_MASK) && _backupPkRoot == (_backupPkRoot & BACKUP_PK_MASK),
            "SimpleAccount: non-canonical backup key"
        );
        initialSignerRoot = _initialSignerRoot;
        backupPkSeed = _backupPkSeed;
        backupPkRoot = _backupPkRoot;
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

        // SPHINCS- backup path: routed purely by length, verified against the committed backup key,
        // valid in BOTH the inactive (cross-chain bootstrap) and active (recovery) states. It rotates
        // the FORS owner exactly like a FORS op — its callData carries [currentKey][nextOwner] — so a
        // backup signature re-seeds the rotating chain (burns currentKey, activates nextOwner).
        if (userOp.signature.length == SPHINCS_SIG_LEN) {
            return _validateSphincsSignature(userOp.signature, userOpHash, userOp.callData, nextOwner);
        }

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

    /// @dev SPHINCS- backup verification (co-equal, durable). A valid signature over `userOpHash`
    ///      against the committed backup key authorizes the op and rotates the FORS owner exactly like
    ///      a FORS op: the callData tail carries [currentKey][nextOwner], and _rotate burns currentKey
    ///      (even though it never signed) and activates nextOwner — re-seeding the chain for recovery.
    ///      The backup key itself is never rotated. Also flips `activated` so a pre-activation SPHINCS-
    ///      op can bootstrap the account on chains absent from the Merkle tree. Length is guaranteed
    ///      == SPHINCS_SIG_LEN and the stored key is canonical, so verify() returns a bool, never reverts.
    function _validateSphincsSignature(
        bytes calldata signature,
        bytes32 userOpHash,
        bytes calldata callData,
        address nextOwner
    ) internal returns (uint256 validationData) {
        require(callData.length >= 44, "SimpleAccount: missing rotation keys"); // 4 selector + 20 current + 20 next
        address currentKey = address(bytes20(callData[callData.length - 40:callData.length - 20]));

        if (!SPHINCS_VERIFIER.verify(backupPkSeed, backupPkRoot, userOpHash, signature)) {
            return SIG_VALIDATION_FAILED;
        }

        emit BackupSignerUsed(userOpHash);
        if (!activated) activated = true;
        _rotate(currentKey, nextOwner);
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

    /// @notice Authorize a new signer (device). Reachable by any validated UserOp (FORS or SPHINCS-)
    ///         through its callData; guarded to EntryPoint/self. Enrollment only adds (NONE -> ACTIVE):
    ///         it never burns and never rotates an existing chain. Flips `activated` so a pre-activation
    ///         SPHINCS- bootstrap leaves the account usable on chains absent from the activation tree.
    function addSigner(address newSigner) external {
        _requireFromEntryPointOrSelf();
        require(newSigner != address(0), "SimpleAccount: zero signer");
        require(authState[newSigner] == AUTH_NONE, "SimpleAccount: signer not fresh");
        authState[newSigner] = AUTH_ACTIVE;
        if (!activated) activated = true;
        emit SignerAdded(newSigner);
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
