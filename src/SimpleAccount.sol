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
import {ISphincsParamVerifier} from "./Interfaces/ISphincsParamVerifier.sol";
import {SphincsParamsLib} from "./Verifiers/SphincsParamsLib.sol";
import {FORS_SIG_LEN} from "./Verifiers/ForsVerifier.sol";

/// @title SimpleAccount
/// @notice ERC-4337 smart account using standalone FORS as the primary signer, with any number of
///         durable, co-equal SPHINCS- backup signers for recovery and cross-chain bootstrap — each
///         registered with its OWN parameter set (so one account can hold both a "lightweight"
///         low-budget SPHINCS- key and a "heavy" one). Multiple devices are supported via
///         per-signer authState; new devices are enrolled with addSigner().
///
///         Signature routing:
///           SPHINCS-     = [pkSeed(32)][pkRoot(32)][blob]   -> registered-key lookup (either state)
///           activation   = [version(1)][proofLen(2)][Merkle proof][FORS blob]   (!activated)
///           FORS normal  = [FORS_SIG_LEN bytes FORS blob]                       (activated)
///         The SPHINCS- route is claimed by the 64-byte public-key head: if it maps to a registered
///         signer the op commits to that route (a wrong-length blob then FAILS, never falls
///         through). Registration keeps every registered envelope length disjoint from the FORS
///         and activation length classes, so neither of those can be shadowed.
///         userOp.callData  = [... any call ...][20 bytes nextOwner]                      (FORS / activation)
///                          = [... any call ...][20 bytes currentKey][20 bytes nextOwner] (SPHINCS-)
contract SimpleAccount is BaseAccount, TokenCallbackHandler, Initializable {
    // version(1) + proofLen(2)
    uint256 private constant ACTIVATION_HEADER_LENGTH = 3;
    uint256 private constant MAX_ACTIVATION_PROOF_LENGTH = 64;
    // SPHINCS- envelope prefix: [pkSeed(32)][pkRoot(32)] ahead of the parameter-dependent blob.
    uint256 private constant SPHINCS_PK_HEADER_LENGTH = 64;
    // Top-128-bit mask: SPHINCS- public-key words must be canonical (low 128 bits zero), matching
    // the verifier's N_MASK; a non-canonical key would make verify() revert on every backup op.
    bytes32 private constant SPHINCS_PK_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000;

    uint8 internal constant AUTH_NONE = 0; // never authorized
    uint8 internal constant AUTH_ACTIVE = 1; // authorized, may sign exactly one UserOp
    uint8 internal constant AUTH_BURNED = 2; // already used, never valid again

    /// @notice Per-signer authorization state. Each device runs its own key chain;
    ///         a key is authorized once, signs once, then is burned.
    mapping(address => uint8) public authState;
    /// @notice Registered SPHINCS- backup signers: id (see sphincsSignerId) => parameter set.
    ///         An all-zero slot (d == 0) means the key is NOT authorized. The params occupy only
    ///         8 of the slot's 32 bytes — the spare bytes could later hold a per-signer use
    ///         counter / max-uses budget to enforce reuse limits on-chain (see docs, Future work).
    mapping(address => SphincsParamsLib.Params) public sphincsSigners;
    /// @notice False until the first signer is activated against initialSignerRoot.
    bool public activated;
    bytes32 public initialSignerRoot;
    IEntryPoint public immutable ENTRY_POINT;
    ISignatureVerifier public immutable VERIFIER;
    ISphincsParamVerifier public immutable SPHINCS_PARAM_VERIFIER;

    event AccountInitialized(
        IEntryPoint indexed entryPoint, bytes32 indexed initialSignerRoot, address indexed verifier
    );
    event AccountActivated(bytes32 indexed initialSignerRoot, address indexed initialOwner, address indexed nextOwner);
    event OwnerRotated(address indexed previousOwner, address indexed newOwner);
    /// @notice Emitted when a SPHINCS- backup signature authorizes an op (recovery, bootstrap, or co-equal use).
    event SphincsSignerUsed(bytes32 indexed userOpHash, address indexed id);
    /// @notice Emitted when a new signer (device) is authorized via addSigner().
    event SignerAdded(address indexed signer);
    /// @notice Emitted when a SPHINCS- backup signer is registered (initialize or addSphincsSigner).
    event SphincsSignerAdded(address indexed id, bytes32 pkSeed, bytes32 pkRoot, uint256 packedParams);
    /// @notice Emitted when a SPHINCS- backup signer is removed (its params slot zeroed).
    event SphincsSignerRemoved(address indexed id);

    constructor(IEntryPoint _entryPoint, ISignatureVerifier _verifier, ISphincsParamVerifier _sphincsParamVerifier) {
        ENTRY_POINT = _entryPoint;
        VERIFIER = _verifier;
        SPHINCS_PARAM_VERIFIER = _sphincsParamVerifier;

        // Length-dispatch disjointness: SPHINCS- envelope lengths are per-signer (parameter-
        // dependent), so the invariant that they never collide with the FORS length or the
        // activation-envelope length class is enforced at REGISTRATION time in
        // _registerSphincsSigner, not here.
        _disableInitializers();
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return ENTRY_POINT;
    }

    /// @dev Called once by the factory after clone deployment. The initial backup key is bound
    ///      into the account address via the CREATE2 salt (see SimpleAccountFactory +
    ///      InitialSignerCommitment), so registering it here cannot be front-run with a different
    ///      key at the same address. It is enrolled with the CANONICAL parameter set; further
    ///      SPHINCS- signers (any valid parameter set) are enrolled post-deploy via addSphincsSigner.
    function initialize(bytes32 _initialSignerRoot, bytes32 _backupPkSeed, bytes32 _backupPkRoot)
        public
        virtual
        initializer
    {
        require(_initialSignerRoot != bytes32(0), "SimpleAccount: zero root");
        initialSignerRoot = _initialSignerRoot;
        _registerSphincsSigner(_backupPkSeed, _backupPkRoot, SphincsParamsLib.canonical());
        emit AccountInitialized(entryPoint(), _initialSignerRoot, address(VERIFIER));
    }

    /// @notice Deterministic id of a SPHINCS- signer: the CREATE2-commitment leaf hash of its
    ///         public key, truncated to an address. Truncation to 160 bits is safe here —
    ///         registration is self-authorized, so a collision is at worst a self-inflicted DoS.
    function sphincsSignerId(bytes32 pkSeed, bytes32 pkRoot) public pure returns (address) {
        return address(uint160(uint256(InitialSignerCommitment.backupSignerLeaf(pkSeed, pkRoot))));
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
        bytes calldata signature = userOp.signature;

        // SPHINCS- route (valid in BOTH states: cross-chain bootstrap pre-activation, recovery /
        // co-equal use post-activation): the envelope head [pkSeed(32)][pkRoot(32)] selects a
        // registered signer; its stored params determine the exact expected blob length. An exact
        // FORS-length signature skips the lookup entirely — registration guarantees no registered
        // envelope has that length, so the FORS hot path pays nothing here. A non-registered head
        // (e.g. an activation envelope's first 64 bytes) misses the mapping and falls through.
        if (signature.length > SPHINCS_PK_HEADER_LENGTH && signature.length != FORS_SIG_LEN) {
            bytes32 pkSeed = bytes32(signature[0:32]);
            bytes32 pkRoot = bytes32(signature[32:64]);
            SphincsParamsLib.Params memory params = sphincsSigners[sphincsSignerId(pkSeed, pkRoot)];
            if (params.d != 0) {
                // Registered head => committed to the SPHINCS- route: a wrong-length blob is a
                // failed signature, never a fall-through to the FORS/activation paths.
                if (signature.length != SPHINCS_PK_HEADER_LENGTH + SphincsParamsLib.blobLen(params)) {
                    return SIG_VALIDATION_FAILED;
                }
                return _validateSphincsSignature(pkSeed, pkRoot, params, signature, userOpHash, userOp.callData, nextOwner);
            }
        }

        if (!activated) {
            return _validateActivationSignature(signature, userOpHash, nextOwner);
        }

        if (signature.length != FORS_SIG_LEN) {
            return SIG_VALIDATION_FAILED;
        }

        address recovered = VERIFIER.recover(signature, userOpHash);

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
    ///      against a REGISTERED key authorizes the op and rotates the FORS owner exactly like a
    ///      FORS op: the callData tail carries [currentKey][nextOwner], and _rotate burns
    ///      currentKey (even though it never signed) and activates nextOwner — re-seeding the
    ///      chain for recovery. The backup keys themselves are never rotated by use. Also flips
    ///      `activated` so a pre-activation SPHINCS- op can bootstrap the account on chains absent
    ///      from the Merkle tree. Registration invariants (canonical key, validated params, exact
    ///      envelope length checked by the dispatcher) guarantee verify() returns a bool and
    ///      never reverts here.
    function _validateSphincsSignature(
        bytes32 pkSeed,
        bytes32 pkRoot,
        SphincsParamsLib.Params memory params,
        bytes calldata signature,
        bytes32 userOpHash,
        bytes calldata callData,
        address nextOwner
    ) internal returns (uint256 validationData) {
        require(callData.length >= 44, "SimpleAccount: missing rotation keys"); // 4 selector + 20 current + 20 next
        address currentKey = address(bytes20(callData[callData.length - 40:callData.length - 20]));

        if (
            !SPHINCS_PARAM_VERIFIER.verify(
                pkSeed,
                pkRoot,
                userOpHash,
                SphincsParamsLib.pack(params),
                signature[SPHINCS_PK_HEADER_LENGTH:]
            )
        ) {
            return SIG_VALIDATION_FAILED;
        }

        emit SphincsSignerUsed(userOpHash, sphincsSignerId(pkSeed, pkRoot));
        if (!activated) activated = true;
        _rotate(currentKey, nextOwner);
        return SIG_VALIDATION_SUCCESS;
    }

    /// @notice Register an additional SPHINCS- backup signer with its own parameter set.
    ///         Reachable by any validated UserOp (FORS or SPHINCS-) through its callData; guarded
    ///         to EntryPoint/self. Unlike the initialize-time key, post-deploy signers are NOT
    ///         committed into the account address. Does not flip `activated`: the new signer must
    ///         still produce a valid op (or addSigner must run) before the account is live.
    function addSphincsSigner(bytes32 pkSeed, bytes32 pkRoot, SphincsParamsLib.Params calldata params) external {
        _requireFromEntryPointOrSelf();
        _registerSphincsSigner(pkSeed, pkRoot, params);
    }

    /// @notice Remove a registered SPHINCS- backup signer (zero its params slot). Removing the
    ///         last one is allowed — the rotating FORS chain remains the primary authority.
    function removeSphincsSigner(address id) external {
        _requireFromEntryPointOrSelf();
        require(sphincsSigners[id].d != 0, "SimpleAccount: unknown sphincs signer");
        delete sphincsSigners[id];
        emit SphincsSignerRemoved(id);
    }

    /// @dev Shared registration path (initialize + addSphincsSigner). Enforces: canonical
    ///      non-zero key words, an executable parameter set, no silent re-registration, and the
    ///      length-disjointness invariant — a registered envelope length must never equal the
    ///      FORS length or land in the activation-envelope length class, else a SPHINCS- op could
    ///      shadow (or be shadowed by) another route. The activation-class check is provably
    ///      unreachable (envelope ≡ 0 mod 4, activation lengths ≡ 3 mod 4 — see
    ///      SphincsParamsLib.t.sol) and kept belt-and-braces.
    function _registerSphincsSigner(bytes32 pkSeed, bytes32 pkRoot, SphincsParamsLib.Params memory params) internal {
        require(pkSeed != bytes32(0) && pkRoot != bytes32(0), "SimpleAccount: zero sphincs key");
        // Reject non-canonical keys up front (low 128 bits must be zero) so verify() — which
        // reverts on non-canonical pubkeys — can never brick a backup path.
        require(
            pkSeed == (pkSeed & SPHINCS_PK_MASK) && pkRoot == (pkRoot & SPHINCS_PK_MASK),
            "SimpleAccount: non-canonical sphincs key"
        );
        SphincsParamsLib.validate(params);

        uint256 envelopeLen = SPHINCS_PK_HEADER_LENGTH + SphincsParamsLib.blobLen(params);
        require(envelopeLen != FORS_SIG_LEN, "SimpleAccount: sphincs len is fors len");
        uint256 minActivation = ACTIVATION_HEADER_LENGTH + FORS_SIG_LEN;
        require(
            envelopeLen < minActivation || (envelopeLen - minActivation) % 32 != 0
                || (envelopeLen - minActivation) / 32 > MAX_ACTIVATION_PROOF_LENGTH,
            "SimpleAccount: sphincs len in envelope"
        );

        address id = sphincsSignerId(pkSeed, pkRoot);
        require(sphincsSigners[id].d == 0, "SimpleAccount: sphincs signer exists");
        sphincsSigners[id] = params;
        emit SphincsSignerAdded(id, pkSeed, pkRoot, SphincsParamsLib.pack(params));
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
