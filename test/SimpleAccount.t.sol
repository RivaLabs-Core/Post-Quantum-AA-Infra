// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/SimpleAccount.sol";
import "../src/SimpleAccountFactory.sol";
import {ISignatureVerifier} from "../src/Interfaces/ISignatureVerifier.sol";
import {ISphincsParamVerifier} from "../src/Interfaces/ISphincsParamVerifier.sol";
import {SphincsParamsLib} from "../src/Verifiers/SphincsParamsLib.sol";
import {FORS_SIG_LEN} from "../src/Verifiers/ForsVerifier.sol";
import {SPHINCS_SIG_LEN} from "../src/Verifiers/SphincsVerifier.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

/// @dev Mock verifier - test pre-sets the address recover() should return.
contract MockSignatureVerifier is ISignatureVerifier {
    address public _recovered;

    function setRecovered(address a) external {
        _recovered = a;
    }

    function recover(bytes calldata, bytes32) external view returns (address) {
        return _recovered;
    }
}

/// @dev Mock parametric SPHINCS- verifier - test pre-sets the bool verify() should return.
///      With expect(...) armed it additionally returns true ONLY when the account passed exactly
///      the expected (pkSeed, pkRoot, packedParams, blob length) — proving envelope slicing and
///      per-signer param plumbing.
contract MockSphincsParamVerifier is ISphincsParamVerifier {
    bool public _valid;
    bool internal _checkArgs;
    bytes32 internal _expSeed;
    bytes32 internal _expRoot;
    uint256 internal _expPacked;
    uint256 internal _expBlobLen;

    function setValid(bool v) external {
        _valid = v;
        _checkArgs = false;
    }

    function expect(bytes32 pkSeed, bytes32 pkRoot, uint256 packedParams, uint256 blobLen) external {
        _valid = true;
        _checkArgs = true;
        _expSeed = pkSeed;
        _expRoot = pkRoot;
        _expPacked = packedParams;
        _expBlobLen = blobLen;
    }

    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32, uint256 packedParams, bytes calldata sig)
        external
        view
        returns (bool)
    {
        if (_checkArgs) {
            if (pkSeed != _expSeed || pkRoot != _expRoot || packedParams != _expPacked || sig.length != _expBlobLen) {
                return false;
            }
        }
        return _valid;
    }
}

contract SimpleAccountTest is Test {
    bytes32 internal constant INITIAL_SIGNER_LEAF_TYPEHASH =
        keccak256("NiceTryInitialSignerLeaf:v1(uint256 chainId,address signer)");
    uint8 internal constant ACTIVATION_SIGNATURE_VERSION = 1;
    uint256 internal constant ACTIVATION_TREE_LEAF_COUNT = 256;
    uint256 internal constant ACTIVATION_TREE_DEPTH = 8;

    // Canonical (top-128-bit-aligned, low 128 bits zero) SPHINCS- backup public keys for tests.
    bytes32 internal constant BACKUP_PK_SEED = bytes32(uint256(0xB1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1) << 128);
    bytes32 internal constant BACKUP_PK_ROOT = bytes32(uint256(0xB2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2) << 128);
    // A second, post-deploy-enrolled SPHINCS- key (the "lightweight" signer in these tests).
    bytes32 internal constant PK_SEED_2 = bytes32(uint256(0xC1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1) << 128);
    bytes32 internal constant PK_ROOT_2 = bytes32(uint256(0xC2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2) << 128);

    SimpleAccountFactory factory;
    SimpleAccount account;
    MockSignatureVerifier verifier;
    MockSphincsParamVerifier sphincsVerifier;
    IEntryPoint entryPoint;

    address initialOwner = makeAddr("initialForsOwner");
    address owner0 = makeAddr("forsOwner0");
    address owner1 = makeAddr("forsOwner1");
    address owner2 = makeAddr("forsOwner2");

    address recipient = makeAddr("recipient");

    bytes32 initialLeaf;
    bytes32 initialSignerRoot;
    bytes32[] activationProof;

    address constant ENTRYPOINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    function setUp() public {
        entryPoint = IEntryPoint(ENTRYPOINT);
        vm.etch(ENTRYPOINT, hex"00");

        initialLeaf = _leaf(block.chainid, initialOwner);
        (initialSignerRoot, activationProof) = _buildActivationTree();

        verifier = new MockSignatureVerifier();
        sphincsVerifier = new MockSphincsParamVerifier();
        factory = new SimpleAccountFactory(entryPoint, verifier, sphincsVerifier);

        address accountAddr = factory.createAccount(initialSignerRoot, BACKUP_PK_SEED, BACKUP_PK_ROOT, 0);
        account = SimpleAccount(payable(accountAddr));

        vm.deal(address(account), 100 ether);
    }

    /// @dev The "lightweight" second parameter set used across the multi-signer tests
    ///      (blob 3060 bytes, envelope 3124 — disjoint from every reserved length class).
    function _lightParams() internal pure returns (SphincsParamsLib.Params memory) {
        return SphincsParamsLib.Params({h: 8, d: 1, k: 10, a: 12, logW: 4, l: 64, targetSum: 480});
    }

    // =========================================================================
    // Factory / init
    // =========================================================================

    function test_factoryDeploysInactiveAccount() public view {
        assertFalse(account.activated());
        assertEq(account.initialSignerRoot(), initialSignerRoot);
        assertEq(address(account.ENTRY_POINT()), ENTRYPOINT);
        assertEq(address(account.VERIFIER()), address(verifier));
        assertEq(address(account.SPHINCS_PARAM_VERIFIER()), address(sphincsVerifier));
        // The CREATE2-committed backup key is registered with the canonical parameter set.
        _assertRegisteredParams(
            account.sphincsSignerId(BACKUP_PK_SEED, BACKUP_PK_ROOT), SphincsParamsLib.canonical()
        );
    }

    function test_cannotReinitialize() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        account.initialize(bytes32(uint256(1)), BACKUP_PK_SEED, BACKUP_PK_ROOT);
    }

    function test_factoryRejectsZeroRoot() public {
        vm.expectRevert("SimpleAccountFactory: zero root");
        factory.createAccount(bytes32(0), BACKUP_PK_SEED, BACKUP_PK_ROOT, 1);
    }

    function test_factoryGetAddressRejectsZeroRoot() public {
        vm.expectRevert("SimpleAccountFactory: zero root");
        factory.getAddress(bytes32(0), BACKUP_PK_SEED, BACKUP_PK_ROOT, 1);
    }

    function test_factoryDifferentSaltGivesDifferentAddress() public view {
        address addr0 = factory.getAddress(initialSignerRoot, BACKUP_PK_SEED, BACKUP_PK_ROOT, 0);
        address addr1 = factory.getAddress(initialSignerRoot, BACKUP_PK_SEED, BACKUP_PK_ROOT, 1);
        assertTrue(addr0 != addr1);
    }

    function test_factoryDifferentRootGivesDifferentAddress() public {
        bytes32 otherRoot = _leaf(block.chainid, makeAddr("otherInitialOwner"));
        address addr0 = factory.getAddress(initialSignerRoot, BACKUP_PK_SEED, BACKUP_PK_ROOT, 0);
        address addr1 = factory.getAddress(otherRoot, BACKUP_PK_SEED, BACKUP_PK_ROOT, 0);
        assertTrue(addr0 != addr1);
    }

    function test_factoryReturnsSameAddressIfAlreadyDeployed() public {
        address first = factory.createAccount(initialSignerRoot, BACKUP_PK_SEED, BACKUP_PK_ROOT, 0);
        address second = factory.createAccount(initialSignerRoot, BACKUP_PK_SEED, BACKUP_PK_ROOT, 0);
        assertEq(first, second);
    }

    // =========================================================================
    // Activation
    // =========================================================================

    function test_validActivation_rotatesOwner() public {
        verifier.setRecovered(initialOwner);
        bytes memory callData = _execCalldata(recipient, 0, "", owner0);
        PackedUserOperation memory op = _userOp(callData, _activationBlob(_dummyBlob(), _proof()));

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("activation"), 0);

        assertEq(r, 0);
        assertTrue(account.activated());
        assertEq(account.authState(owner0), 1);
    }

    function test_activationBadProof_rejected() public {
        verifier.setRecovered(initialOwner);
        bytes32[] memory proof = _proof();
        bytes memory callData = _execCalldata(recipient, 0, "", owner0);
        proof[0] = keccak256("wrong-proof");
        bytes memory sig = _activationBlob(_dummyBlob(), proof);
        PackedUserOperation memory op = _userOp(callData, sig);

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("activation"), 0);

        assertEq(r, 1);
        assertFalse(account.activated());
        assertEq(account.authState(owner0), 0);
    }

    function test_activationWrongChain_rejected() public {
        verifier.setRecovered(initialOwner);
        bytes memory callData = _execCalldata(recipient, 0, "", owner0);
        PackedUserOperation memory op = _userOp(callData, _activationBlob(_dummyBlob(), _proof()));

        vm.chainId(block.chainid + 1);

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("activation"), 0);

        assertEq(r, 1);
        assertFalse(account.activated());
        assertEq(account.authState(owner0), 0);
    }

    function test_plainForsSigCannotActivate() public {
        verifier.setRecovered(initialOwner);
        bytes memory callData = _execCalldata(recipient, 0, "", owner0);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("activation"), 0);

        assertEq(r, 1);
        assertFalse(account.activated());
        assertEq(account.authState(owner0), 0);
    }

    /// @dev With SPHINCS- signers registered, an activation envelope must still route to the
    ///      activation path: its first 64 bytes never match a registered key head.
    function test_activation_notShadowedByRegisteredSigners() public {
        vm.prank(ENTRYPOINT);
        account.addSphincsSigner(PK_SEED_2, PK_ROOT_2, _lightParams());

        test_validActivation_rotatesOwner();
    }

    // =========================================================================
    // Validation + rotation after activation
    // =========================================================================

    function test_validSig_rotatesOwner() public {
        _activateTo(owner0);

        verifier.setRecovered(owner0);
        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("op"), 0);

        assertEq(r, 0);
        assertEq(account.authState(owner0), 2);
        assertEq(account.authState(owner1), 1);
    }

    function test_strangerSig_rejected() public {
        _activateTo(owner0);

        verifier.setRecovered(makeAddr("stranger"));
        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("op"), 0);

        assertEq(r, 1);
        assertEq(account.authState(owner0), 1);
        assertEq(account.authState(owner1), 0);
    }

    function test_zeroRecovered_rejected() public {
        _activateTo(owner0);

        verifier.setRecovered(address(0));
        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("op"), 0);

        assertEq(r, 1);
        assertEq(account.authState(owner0), 1);
    }

    function test_burnedKeyReuse_rejected() public {
        _activateTo(owner0);

        // First op burns owner0, activates owner1.
        verifier.setRecovered(owner0);
        _validate(owner1, keccak256("op0"));
        assertEq(account.authState(owner0), 2);

        // owner0 is now burned; reusing it must fail and change nothing.
        verifier.setRecovered(owner0);
        bytes memory callData = _execCalldata(recipient, 0, "", owner2);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("op1"), 0);

        assertEq(r, 1);
        assertEq(account.authState(owner1), 1);
        assertEq(account.authState(owner2), 0);
    }

    function test_rotateToActiveKey_reverts() public {
        _activateTo(owner0);

        // Rotating onto an already-active key (owner0 itself) is rejected.
        verifier.setRecovered(owner0);
        bytes memory callData = _execCalldata(recipient, 0, "", owner0);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        vm.expectRevert("SimpleAccount: next owner not fresh");
        account.validateUserOp(op, keccak256("op"), 0);
    }

    function test_rotateToBurnedKey_reverts() public {
        _activateTo(owner0);

        verifier.setRecovered(owner0);
        _validate(owner1, keccak256("op0"));

        // owner0 is burned; rotating back onto it is rejected.
        verifier.setRecovered(owner1);
        bytes memory callData = _execCalldata(recipient, 0, "", owner0);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        vm.expectRevert("SimpleAccount: next owner not fresh");
        account.validateUserOp(op, keccak256("op1"), 0);
    }

    function test_badSigLen_rejected() public {
        _activateTo(owner0);

        verifier.setRecovered(owner0);
        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, new bytes(FORS_SIG_LEN - 1));

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("op"), 0);

        assertEq(r, 1);
        assertEq(account.authState(owner0), 1);
    }

    function test_revertsOnBadCalldataLen() public {
        PackedUserOperation memory op = _userOp(hex"aabbcc", _activationBlob(_dummyBlob(), _proof()));

        vm.prank(ENTRYPOINT);
        vm.expectRevert("SimpleAccount: missing next owner");
        account.validateUserOp(op, keccak256("op"), 0);
    }

    function test_revertsOnZeroNextOwner() public {
        _activateTo(owner0);

        verifier.setRecovered(owner0);
        bytes memory callData = _execCalldata(recipient, 0, "", address(0));
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        vm.expectRevert("SimpleAccount: zero next owner");
        account.validateUserOp(op, keccak256("op"), 0);
    }

    function test_revertsIfNotEntryPoint() public {
        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, _activationBlob(_dummyBlob(), _proof()));

        vm.prank(makeAddr("random"));
        vm.expectRevert("SimpleAccount: not from EntryPoint");
        account.validateUserOp(op, keccak256("op"), 0);
    }

    function test_paysPrefund() public {
        _activateTo(owner0);

        verifier.setRecovered(owner0);
        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        uint256 before = ENTRYPOINT.balance;
        vm.prank(ENTRYPOINT);
        account.validateUserOp(op, keccak256("op"), 0.1 ether);

        assertEq(ENTRYPOINT.balance, before + 0.1 ether);
    }

    function test_revertsIfPrefundTransferFails() public {
        _activateTo(owner0);

        verifier.setRecovered(owner0);
        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        vm.expectRevert("SimpleAccount: prefund failed");
        account.validateUserOp(op, keccak256("op"), address(account).balance + 1);

        assertEq(account.authState(owner0), 1);
    }

    function test_multiTxRotationChain() public {
        _activateTo(owner0);

        verifier.setRecovered(owner0);
        _validate(owner1, keccak256("op0"));
        assertEq(account.authState(owner0), 2);
        assertEq(account.authState(owner1), 1);

        verifier.setRecovered(owner1);
        _validate(owner2, keccak256("op1"));
        assertEq(account.authState(owner1), 2);
        assertEq(account.authState(owner2), 1);
    }

    // =========================================================================
    // SPHINCS- backup signers (co-equal, key-head-dispatched, rotate the FORS owner)
    // =========================================================================

    /// @dev A SPHINCS- op carries [execute][currentKey][nextOwner] and rotates the FORS owner
    ///      identically to a FORS op: burn currentKey (even though it never signed), activate nextOwner.
    function test_sphincsRotatesFORSOwner() public {
        _activateTo(owner0);
        sphincsVerifier.setValid(true);
        bytes memory callData = _execCalldata2(recipient, 0, "", owner0, owner1);
        PackedUserOperation memory op = _userOp(callData, _backupEnvelope());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("sphincs-op"), 0);

        assertEq(r, 0);
        assertEq(account.authState(owner0), 2); // burned for recovery, without owner0 ever signing
        assertEq(account.authState(owner1), 1); // new active FORS owner
    }

    function test_sphincsInvalidRejected() public {
        _activateTo(owner0);
        sphincsVerifier.setValid(false);
        bytes memory callData = _execCalldata2(recipient, 0, "", owner0, owner1);
        PackedUserOperation memory op = _userOp(callData, _backupEnvelope());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("sphincs-op"), 0);

        assertEq(r, 1);
        assertEq(account.authState(owner0), 1); // unchanged
        assertEq(account.authState(owner1), 0);
    }

    function test_sphincsBackup_keyStillRegisteredAfterUse() public {
        _activateTo(owner0);
        sphincsVerifier.setValid(true);
        bytes memory callData = _execCalldata2(recipient, 0, "", owner0, owner1);
        PackedUserOperation memory op = _userOp(callData, _backupEnvelope());

        vm.prank(ENTRYPOINT);
        account.validateUserOp(op, keccak256("sphincs-op"), 0);

        // Backup keys are the static parallel authority — never rotated/consumed by use.
        _assertRegisteredParams(
            account.sphincsSignerId(BACKUP_PK_SEED, BACKUP_PK_ROOT), SphincsParamsLib.canonical()
        );
    }

    /// @dev A registered-key envelope must route to the SPHINCS- verifier even when the FORS
    ///      verifier would accept — proving dispatch is by registered key head, not by which
    ///      verifier happens to say yes.
    function test_dispatch_registeredHeadRoutesToSphincs() public {
        _activateTo(owner0);
        verifier.setRecovered(owner0); // FORS would accept
        sphincsVerifier.setValid(false); // SPHINCS- rejects
        bytes memory callData = _execCalldata2(recipient, 0, "", owner0, owner1);
        PackedUserOperation memory op = _userOp(callData, _backupEnvelope());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("sphincs-op"), 0);

        assertEq(r, 1);
        assertEq(account.authState(owner0), 1);
    }

    /// @dev A registered key head with a wrong-length blob is a FAILED signature — the op has
    ///      committed to the SPHINCS- route and must not fall through to FORS/activation.
    function test_dispatch_registeredHeadWrongLengthFails() public {
        _activateTo(owner0);
        sphincsVerifier.setValid(true); // even a lying verifier can't be reached
        verifier.setRecovered(owner0); // and FORS would accept if it fell through
        bytes memory callData = _execCalldata2(recipient, 0, "", owner0, owner1);
        bytes memory sig = abi.encodePacked(BACKUP_PK_SEED, BACKUP_PK_ROOT, new bytes(SPHINCS_SIG_LEN - 1));
        PackedUserOperation memory op = _userOp(callData, sig);

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("sphincs-op"), 0);

        assertEq(r, 1);
        assertEq(account.authState(owner0), 1);
        assertEq(account.authState(owner1), 0);
    }

    /// @dev An unregistered key head falls through and fails as a malformed FORS sig; nothing changes.
    function test_dispatch_unregisteredHeadFallsThrough() public {
        _activateTo(owner0);
        sphincsVerifier.setValid(true); // must never be consulted
        bytes memory callData = _execCalldata2(recipient, 0, "", owner0, owner1);
        bytes memory sig = abi.encodePacked(PK_SEED_2, PK_ROOT_2, new bytes(SPHINCS_SIG_LEN));
        PackedUserOperation memory op = _userOp(callData, sig);

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("sphincs-op"), 0);

        assertEq(r, 1);
        assertEq(account.authState(owner0), 1);
        assertEq(account.authState(owner1), 0);
    }

    /// @dev Cross-chain bootstrap: pre-activation a SPHINCS- op rotates in the first FORS owner
    ///      (currentKey can be a throwaway since none exists yet) and flips activated.
    function test_sphincsBootstrapRotates() public {
        assertFalse(account.activated());
        sphincsVerifier.setValid(true);
        bytes memory callData = _execCalldata2(recipient, 0, "", address(0), owner0);
        PackedUserOperation memory op = _userOp(callData, _backupEnvelope());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("bootstrap"), 0);

        assertEq(r, 0);
        assertTrue(account.activated());
        assertEq(account.authState(owner0), 1);
    }

    /// @dev The account must hand the verifier exactly the registered key, its packed params and
    ///      the blob (envelope minus the 64-byte head) — checked by the arg-recording mock.
    function test_sphincs_verifierReceivesRegisteredParams() public {
        _activateTo(owner0);
        sphincsVerifier.expect(
            BACKUP_PK_SEED, BACKUP_PK_ROOT, SphincsParamsLib.pack(SphincsParamsLib.canonical()), SPHINCS_SIG_LEN
        );
        bytes memory callData = _execCalldata2(recipient, 0, "", owner0, owner1);
        PackedUserOperation memory op = _userOp(callData, _backupEnvelope());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("sphincs-op"), 0);

        assertEq(r, 0, "verifier saw unexpected key/params/blob");
    }

    // =========================================================================
    // Multiple SPHINCS- signers: enrollment, per-signer params, removal
    // =========================================================================

    function test_addSphincsSigner_registersSecondKey() public {
        _activateTo(owner0);
        vm.prank(ENTRYPOINT);
        account.addSphincsSigner(PK_SEED_2, PK_ROOT_2, _lightParams());

        _assertRegisteredParams(account.sphincsSignerId(PK_SEED_2, PK_ROOT_2), _lightParams());
        // The initial backup key is untouched.
        _assertRegisteredParams(
            account.sphincsSignerId(BACKUP_PK_SEED, BACKUP_PK_ROOT), SphincsParamsLib.canonical()
        );
    }

    /// @dev An op signed with the second key must be verified with THAT key's params and length.
    function test_secondSigner_opUsesItsOwnParams() public {
        _activateTo(owner0);
        vm.prank(ENTRYPOINT);
        account.addSphincsSigner(PK_SEED_2, PK_ROOT_2, _lightParams());

        uint256 blobLen = SphincsParamsLib.blobLen(_lightParams()); // 3060, != canonical 3688
        sphincsVerifier.expect(PK_SEED_2, PK_ROOT_2, SphincsParamsLib.pack(_lightParams()), blobLen);

        bytes memory callData = _execCalldata2(recipient, 0, "", owner0, owner1);
        bytes memory sig = abi.encodePacked(PK_SEED_2, PK_ROOT_2, new bytes(blobLen));
        PackedUserOperation memory op = _userOp(callData, sig);

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("light-op"), 0);

        assertEq(r, 0);
        assertEq(account.authState(owner0), 2);
        assertEq(account.authState(owner1), 1);
    }

    function test_addSphincsSigner_viaSelfExecute() public {
        _activateTo(owner0);
        bytes memory data = abi.encodeWithSelector(account.addSphincsSigner.selector, PK_SEED_2, PK_ROOT_2, _lightParams());
        vm.prank(ENTRYPOINT);
        account.execute(address(account), 0, data);

        _assertRegisteredParams(account.sphincsSignerId(PK_SEED_2, PK_ROOT_2), _lightParams());
    }

    function test_addSphincsSigner_rejectsUnauthorizedCaller() public {
        vm.prank(makeAddr("random"));
        vm.expectRevert("SimpleAccount: not from EntryPoint or account");
        account.addSphincsSigner(PK_SEED_2, PK_ROOT_2, _lightParams());
    }

    function test_addSphincsSigner_rejectsDuplicate() public {
        vm.prank(ENTRYPOINT);
        vm.expectRevert("SimpleAccount: sphincs signer exists");
        account.addSphincsSigner(BACKUP_PK_SEED, BACKUP_PK_ROOT, _lightParams());
    }

    function test_addSphincsSigner_rejectsZeroKey() public {
        vm.prank(ENTRYPOINT);
        vm.expectRevert("SimpleAccount: zero sphincs key");
        account.addSphincsSigner(bytes32(0), PK_ROOT_2, _lightParams());
    }

    function test_addSphincsSigner_rejectsNonCanonicalKey() public {
        vm.prank(ENTRYPOINT);
        vm.expectRevert("SimpleAccount: non-canonical sphincs key");
        account.addSphincsSigner(bytes32(uint256(1)), PK_ROOT_2, _lightParams());
    }

    function test_addSphincsSigner_rejectsInvalidParams() public {
        SphincsParamsLib.Params memory p = _lightParams();
        p.d = 0;
        vm.prank(ENTRYPOINT);
        vm.expectRevert("SphincsParams: zero param");
        account.addSphincsSigner(PK_SEED_2, PK_ROOT_2, p);
    }

    /// @dev A VALID param set whose envelope length equals FORS_SIG_LEN (64 + 2384 = 2448) must be
    ///      rejected at registration — it could shadow the FORS route. (The set's arithmetic is
    ///      pinned in SphincsParamsLib.t.sol.)
    function test_addSphincsSigner_rejectsForsLengthCollision() public {
        SphincsParamsLib.Params memory p =
            SphincsParamsLib.Params({h: 32, d: 4, k: 7, a: 6, logW: 3, l: 18, targetSum: 63});
        vm.prank(ENTRYPOINT);
        vm.expectRevert("SimpleAccount: sphincs len is fors len");
        account.addSphincsSigner(PK_SEED_2, PK_ROOT_2, p);
    }

    function test_removeSphincsSigner_removesAndOpsFail() public {
        _activateTo(owner0);
        address id = account.sphincsSignerId(BACKUP_PK_SEED, BACKUP_PK_ROOT);

        vm.prank(ENTRYPOINT);
        account.removeSphincsSigner(id);

        (, uint8 d,,,,,) = account.sphincsSigners(id);
        assertEq(d, 0, "params slot must be zeroed");

        // A backup op with the removed key now fails (head no longer registered).
        sphincsVerifier.setValid(true);
        bytes memory callData = _execCalldata2(recipient, 0, "", owner0, owner1);
        PackedUserOperation memory op = _userOp(callData, _backupEnvelope());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("sphincs-op"), 0);
        assertEq(r, 1);
        assertEq(account.authState(owner0), 1);
    }

    function test_removeSphincsSigner_reRegisterAfterRemove() public {
        address id = account.sphincsSignerId(BACKUP_PK_SEED, BACKUP_PK_ROOT);
        vm.prank(ENTRYPOINT);
        account.removeSphincsSigner(id);

        // Re-registering the same key (even with different params) is allowed once removed.
        vm.prank(ENTRYPOINT);
        account.addSphincsSigner(BACKUP_PK_SEED, BACKUP_PK_ROOT, _lightParams());
        _assertRegisteredParams(id, _lightParams());
    }

    function test_removeSphincsSigner_rejectsUnknownId() public {
        vm.prank(ENTRYPOINT);
        vm.expectRevert("SimpleAccount: unknown sphincs signer");
        account.removeSphincsSigner(makeAddr("neverRegistered"));
    }

    function test_removeSphincsSigner_rejectsUnauthorizedCaller() public {
        address id = account.sphincsSignerId(BACKUP_PK_SEED, BACKUP_PK_ROOT);
        vm.prank(makeAddr("random"));
        vm.expectRevert("SimpleAccount: not from EntryPoint or account");
        account.removeSphincsSigner(id);
    }

    // =========================================================================
    // addSigner enrollment (reachable by any valid signer; flips activated)
    // =========================================================================

    function test_addSigner_enrollsNewDevice() public {
        _activateTo(owner0);
        vm.prank(ENTRYPOINT);
        account.addSigner(owner1);
        assertEq(account.authState(owner1), 1);
        assertEq(account.authState(owner0), 1); // existing device untouched, not burned
    }

    function test_addSigner_bootstrapsInactiveAccount() public {
        // Pre-activation enrollment (e.g. driven by a SPHINCS- op's callData on an uncommitted chain)
        // flips activated and authorizes the first device.
        assertFalse(account.activated());
        vm.prank(ENTRYPOINT);
        account.addSigner(owner0);
        assertTrue(account.activated());
        assertEq(account.authState(owner0), 1);
    }

    function test_addSigner_rejectsZero() public {
        _activateTo(owner0);
        vm.prank(ENTRYPOINT);
        vm.expectRevert("SimpleAccount: zero signer");
        account.addSigner(address(0));
    }

    function test_addSigner_rejectsActiveTarget() public {
        _activateTo(owner0);
        vm.prank(ENTRYPOINT);
        vm.expectRevert("SimpleAccount: signer not fresh");
        account.addSigner(owner0);
    }

    function test_addSigner_rejectsBurnedTarget() public {
        _activateTo(owner0);
        verifier.setRecovered(owner0);
        _validate(owner1, keccak256("op0")); // burns owner0
        vm.prank(ENTRYPOINT);
        vm.expectRevert("SimpleAccount: signer not fresh");
        account.addSigner(owner0);
    }

    function test_addSigner_rejectsUnauthorizedCaller() public {
        _activateTo(owner0);
        vm.prank(makeAddr("random"));
        vm.expectRevert("SimpleAccount: not from EntryPoint or account");
        account.addSigner(owner1);
    }

    // =========================================================================
    // Backup-key binding into the deterministic address
    // =========================================================================

    function test_differentBackupKeyGivesDifferentAddress() public view {
        address a0 = factory.getAddress(initialSignerRoot, BACKUP_PK_SEED, BACKUP_PK_ROOT, 0);
        bytes32 otherSeed = bytes32(uint256(0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC) << 128);
        address a1 = factory.getAddress(initialSignerRoot, otherSeed, BACKUP_PK_ROOT, 0);
        assertTrue(a0 != a1);
    }

    function test_crossChain_addressIdenticalAcrossChains() public {
        address a0 = factory.getAddress(initialSignerRoot, BACKUP_PK_SEED, BACKUP_PK_ROOT, 0);
        vm.chainId(block.chainid + 12_345);
        address a1 = factory.getAddress(initialSignerRoot, BACKUP_PK_SEED, BACKUP_PK_ROOT, 0);
        assertEq(a0, a1);
    }

    function test_factoryRejectsZeroBackupKey() public {
        vm.expectRevert("SimpleAccountFactory: zero backup key");
        factory.createAccount(initialSignerRoot, bytes32(0), BACKUP_PK_ROOT, 7);
    }

    function test_createAccount_rejectsNonCanonicalBackupKey() public {
        bytes32 nonCanonical = bytes32(uint256(1)); // low bit set -> not top-128-aligned
        vm.expectRevert("SimpleAccount: non-canonical sphincs key");
        factory.createAccount(initialSignerRoot, nonCanonical, BACKUP_PK_ROOT, 7);
    }

    // =========================================================================
    // Execute
    // =========================================================================

    function test_executeSendsETH() public {
        vm.prank(ENTRYPOINT);
        account.execute(recipient, 1 ether, "");
        assertEq(recipient.balance, 1 ether);
    }

    function test_ownerCannotWithdrawDepositDirectly() public {
        vm.prank(owner0);
        vm.expectRevert("SimpleAccount: not from EntryPoint or account");
        account.withdrawDepositTo(payable(recipient), 0);
    }

    function test_ownerCannotAddDepositDirectly() public {
        vm.prank(owner0);
        vm.expectRevert("SimpleAccount: not from EntryPoint or account");
        account.addDeposit();
    }

    function test_executeBatch() public {
        address r2 = makeAddr("r2");
        address[] memory targets = new address[](2);
        targets[0] = recipient;
        targets[1] = r2;
        uint256[] memory values = new uint256[](2);
        values[0] = 1 ether;
        values[1] = 2 ether;
        bytes[] memory datas = new bytes[](2);

        vm.prank(ENTRYPOINT);
        account.executeBatch(targets, values, datas);
        assertEq(recipient.balance, 1 ether);
        assertEq(r2.balance, 2 ether);
    }

    function test_receiveETH() public {
        vm.deal(makeAddr("sender"), 1 ether);
        vm.prank(makeAddr("sender"));
        (bool ok,) = address(account).call{value: 1 ether}("");
        assertTrue(ok);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    function _assertRegisteredParams(address id, SphincsParamsLib.Params memory expected) internal view {
        (uint8 h, uint8 d, uint8 k, uint8 a, uint8 logW, uint8 l, uint16 targetSum) = account.sphincsSigners(id);
        assertEq(h, expected.h);
        assertEq(d, expected.d);
        assertEq(k, expected.k);
        assertEq(a, expected.a);
        assertEq(logW, expected.logW);
        assertEq(l, expected.l);
        assertEq(targetSum, expected.targetSum);
    }

    function _activateTo(address nextOwner) internal {
        verifier.setRecovered(initialOwner);
        bytes memory callData = _execCalldata(recipient, 0, "", nextOwner);
        PackedUserOperation memory op = _userOp(callData, _activationBlob(_dummyBlob(), _proof()));

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("activation"), 0);
        assertEq(r, 0);
        assertTrue(account.activated());
        assertEq(account.authState(nextOwner), 1);
    }

    function _execCalldata(address to, uint256 value, bytes memory data, address nextOwner)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodePacked(abi.encodeWithSelector(account.execute.selector, to, value, data), bytes20(nextOwner));
    }

    /// @dev SPHINCS- calldata layout: [execute(...)][currentKey][nextOwner] (40-byte rotation tail).
    function _execCalldata2(address to, uint256 value, bytes memory data, address currentKey, address nextOwner)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodePacked(
            abi.encodeWithSelector(account.execute.selector, to, value, data), bytes20(currentKey), bytes20(nextOwner)
        );
    }

    function _dummyBlob() internal pure returns (bytes memory) {
        return new bytes(FORS_SIG_LEN);
    }

    /// @dev SPHINCS- envelope for the initialize-registered backup key (canonical params):
    ///      [pkSeed(32)][pkRoot(32)][zeroed canonical-length blob].
    function _backupEnvelope() internal pure returns (bytes memory) {
        return abi.encodePacked(BACKUP_PK_SEED, BACKUP_PK_ROOT, new bytes(SPHINCS_SIG_LEN));
    }

    function _userOp(bytes memory callData, bytes memory sig) internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: sig
        });
    }

    function _validate(address nextOwner, bytes32 userOpHash) internal {
        bytes memory callData = _execCalldata(recipient, 0, "", nextOwner);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, userOpHash, 0);
        assertEq(r, 0);
    }

    function _proof() internal view returns (bytes32[] memory proof) {
        proof = new bytes32[](activationProof.length);
        for (uint256 i = 0; i < activationProof.length; i++) {
            proof[i] = activationProof[i];
        }
    }

    function _activationBlob(bytes memory forsSig, bytes32[] memory proof) internal pure returns (bytes memory) {
        require(proof.length <= type(uint16).max, "proof too long");
        bytes memory blob = abi.encodePacked(bytes1(ACTIVATION_SIGNATURE_VERSION), bytes2(uint16(proof.length)));
        for (uint256 i = 0; i < proof.length; i++) {
            blob = bytes.concat(blob, proof[i]);
        }
        return bytes.concat(blob, forsSig);
    }

    function _leaf(uint256 chainId, address signer) internal pure returns (bytes32) {
        return keccak256(abi.encode(INITIAL_SIGNER_LEAF_TYPEHASH, chainId, signer));
    }

    function _buildActivationTree() internal view returns (bytes32 root, bytes32[] memory proof) {
        bytes32[] memory level = new bytes32[](ACTIVATION_TREE_LEAF_COUNT);
        level[0] = initialLeaf;

        for (uint256 i = 1; i < ACTIVATION_TREE_LEAF_COUNT; i++) {
            address signer = address(uint160(uint256(keccak256(abi.encode("remoteInitialOwner", i)))));
            level[i] = _leaf(block.chainid + i, signer);
        }

        proof = new bytes32[](ACTIVATION_TREE_DEPTH);
        uint256 index = 0;
        uint256 width = ACTIVATION_TREE_LEAF_COUNT;

        for (uint256 depth = 0; depth < ACTIVATION_TREE_DEPTH; depth++) {
            proof[depth] = level[index ^ 1];

            bytes32[] memory nextLevel = new bytes32[](width / 2);
            for (uint256 i = 0; i < width; i += 2) {
                nextLevel[i / 2] = _hashPair(level[i], level[i + 1]);
            }

            level = nextLevel;
            index /= 2;
            width /= 2;
        }

        root = level[0];
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encode(a, b)) : keccak256(abi.encode(b, a));
    }
}
