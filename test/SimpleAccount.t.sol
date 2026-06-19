// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/SimpleAccount.sol";
import "../src/SimpleAccountFactory.sol";
import {ISignatureVerifier} from "../src/Interfaces/ISignatureVerifier.sol";
import {ISphincsVerifier} from "../src/Interfaces/ISphincsVerifier.sol";
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

/// @dev Mock SPHINCS- verifier - test pre-sets the bool verify() should return.
contract MockSphincsVerifier is ISphincsVerifier {
    bool public _valid;

    function setValid(bool v) external {
        _valid = v;
    }

    function verify(bytes32, bytes32, bytes32, bytes calldata) external view returns (bool) {
        return _valid;
    }
}

contract SimpleAccountTest is Test {
    bytes32 internal constant INITIAL_SIGNER_LEAF_TYPEHASH =
        keccak256("NiceTryInitialSignerLeaf:v1(uint256 chainId,address signer)");
    uint8 internal constant ACTIVATION_SIGNATURE_VERSION = 1;
    uint256 internal constant ACTIVATION_TREE_LEAF_COUNT = 256;
    uint256 internal constant ACTIVATION_TREE_DEPTH = 8;

    // Canonical (top-128-bit-aligned, low 128 bits zero) SPHINCS- backup public key for tests.
    bytes32 internal constant BACKUP_PK_SEED = bytes32(uint256(0xB1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1) << 128);
    bytes32 internal constant BACKUP_PK_ROOT = bytes32(uint256(0xB2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2) << 128);

    SimpleAccountFactory factory;
    SimpleAccount account;
    MockSignatureVerifier verifier;
    MockSphincsVerifier sphincsVerifier;
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
        sphincsVerifier = new MockSphincsVerifier();
        factory = new SimpleAccountFactory(entryPoint, verifier, sphincsVerifier);

        address accountAddr = factory.createAccount(initialSignerRoot, BACKUP_PK_SEED, BACKUP_PK_ROOT, 0);
        account = SimpleAccount(payable(accountAddr));

        vm.deal(address(account), 100 ether);
    }

    // =========================================================================
    // Factory / init
    // =========================================================================

    function test_factoryDeploysInactiveAccount() public view {
        assertEq(account.owner(), address(0));
        assertEq(account.initialSignerRoot(), initialSignerRoot);
        assertEq(address(account.ENTRY_POINT()), ENTRYPOINT);
        assertEq(address(account.VERIFIER()), address(verifier));
        assertEq(address(account.SPHINCS_VERIFIER()), address(sphincsVerifier));
        assertEq(account.backupPkSeed(), BACKUP_PK_SEED);
        assertEq(account.backupPkRoot(), BACKUP_PK_ROOT);
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
        assertEq(account.owner(), owner0);
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
        assertEq(account.owner(), address(0));
    }

    function test_activationWrongChain_rejected() public {
        verifier.setRecovered(initialOwner);
        bytes memory callData = _execCalldata(recipient, 0, "", owner0);
        PackedUserOperation memory op = _userOp(callData, _activationBlob(_dummyBlob(), _proof()));

        vm.chainId(block.chainid + 1);

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("activation"), 0);

        assertEq(r, 1);
        assertEq(account.owner(), address(0));
    }

    function test_plainForsSigCannotActivate() public {
        verifier.setRecovered(initialOwner);
        bytes memory callData = _execCalldata(recipient, 0, "", owner0);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("activation"), 0);

        assertEq(r, 1);
        assertEq(account.owner(), address(0));
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
        assertEq(account.owner(), owner1);
    }

    function test_strangerSig_rejected() public {
        _activateTo(owner0);

        verifier.setRecovered(makeAddr("stranger"));
        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("op"), 0);

        assertEq(r, 1);
        assertEq(account.owner(), owner0);
    }

    function test_zeroRecovered_rejected() public {
        _activateTo(owner0);

        verifier.setRecovered(address(0));
        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("op"), 0);

        assertEq(r, 1);
        assertEq(account.owner(), owner0);
    }

    function test_badSigLen_rejected() public {
        _activateTo(owner0);

        verifier.setRecovered(owner0);
        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, new bytes(FORS_SIG_LEN - 1));

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("op"), 0);

        assertEq(r, 1);
        assertEq(account.owner(), owner0);
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

        assertEq(account.owner(), owner0);
    }

    function test_multiTxRotationChain() public {
        _activateTo(owner0);

        verifier.setRecovered(owner0);
        _validate(owner1, keccak256("op0"));
        assertEq(account.owner(), owner1);

        verifier.setRecovered(owner1);
        _validate(owner2, keccak256("op1"));
        assertEq(account.owner(), owner2);
    }

    // =========================================================================
    // SPHINCS- backup signer (co-equal, length-dispatched, cross-chain bootstrap)
    // =========================================================================

    function test_sphincsBackup_coEqualOpRotatesOwner() public {
        _activateTo(owner0);
        sphincsVerifier.setValid(true);
        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, _sphincsBlob());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("sphincs-op"), 0);

        assertEq(r, 0);
        assertEq(account.owner(), owner1);
    }

    function test_sphincsBackup_invalidRejected() public {
        _activateTo(owner0);
        sphincsVerifier.setValid(false);
        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, _sphincsBlob());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("sphincs-op"), 0);

        assertEq(r, 1);
        assertEq(account.owner(), owner0);
    }

    function test_sphincsBackup_keyUnchangedAfterUse() public {
        _activateTo(owner0);
        sphincsVerifier.setValid(true);
        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, _sphincsBlob());

        vm.prank(ENTRYPOINT);
        account.validateUserOp(op, keccak256("sphincs-op"), 0);

        assertEq(account.backupPkSeed(), BACKUP_PK_SEED);
        assertEq(account.backupPkRoot(), BACKUP_PK_ROOT);
    }

    /// @dev A SPHINCS_SIG_LEN blob must route to the SPHINCS- verifier even when the FORS verifier
    ///      would accept — proving dispatch is by length, not by which verifier happens to say yes.
    function test_lengthDispatch_sphincsLenRoutesToSphincs() public {
        _activateTo(owner0);
        verifier.setRecovered(owner0); // FORS would accept
        sphincsVerifier.setValid(false); // SPHINCS- rejects
        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, _sphincsBlob());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("sphincs-op"), 0);

        assertEq(r, 1);
        assertEq(account.owner(), owner0);
    }

    function test_sphincsBootstrap_activatesInactiveAccount() public {
        assertEq(account.owner(), address(0)); // inactive from setUp
        sphincsVerifier.setValid(true);
        bytes memory callData = _execCalldata(recipient, 0, "", owner0);
        PackedUserOperation memory op = _userOp(callData, _sphincsBlob());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("bootstrap"), 0);

        assertEq(r, 0);
        assertEq(account.owner(), owner0);
    }

    /// @dev Cross-chain: on a chain absent from the activation tree (where FORS+Merkle activation
    ///      would fail), the SPHINCS- backup can still bootstrap the account at the same address.
    function test_sphincsBootstrap_worksOnUncommittedChain() public {
        vm.chainId(block.chainid + 999_999);
        assertEq(account.owner(), address(0));
        sphincsVerifier.setValid(true);
        bytes memory callData = _execCalldata(recipient, 0, "", owner0);
        PackedUserOperation memory op = _userOp(callData, _sphincsBlob());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("bootstrap"), 0);

        assertEq(r, 0);
        assertEq(account.owner(), owner0);
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
        vm.expectRevert("SimpleAccount: non-canonical backup key");
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

    function _activateTo(address nextOwner) internal {
        verifier.setRecovered(initialOwner);
        bytes memory callData = _execCalldata(recipient, 0, "", nextOwner);
        PackedUserOperation memory op = _userOp(callData, _activationBlob(_dummyBlob(), _proof()));

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("activation"), 0);
        assertEq(r, 0);
        assertEq(account.owner(), nextOwner);
    }

    function _execCalldata(address to, uint256 value, bytes memory data, address nextOwner)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodePacked(abi.encodeWithSelector(account.execute.selector, to, value, data), bytes20(nextOwner));
    }

    function _dummyBlob() internal pure returns (bytes memory) {
        return new bytes(FORS_SIG_LEN);
    }

    function _sphincsBlob() internal pure returns (bytes memory) {
        return new bytes(SPHINCS_SIG_LEN);
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
