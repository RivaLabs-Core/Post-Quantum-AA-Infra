// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/SimpleAccount.sol";
import "../src/SimpleAccountFactory.sol";
import {ISignatureVerifier} from "../src/Interfaces/ISignatureVerifier.sol";
import {FORS_SIG_LEN} from "../src/Verifiers/ForsVerifier.sol";
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

contract SimpleAccountTest is Test {
    bytes32 internal constant INITIAL_SIGNER_LEAF_TYPEHASH = keccak256(
        "NiceTryInitialSignerLeaf:v1(uint256 chainId,address signer,bytes32 derivationPathHash,uint8 schemeId,uint64 signerIndex)"
    );
    uint8 internal constant ACTIVATION_SIGNATURE_VERSION = 1;
    uint8 internal constant SCHEME_FORS = 1;
    uint64 internal constant INITIAL_SIGNER_INDEX = 0;

    SimpleAccountFactory factory;
    SimpleAccount account;
    MockSignatureVerifier verifier;
    IEntryPoint entryPoint;

    address initialOwner = makeAddr("initialForsOwner");
    address remoteInitialOwner = makeAddr("remoteInitialForsOwner");
    address owner0 = makeAddr("forsOwner0");
    address owner1 = makeAddr("forsOwner1");
    address owner2 = makeAddr("forsOwner2");

    address recipient = makeAddr("recipient");

    bytes32 derivationPathHash;
    bytes32 remoteDerivationPathHash;
    bytes32 initialLeaf;
    bytes32 remoteLeaf;
    bytes32 initialSignerRoot;

    address constant ENTRYPOINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    function setUp() public {
        entryPoint = IEntryPoint(ENTRYPOINT);
        vm.etch(ENTRYPOINT, hex"00");

        derivationPathHash = keccak256("NiceTry/test/local-path");
        remoteDerivationPathHash = keccak256("NiceTry/test/remote-path");
        initialLeaf = _leaf(block.chainid, initialOwner, derivationPathHash);
        remoteLeaf = _leaf(block.chainid + 1, remoteInitialOwner, remoteDerivationPathHash);
        initialSignerRoot = _hashPair(initialLeaf, remoteLeaf);

        verifier = new MockSignatureVerifier();
        factory = new SimpleAccountFactory(entryPoint, verifier);

        address accountAddr = factory.createAccount(initialSignerRoot, 0);
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
    }

    function test_cannotReinitialize() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        account.initialize(bytes32(uint256(1)));
    }

    function test_factoryRejectsZeroRoot() public {
        vm.expectRevert("SimpleAccountFactory: zero root");
        factory.createAccount(bytes32(0), 1);
    }

    function test_factoryGetAddressRejectsZeroRoot() public {
        vm.expectRevert("SimpleAccountFactory: zero root");
        factory.getAddress(bytes32(0), 1);
    }

    function test_factoryDifferentSaltGivesDifferentAddress() public view {
        address addr0 = factory.getAddress(initialSignerRoot, 0);
        address addr1 = factory.getAddress(initialSignerRoot, 1);
        assertTrue(addr0 != addr1);
    }

    function test_factoryDifferentRootGivesDifferentAddress() public {
        bytes32 otherRoot = _leaf(block.chainid, makeAddr("otherInitialOwner"), derivationPathHash);
        address addr0 = factory.getAddress(initialSignerRoot, 0);
        address addr1 = factory.getAddress(otherRoot, 0);
        assertTrue(addr0 != addr1);
    }

    function test_factoryReturnsSameAddressIfAlreadyDeployed() public {
        address first = factory.createAccount(initialSignerRoot, 0);
        address second = factory.createAccount(initialSignerRoot, 0);
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
        bytes memory sig =
            _activationBlob(_dummyBlob(), proof, keccak256("wrong-path"), SCHEME_FORS, INITIAL_SIGNER_INDEX);
        PackedUserOperation memory op = _userOp(callData, sig);

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("activation"), 0);

        assertEq(r, 1);
        assertEq(account.owner(), address(0));
    }

    function test_activationWrongScheme_rejected() public {
        verifier.setRecovered(initialOwner);
        bytes memory callData = _execCalldata(recipient, 0, "", owner0);
        bytes memory sig = _activationBlob(_dummyBlob(), _proof(), derivationPathHash, 2, INITIAL_SIGNER_INDEX);
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
        proof = new bytes32[](1);
        proof[0] = remoteLeaf;
    }

    function _activationBlob(bytes memory forsSig, bytes32[] memory proof) internal view returns (bytes memory) {
        return _activationBlob(forsSig, proof, derivationPathHash, SCHEME_FORS, INITIAL_SIGNER_INDEX);
    }

    function _activationBlob(
        bytes memory forsSig,
        bytes32[] memory proof,
        bytes32 pathHash,
        uint8 schemeId,
        uint64 signerIndex
    ) internal pure returns (bytes memory blob) {
        require(proof.length <= type(uint16).max, "proof too long");
        blob = abi.encodePacked(
            bytes1(ACTIVATION_SIGNATURE_VERSION),
            bytes1(schemeId),
            bytes8(signerIndex),
            pathHash,
            bytes2(uint16(proof.length))
        );
        for (uint256 i = 0; i < proof.length; i++) {
            blob = bytes.concat(blob, proof[i]);
        }
        return bytes.concat(blob, forsSig);
    }

    function _leaf(uint256 chainId, address signer, bytes32 pathHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(INITIAL_SIGNER_LEAF_TYPEHASH, chainId, signer, pathHash, SCHEME_FORS, uint64(0)));
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encode(a, b)) : keccak256(abi.encode(b, a));
    }
}
