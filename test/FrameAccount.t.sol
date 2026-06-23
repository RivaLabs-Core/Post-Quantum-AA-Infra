// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ISignatureVerifier} from "../src/Interfaces/ISignatureVerifier.sol";
import {FORS_SIG_LEN} from "../src/Verifiers/ForsVerifier.sol";
import {FrameAccount} from "../src/FrameAccount.sol";

contract FrameMockSignatureVerifier is ISignatureVerifier {
    address public recovered;

    function setRecovered(address signer) external {
        recovered = signer;
    }

    function recover(bytes calldata, bytes32) external view returns (address signer) {
        return recovered;
    }
}

contract FrameAccountHarness is FrameAccount {
    struct MockFrame {
        uint256 mode;
        uint256 flags;
        address target;
        uint256 value;
        bytes data;
    }

    bytes32 internal mockSigHash;
    uint256 internal mockCurrentFrameIndex;
    MockFrame[] internal frames;

    bool public approved;
    uint256 public approvedScope;

    constructor(address initialOwner, ISignatureVerifier verifier) FrameAccount(initialOwner, verifier) {}

    function setSigHash(bytes32 sigHash) external {
        mockSigHash = sigHash;
    }

    function setCurrentFrameIndex(uint256 frameIndex) external {
        mockCurrentFrameIndex = frameIndex;
    }

    function clearFrames() external {
        delete frames;
    }

    function pushFrame(uint256 mode, uint256 flags, address target, uint256 value, bytes calldata data) external {
        frames.push(MockFrame({mode: mode, flags: flags, target: target, value: value, data: data}));
    }

    function validateForTest(bytes calldata signature) external {
        _validateFrameSignature(signature);
        _approveExecutionAndPayment();
    }

    function _txSigHash() internal view override returns (bytes32) {
        return mockSigHash;
    }

    function _frameCount() internal view override returns (uint256) {
        return frames.length;
    }

    function _currentFrameIndex() internal view override returns (uint256) {
        return mockCurrentFrameIndex;
    }

    function _frameTarget(uint256 frameIndex) internal view override returns (address) {
        return frames[frameIndex].target;
    }

    function _frameMode(uint256 frameIndex) internal view override returns (uint256) {
        return frames[frameIndex].mode;
    }

    function _frameValue(uint256 frameIndex) internal view override returns (uint256) {
        return frames[frameIndex].value;
    }

    function _frameAtomicBatch(uint256 frameIndex) internal view override returns (bool) {
        return (frames[frameIndex].flags & ATOMIC_BATCH_FLAG) != 0;
    }

    function _frameDataLength(uint256 frameIndex) internal view override returns (uint256) {
        return frames[frameIndex].data.length;
    }

    function _frameDataLoad(uint256 frameIndex, uint256 offset) internal view override returns (bytes32 word) {
        bytes memory data = frames[frameIndex].data;
        assembly {
            word := mload(add(add(data, 0x20), offset))
        }
    }

    function _approveExecutionAndPayment() internal override {
        approved = true;
        approvedScope = 3;
    }
}

contract FrameAccountTest is Test {
    uint256 internal constant VERIFY_MODE = 1;
    uint256 internal constant SENDER_MODE = 2;
    uint256 internal constant ATOMIC_BATCH_FLAG = 1 << 2;

    FrameMockSignatureVerifier verifier;
    FrameAccountHarness account;

    address owner0 = makeAddr("owner0");
    address owner1 = makeAddr("owner1");
    address stranger = makeAddr("stranger");
    bytes32 sigHash = keccak256("frame-sig-hash");

    function setUp() public {
        verifier = new FrameMockSignatureVerifier();
        account = new FrameAccountHarness(owner0, verifier);
        account.setSigHash(sigHash);
        verifier.setRecovered(owner0);
        _setValidRotationFrames(owner1);
    }

    function test_constructorSetsOwnerAndVerifier() public view {
        assertEq(account.authState(owner0), 1);
        assertEq(address(account.VERIFIER()), address(verifier));
    }

    function test_constructorRejectsZeroOwner() public {
        vm.expectRevert(FrameAccount.FrameAccountZeroOwner.selector);
        new FrameAccountHarness(address(0), verifier);
    }

    function test_constructorRejectsZeroVerifier() public {
        vm.expectRevert(FrameAccount.FrameAccountZeroVerifier.selector);
        new FrameAccountHarness(owner0, ISignatureVerifier(address(0)));
    }

    function test_validSignatureWithNextRotationFrameApprovesWithoutRotatingYet() public {
        account.validateForTest(_dummyBlob());

        assertTrue(account.approved());
        assertEq(account.approvedScope(), 3);
        // Validation is side-effect-free: the signer stays active until the rotate frame runs.
        assertEq(account.authState(owner0), 1);
    }

    function test_fallbackIsVerifyEntryPoint() public {
        (bool ok,) = address(account).call(_dummyBlob());

        assertTrue(ok);
        assertTrue(account.approved());
        assertEq(account.authState(owner0), 1);
    }

    function test_senderFrameRotatesOwnerWhenCalledBySelf() public {
        vm.prank(address(account));
        account.rotateOwner(owner0, owner1);

        assertEq(account.authState(owner0), 2);
        assertEq(account.authState(owner1), 1);
    }

    function test_rotateOwnerRejectsDirectCaller() public {
        vm.expectRevert(FrameAccount.FrameAccountNotSelf.selector);
        account.rotateOwner(owner0, owner1);
    }

    function test_rotateOwnerRejectsZeroOwner() public {
        vm.prank(address(account));
        vm.expectRevert(FrameAccount.FrameAccountZeroOwner.selector);
        account.rotateOwner(owner0, address(0));
    }

    function test_rotateOwnerRejectsInactiveCurrent() public {
        vm.prank(address(account));
        vm.expectRevert(abi.encodeWithSelector(FrameAccount.FrameAccountKeyNotActive.selector, stranger));
        account.rotateOwner(stranger, owner1);
    }

    function test_rotateOwnerRejectsNonFreshNext() public {
        // owner0 is already active, so it is not a fresh next key.
        vm.prank(address(account));
        vm.expectRevert(abi.encodeWithSelector(FrameAccount.FrameAccountNextOwnerNotFresh.selector, owner0));
        account.rotateOwner(owner0, owner0);
    }

    function test_badSignatureLengthRejects() public {
        bytes memory badSignature = new bytes(FORS_SIG_LEN - 1);

        vm.expectRevert(
            abi.encodeWithSelector(FrameAccount.FrameAccountBadSignatureLength.selector, badSignature.length)
        );
        account.validateForTest(badSignature);

        assertFalse(account.approved());
    }

    function test_wrongRecoveredSignerRejects() public {
        verifier.setRecovered(stranger);

        vm.expectRevert(abi.encodeWithSelector(FrameAccount.FrameAccountInvalidSignature.selector, stranger));
        account.validateForTest(_dummyBlob());

        assertFalse(account.approved());
    }

    function test_zeroRecoveredSignerRejects() public {
        verifier.setRecovered(address(0));

        vm.expectRevert(abi.encodeWithSelector(FrameAccount.FrameAccountInvalidSignature.selector, address(0)));
        account.validateForTest(_dummyBlob());

        assertFalse(account.approved());
    }

    function test_missingNextRotationFrameRejects() public {
        account.clearFrames();
        account.pushFrame(VERIFY_MODE, 0, address(account), 0, "");

        vm.expectRevert(abi.encodeWithSelector(FrameAccount.FrameAccountMissingRotationFrame.selector, 0, 1));
        account.validateForTest(_dummyBlob());
    }

    function test_nextFrameMustBeSenderMode() public {
        _setRotationFrames({mode: VERIFY_MODE, flags: 0, target: address(account), value: 0, nextOwner: owner1});

        vm.expectRevert(abi.encodeWithSelector(FrameAccount.FrameAccountRotationFrameWrongMode.selector, 1, 1));
        account.validateForTest(_dummyBlob());
    }

    function test_nextFrameMustTargetAccount() public {
        address wrongTarget = makeAddr("wrongTarget");
        _setRotationFrames({mode: SENDER_MODE, flags: 0, target: wrongTarget, value: 0, nextOwner: owner1});

        vm.expectRevert(
            abi.encodeWithSelector(FrameAccount.FrameAccountRotationFrameWrongTarget.selector, 1, wrongTarget)
        );
        account.validateForTest(_dummyBlob());
    }

    function test_nextFrameMustHaveZeroValue() public {
        _setRotationFrames({mode: SENDER_MODE, flags: 0, target: address(account), value: 1, nextOwner: owner1});

        vm.expectRevert(abi.encodeWithSelector(FrameAccount.FrameAccountRotationFrameNonZeroValue.selector, 1, 1));
        account.validateForTest(_dummyBlob());
    }

    function test_rotationFrameMustNotBeAtomic() public {
        _setRotationFrames({
            mode: SENDER_MODE, flags: ATOMIC_BATCH_FLAG, target: address(account), value: 0, nextOwner: owner1
        });

        vm.expectRevert(abi.encodeWithSelector(FrameAccount.FrameAccountRotationFrameAtomic.selector, 1));
        account.validateForTest(_dummyBlob());
    }

    function test_rotationFrameMustHaveExactCalldataLength() public {
        account.clearFrames();
        account.pushFrame(VERIFY_MODE, 0, address(account), 0, "");
        account.pushFrame(SENDER_MODE, 0, address(account), 0, abi.encodePacked(account.rotateOwner.selector));

        vm.expectRevert(abi.encodeWithSelector(FrameAccount.FrameAccountRotationFrameWrongDataLength.selector, 1, 4));
        account.validateForTest(_dummyBlob());
    }

    function test_rotationFrameMustCallRotateOwner() public {
        // Same byte length as rotateOwner(address,address) so the length check passes
        // and the selector check is what rejects it.
        bytes memory wrongCall = abi.encodeWithSelector(bytes4(keccak256("wrong(address,address)")), owner0, owner1);

        account.clearFrames();
        account.pushFrame(VERIFY_MODE, 0, address(account), 0, "");
        account.pushFrame(SENDER_MODE, 0, address(account), 0, wrongCall);

        vm.expectRevert(
            abi.encodeWithSelector(
                FrameAccount.FrameAccountRotationFrameWrongSelector.selector,
                1,
                bytes4(keccak256("wrong(address,address)"))
            )
        );
        account.validateForTest(_dummyBlob());
    }

    function test_rotationFrameMustBurnRecoveredSigner() public {
        // Rotation frame whose currentKey is not the recovered signer is rejected.
        account.clearFrames();
        account.pushFrame(VERIFY_MODE, 0, address(account), 0, "");
        account.pushFrame(SENDER_MODE, 0, address(account), 0, _rotateOwnerCalldata(stranger, owner1));
        account.setCurrentFrameIndex(0);

        vm.expectRevert(
            abi.encodeWithSelector(FrameAccount.FrameAccountRotationFrameWrongCurrent.selector, 1, stranger)
        );
        account.validateForTest(_dummyBlob());
    }

    function test_rotationFrameMustNotRotateToZero() public {
        _setRotationFrames({mode: SENDER_MODE, flags: 0, target: address(account), value: 0, nextOwner: address(0)});

        vm.expectRevert(abi.encodeWithSelector(FrameAccount.FrameAccountRotationFrameZeroOwner.selector, 1));
        account.validateForTest(_dummyBlob());
    }

    function test_rotationFrameCanBeAfterEarlierVerifyFrame() public {
        account.clearFrames();
        account.pushFrame(VERIFY_MODE, 0, address(account), 0, "");
        account.pushFrame(VERIFY_MODE, 0, address(account), 0, "");
        account.pushFrame(SENDER_MODE, 0, address(account), 0, _rotateOwnerCalldata(owner1));
        account.setCurrentFrameIndex(1);

        account.validateForTest(_dummyBlob());

        assertTrue(account.approved());
    }

    function _setValidRotationFrames(address nextOwner) internal {
        _setRotationFrames({mode: SENDER_MODE, flags: 0, target: address(account), value: 0, nextOwner: nextOwner});
    }

    function _setRotationFrames(uint256 mode, uint256 flags, address target, uint256 value, address nextOwner)
        internal
    {
        account.clearFrames();
        account.pushFrame(VERIFY_MODE, 0, address(account), 0, "");
        account.pushFrame(mode, flags, target, value, _rotateOwnerCalldata(owner0, nextOwner));
        account.setCurrentFrameIndex(0);
    }

    function _rotateOwnerCalldata(address nextOwner) internal view returns (bytes memory) {
        return _rotateOwnerCalldata(owner0, nextOwner);
    }

    function _rotateOwnerCalldata(address currentKey, address nextOwner) internal view returns (bytes memory) {
        return abi.encodeWithSelector(account.rotateOwner.selector, currentKey, nextOwner);
    }

    function _dummyBlob() internal pure returns (bytes memory) {
        return new bytes(FORS_SIG_LEN);
    }
}
