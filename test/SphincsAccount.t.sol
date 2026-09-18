// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SphincsAccount} from "../src/SphincsAccount.sol";
import {SphincsAccountFactory} from "../src/SphincsAccountFactory.sol";
import {ISphincsVerifier} from "../src/Interfaces/ISphincsVerifier.sol";
import {SphincsStandardVerifier, SPHINCS_STANDARD_SIG_LEN} from "../src/Verifiers/SphincsStandardVerifier.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

/// @dev Mock SPHINCS- verifier — the test pre-sets the bool `verify()` returns.
contract MockSphincsVerifier is ISphincsVerifier {
    bool public _valid;

    function setValid(bool v) external {
        _valid = v;
    }

    function verify(bytes32, bytes32, bytes32, bytes calldata) external view returns (bool) {
        return _valid;
    }
}

contract SphincsAccountTest is Test {
    address constant ENTRYPOINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    uint256 constant SIG_VALIDATION_FAILED = 1;

    // Canonical (top-128-bit-aligned) SPHINCS- public key.
    bytes32 constant PK_SEED = bytes32(uint256(0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1) << 128);
    bytes32 constant PK_ROOT = bytes32(uint256(0xA2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2) << 128);

    SphincsAccountFactory factory;
    SphincsAccount account;
    MockSphincsVerifier verifier;
    IEntryPoint entryPoint;

    address recipient = makeAddr("recipient");

    function setUp() public {
        entryPoint = IEntryPoint(ENTRYPOINT);
        vm.etch(ENTRYPOINT, hex"00");

        verifier = new MockSphincsVerifier();
        factory = new SphincsAccountFactory(entryPoint, verifier);
        account = SphincsAccount(payable(factory.createAccount(PK_SEED, PK_ROOT, 0)));

        vm.deal(address(account), 100 ether);
    }

    // =========================================================================
    // Factory
    // =========================================================================

    function test_factory_addressMatchesPrediction() public view {
        assertEq(factory.getAddress(PK_SEED, PK_ROOT, 0), address(account));
    }

    function test_factory_isIdempotent() public {
        address again = factory.createAccount(PK_SEED, PK_ROOT, 0);
        assertEq(again, address(account));
    }

    /// @dev The whole point of binding the key into the salt: a different key cannot land on the
    ///      same address, so a deploy race cannot install someone else's key at your address.
    function test_factory_saltBindsKey() public view {
        bytes32 otherSeed = bytes32(uint256(0xC1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1) << 128);
        assertTrue(factory.getAddress(otherSeed, PK_ROOT, 0) != address(account));
        assertTrue(factory.getAddress(PK_SEED, otherSeed, 0) != address(account));
        assertTrue(factory.getAddress(PK_SEED, PK_ROOT, 1) != address(account));
    }

    function test_factory_rejectsZeroKey() public {
        vm.expectRevert("SphincsAccountFactory: zero key");
        factory.getAddress(bytes32(0), PK_ROOT, 0);
        vm.expectRevert("SphincsAccountFactory: zero key");
        factory.getAddress(PK_SEED, bytes32(0), 0);
    }

    /// @dev A non-canonical key would make verify() revert on every op, permanently bricking the
    ///      account. getAddress must refuse to even quote an address for one.
    function test_factory_rejectsNonCanonicalKey() public {
        bytes32 bad = bytes32(uint256(PK_SEED) | 1);
        vm.expectRevert("SphincsAccountFactory: non-canonical key");
        factory.getAddress(bad, PK_ROOT, 0);
        vm.expectRevert("SphincsAccountFactory: non-canonical key");
        factory.createAccount(PK_SEED, bytes32(uint256(PK_ROOT) | 1), 0);
    }

    function test_factory_wiring() public view {
        assertEq(address(factory.ENTRY_POINT()), ENTRYPOINT);
        assertEq(address(factory.VERIFIER()), address(verifier));
        assertTrue(factory.ACCOUNT_IMPL() != address(0));
    }

    // =========================================================================
    // Initialization
    // =========================================================================

    function test_init_storesKey() public view {
        assertEq(account.pkSeed(), PK_SEED);
        assertEq(account.pkRoot(), PK_ROOT);
        assertEq(address(account.VERIFIER()), address(verifier));
        assertEq(address(account.entryPoint()), ENTRYPOINT);
    }

    function test_init_cannotReinitialize() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        account.initialize(PK_SEED, PK_ROOT);
    }

    function test_init_implementationIsLocked() public {
        SphincsAccount impl = SphincsAccount(payable(factory.ACCOUNT_IMPL()));
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(PK_SEED, PK_ROOT);
    }

    // =========================================================================
    // Signature validation
    // =========================================================================

    function test_validate_acceptsValidSignature() public {
        verifier.setValid(true);
        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(_userOp(_execCalldata(), _blob(SPHINCS_STANDARD_SIG_LEN)), keccak256("h"), 0);
        assertEq(r, 0);
    }

    function test_validate_rejectsBadSignature() public {
        verifier.setValid(false);
        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(_userOp(_execCalldata(), _blob(SPHINCS_STANDARD_SIG_LEN)), keccak256("h"), 0);
        assertEq(r, SIG_VALIDATION_FAILED);
    }

    /// @dev Wrong length must FAIL, not revert — even with a verifier that would say yes. A revert
    ///      inside validation is a bundler-level rejection rather than a clean signature failure.
    function test_validate_wrongLengthFailsWithoutReverting() public {
        verifier.setValid(true);
        vm.prank(ENTRYPOINT);
        uint256 r =
            account.validateUserOp(_userOp(_execCalldata(), _blob(SPHINCS_STANDARD_SIG_LEN - 1)), keccak256("h"), 0);
        assertEq(r, SIG_VALIDATION_FAILED);

        vm.prank(ENTRYPOINT);
        r = account.validateUserOp(_userOp(_execCalldata(), _blob(8048)), keccak256("h"), 0);
        assertEq(r, SIG_VALIDATION_FAILED);

        vm.prank(ENTRYPOINT);
        r = account.validateUserOp(_userOp(_execCalldata(), ""), keccak256("h"), 0);
        assertEq(r, SIG_VALIDATION_FAILED);
    }

    /// @dev Unlike SimpleAccount, callData carries no trailing key material, so a bare call — or
    ///      even empty callData — must validate fine.
    function test_validate_noCallDataTailRequired() public {
        verifier.setValid(true);
        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(_userOp("", _blob(SPHINCS_STANDARD_SIG_LEN)), keccak256("h"), 0);
        assertEq(r, 0);
    }

    function test_validate_onlyFromEntryPoint() public {
        verifier.setValid(true);
        vm.expectRevert("SphincsAccount: not from EntryPoint");
        account.validateUserOp(_userOp(_execCalldata(), _blob(SPHINCS_STANDARD_SIG_LEN)), keccak256("h"), 0);
    }

    function test_validate_paysPrefund() public {
        verifier.setValid(true);
        uint256 before = ENTRYPOINT.balance;
        vm.prank(ENTRYPOINT);
        account.validateUserOp(_userOp(_execCalldata(), _blob(SPHINCS_STANDARD_SIG_LEN)), keccak256("h"), 1 ether);
        assertEq(ENTRYPOINT.balance - before, 1 ether);
    }

    /// @dev End-to-end against the REAL verifier: a garbage 8400-byte blob must come back as a
    ///      clean validation failure, never a revert. (No reference vector exists, so the positive
    ///      path is still unproven — see the contract header.)
    function test_validate_realVerifierGarbageFails() public {
        SphincsStandardVerifier real = new SphincsStandardVerifier();
        SphincsAccountFactory f = new SphincsAccountFactory(entryPoint, ISphincsVerifier(address(real)));
        SphincsAccount a = SphincsAccount(payable(f.createAccount(PK_SEED, PK_ROOT, 0)));

        bytes memory sig = _blob(SPHINCS_STANDARD_SIG_LEN);
        vm.prank(ENTRYPOINT);
        assertEq(a.validateUserOp(_userOp(_execCalldata(), sig), keccak256("h"), 0), SIG_VALIDATION_FAILED);

        // And a wrong length still fails cleanly rather than hitting the verifier's revert.
        vm.prank(ENTRYPOINT);
        assertEq(a.validateUserOp(_userOp(_execCalldata(), _blob(8288)), keccak256("h"), 0), SIG_VALIDATION_FAILED);
    }

    // =========================================================================
    // Execution
    // =========================================================================

    function test_execute_fromEntryPoint() public {
        vm.prank(ENTRYPOINT);
        account.execute(recipient, 1 ether, "");
        assertEq(recipient.balance, 1 ether);
    }

    function test_execute_rejectsStranger() public {
        vm.expectRevert();
        account.execute(recipient, 1 ether, "");
    }

    function test_executeBatch_fromEntryPoint() public {
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);
        targets[0] = recipient;
        targets[1] = recipient;
        values[0] = 1 ether;
        values[1] = 2 ether;

        vm.prank(ENTRYPOINT);
        account.executeBatch(targets, values, datas);
        assertEq(recipient.balance, 3 ether);
    }

    function test_executeBatch_lengthMismatch() public {
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](2);

        vm.prank(ENTRYPOINT);
        vm.expectRevert("SphincsAccount: length mismatch");
        account.executeBatch(targets, values, datas);
    }

    function test_receivesEther() public {
        (bool ok,) = address(account).call{value: 1 ether}("");
        assertTrue(ok);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    function _blob(uint256 len) internal pure returns (bytes memory b) {
        b = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            b[i] = bytes1(uint8((i % 251) + 1));
        }
    }

    function _execCalldata() internal view returns (bytes memory) {
        return abi.encodeCall(SphincsAccount.execute, (recipient, 0, ""));
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
}
