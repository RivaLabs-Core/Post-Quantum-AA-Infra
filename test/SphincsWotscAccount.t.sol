// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SphincsWotscAccount} from "../src/SphincsWotscAccount.sol";
import {SphincsWotscAccountFactory} from "../src/SphincsWotscAccountFactory.sol";
import {SphincsAccountFactory_v5} from "../src/SphincsAccountFactory_v5.sol";
import {SphincsAccountFactory_v6} from "../src/SphincsAccountFactory_v6.sol";
import {ISphincsVerifier} from "../src/Interfaces/ISphincsVerifier.sol";
import {SphincsVerifier_v5, SPHINCS_V5_SIG_LEN} from "../src/Verifiers/SphincsVerifier_v5.sol";
import {SphincsVerifier_v6, SPHINCS_V6_SIG_LEN} from "../src/Verifiers/SphincsVerifier_v6.sol";
import {SPHINCS_STANDARD_SIG_LEN} from "../src/Verifiers/SphincsStandardVerifier.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

/// @dev Mock SPHINCS- verifier — the test pre-sets the bool `verify()` returns.
contract MockWotscVerifier is ISphincsVerifier {
    bool public _valid;

    function setValid(bool v) external {
        _valid = v;
    }

    function verify(bytes32, bytes32, bytes32, bytes calldata) external view returns (bool) {
        return _valid;
    }
}

/// @dev Shared suite for the SphincsWotscAccount families; one concrete contract per parameter set.
abstract contract SphincsWotscAccountTestBase is Test {
    address constant ENTRYPOINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    uint256 constant SIG_VALIDATION_FAILED = 1;

    // Canonical (top-128-bit-aligned) SPHINCS- public key.
    bytes32 constant PK_SEED = bytes32(uint256(0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1) << 128);
    bytes32 constant PK_ROOT = bytes32(uint256(0xA2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2) << 128);

    SphincsWotscAccountFactory factory;
    SphincsWotscAccount account;
    MockWotscVerifier verifier;
    IEntryPoint entryPoint;

    address recipient = makeAddr("recipient");

    function _newFactory(IEntryPoint ep, ISphincsVerifier v) internal virtual returns (SphincsWotscAccountFactory);
    function _newRealVerifier() internal virtual returns (ISphincsVerifier);
    function _sigLen() internal pure virtual returns (uint256);
    /// @dev The other WOTS+C family's blob length, which this account must refuse.
    function _otherSigLen() internal pure virtual returns (uint256);
    function _vectorTag() internal pure virtual returns (string memory);

    function setUp() public {
        entryPoint = IEntryPoint(ENTRYPOINT);
        vm.etch(ENTRYPOINT, hex"00");

        verifier = new MockWotscVerifier();
        factory = _newFactory(entryPoint, verifier);
        account = SphincsWotscAccount(payable(factory.createAccount(PK_SEED, PK_ROOT, 0)));

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

    /// @dev A different key cannot land on the same address, so a deploy race cannot install
    ///      someone else's key at your address.
    function test_factory_saltBindsKey() public view {
        bytes32 otherSeed = bytes32(uint256(0xC1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1) << 128);
        assertTrue(factory.getAddress(otherSeed, PK_ROOT, 0) != address(account));
        assertTrue(factory.getAddress(PK_SEED, otherSeed, 0) != address(account));
        assertTrue(factory.getAddress(PK_SEED, PK_ROOT, 1) != address(account));
    }

    function test_factory_rejectsZeroKey() public {
        vm.expectRevert("SphincsWotscAccountFactory: zero key");
        factory.getAddress(bytes32(0), PK_ROOT, 0);
        vm.expectRevert("SphincsWotscAccountFactory: zero key");
        factory.getAddress(PK_SEED, bytes32(0), 0);
    }

    /// @dev A non-canonical key would make verify() revert on every op, permanently bricking the
    ///      account. getAddress must refuse to even quote an address for one.
    function test_factory_rejectsNonCanonicalKey() public {
        bytes32 bad = bytes32(uint256(PK_SEED) | 1);
        vm.expectRevert("SphincsWotscAccountFactory: non-canonical key");
        factory.getAddress(bad, PK_ROOT, 0);
        vm.expectRevert("SphincsWotscAccountFactory: non-canonical key");
        factory.createAccount(PK_SEED, bytes32(uint256(PK_ROOT) | 1), 0);
    }

    function test_factory_wiring() public view {
        assertEq(address(factory.ENTRY_POINT()), ENTRYPOINT);
        assertEq(address(factory.VERIFIER()), address(verifier));
        assertTrue(factory.ACCOUNT_IMPL() != address(0));
    }

    /// @dev The factory, its implementation and the real verifier agree on the blob length.
    function test_sigLen_matchesVerifier() public {
        assertEq(factory.SIG_LEN(), _sigLen());
        assertEq(account.SIG_LEN(), _sigLen());
        (bool ok, bytes memory ret) = address(_newRealVerifier()).call(abi.encodeWithSignature("SIG_LEN()"));
        assertTrue(ok);
        assertEq(abi.decode(ret, (uint256)), _sigLen());
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
        SphincsWotscAccount impl = SphincsWotscAccount(payable(factory.ACCOUNT_IMPL()));
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(PK_SEED, PK_ROOT);
    }

    // =========================================================================
    // Signature validation (mock verifier)
    // =========================================================================

    function test_validate_acceptsValidSignature() public {
        verifier.setValid(true);
        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(_userOp(address(account), _execCalldata(), _blob(_sigLen())), keccak256("h"), 0);
        assertEq(r, 0);
    }

    function test_validate_rejectsBadSignature() public {
        verifier.setValid(false);
        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(_userOp(address(account), _execCalldata(), _blob(_sigLen())), keccak256("h"), 0);
        assertEq(r, SIG_VALIDATION_FAILED);
    }

    /// @dev Wrong length must FAIL, not revert — even with a verifier that would say yes. That
    ///      includes the other WOTS+C family's length and the standard family's.
    function test_validate_wrongLengthFailsWithoutReverting() public {
        verifier.setValid(true);
        uint256[5] memory lens = [_sigLen() - 1, _sigLen() + 1, _otherSigLen(), SPHINCS_STANDARD_SIG_LEN, 0];
        for (uint256 i = 0; i < lens.length; i++) {
            vm.prank(ENTRYPOINT);
            uint256 r = account.validateUserOp(_userOp(address(account), _execCalldata(), _blob(lens[i])), keccak256("h"), 0);
            assertEq(r, SIG_VALIDATION_FAILED);
        }
    }

    /// @dev callData carries no trailing key material, so empty callData must validate fine.
    function test_validate_noCallDataTailRequired() public {
        verifier.setValid(true);
        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(_userOp(address(account), "", _blob(_sigLen())), keccak256("h"), 0);
        assertEq(r, 0);
    }

    function test_validate_onlyFromEntryPoint() public {
        verifier.setValid(true);
        vm.expectRevert("SphincsWotscAccount: not from EntryPoint");
        account.validateUserOp(_userOp(address(account), _execCalldata(), _blob(_sigLen())), keccak256("h"), 0);
    }

    function test_validate_paysPrefund() public {
        verifier.setValid(true);
        uint256 before = ENTRYPOINT.balance;
        vm.prank(ENTRYPOINT);
        account.validateUserOp(_userOp(address(account), _execCalldata(), _blob(_sigLen())), keccak256("h"), 1 ether);
        assertEq(ENTRYPOINT.balance - before, 1 ether);
    }

    // =========================================================================
    // Signature validation (real verifier, signer vectors)
    // =========================================================================

    /// @dev End-to-end against the REAL verifier, with the vector's message standing in for the
    ///      userOpHash: the honest signature validates, a different hash, a flipped bit, garbage
    ///      and a wrong length all fail cleanly without reverting.
    function test_validate_realVerifierVector() public {
        (bytes32 vSeed, bytes32 vRoot, bytes32 message, bytes memory sig) = _vector(0);
        SphincsWotscAccountFactory f = _newFactory(entryPoint, _newRealVerifier());
        address a = f.createAccount(vSeed, vRoot, 0);

        vm.prank(ENTRYPOINT);
        assertEq(SphincsWotscAccount(payable(a)).validateUserOp(_userOp(a, _execCalldata(), sig), message, 0), 0);

        vm.prank(ENTRYPOINT);
        assertEq(
            SphincsWotscAccount(payable(a)).validateUserOp(_userOp(a, _execCalldata(), sig), keccak256("other"), 0),
            SIG_VALIDATION_FAILED
        );

        bytes memory tampered = bytes.concat(sig);
        tampered[_sigLen() / 2] ^= 0x01;
        vm.prank(ENTRYPOINT);
        assertEq(
            SphincsWotscAccount(payable(a)).validateUserOp(_userOp(a, _execCalldata(), tampered), message, 0),
            SIG_VALIDATION_FAILED
        );

        vm.prank(ENTRYPOINT);
        assertEq(
            SphincsWotscAccount(payable(a)).validateUserOp(_userOp(a, _execCalldata(), _blob(_sigLen())), message, 0),
            SIG_VALIDATION_FAILED
        );

        vm.prank(ENTRYPOINT);
        assertEq(
            SphincsWotscAccount(payable(a)).validateUserOp(_userOp(a, _execCalldata(), _blob(_otherSigLen())), message, 0),
            SIG_VALIDATION_FAILED
        );
    }

    /// @dev A valid signature under one key does not validate for an account holding another.
    function test_validate_realVerifierWrongKeyFails() public {
        (, , bytes32 message, bytes memory sig) = _vector(0);
        SphincsWotscAccountFactory f = _newFactory(entryPoint, _newRealVerifier());
        address a = f.createAccount(PK_SEED, PK_ROOT, 0);

        vm.prank(ENTRYPOINT);
        assertEq(
            SphincsWotscAccount(payable(a)).validateUserOp(_userOp(a, _execCalldata(), sig), message, 0),
            SIG_VALIDATION_FAILED
        );
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
        vm.expectRevert("SphincsWotscAccount: length mismatch");
        account.executeBatch(targets, values, datas);
    }

    function test_receivesEther() public {
        (bool ok,) = address(account).call{value: 1 ether}("");
        assertTrue(ok);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    function _vector(uint256 n) internal view returns (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) {
        string memory json = vm.readFile(
            string.concat(vm.projectRoot(), "/test/vectors/sphincs-", _vectorTag(), "-bench-", vm.toString(n), ".json")
        );
        pkSeed = vm.parseJsonBytes32(json, ".pkSeed");
        pkRoot = vm.parseJsonBytes32(json, ".pkRoot");
        message = vm.parseJsonBytes32(json, ".message");
        sig = vm.parseJsonBytes(json, ".signature");
    }

    function _blob(uint256 len) internal pure returns (bytes memory b) {
        b = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            b[i] = bytes1(uint8((i % 251) + 1));
        }
    }

    function _execCalldata() internal view returns (bytes memory) {
        return abi.encodeCall(SphincsWotscAccount.execute, (recipient, 0, ""));
    }

    function _userOp(address sender, bytes memory callData, bytes memory sig)
        internal
        pure
        returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: sender,
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

contract SphincsAccount_v5Test is SphincsWotscAccountTestBase {
    function _newFactory(IEntryPoint ep, ISphincsVerifier v) internal override returns (SphincsWotscAccountFactory) {
        return new SphincsAccountFactory_v5(ep, v);
    }

    function _newRealVerifier() internal override returns (ISphincsVerifier) {
        return ISphincsVerifier(address(new SphincsVerifier_v5()));
    }

    function _sigLen() internal pure override returns (uint256) {
        return SPHINCS_V5_SIG_LEN;
    }

    function _otherSigLen() internal pure override returns (uint256) {
        return SPHINCS_V6_SIG_LEN;
    }

    function _vectorTag() internal pure override returns (string memory) {
        return "v5";
    }

    function test_sigLen_isV5() public view {
        assertEq(factory.SIG_LEN(), 7740);
    }
}

contract SphincsAccount_v6Test is SphincsWotscAccountTestBase {
    function _newFactory(IEntryPoint ep, ISphincsVerifier v) internal override returns (SphincsWotscAccountFactory) {
        return new SphincsAccountFactory_v6(ep, v);
    }

    function _newRealVerifier() internal override returns (ISphincsVerifier) {
        return ISphincsVerifier(address(new SphincsVerifier_v6()));
    }

    function _sigLen() internal pure override returns (uint256) {
        return SPHINCS_V6_SIG_LEN;
    }

    function _otherSigLen() internal pure override returns (uint256) {
        return SPHINCS_V5_SIG_LEN;
    }

    function _vectorTag() internal pure override returns (string memory) {
        return "v6";
    }

    function test_sigLen_isV6() public view {
        assertEq(factory.SIG_LEN(), 6524);
    }
}
