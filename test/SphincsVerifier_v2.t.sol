// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SphincsVerifier_v2, SPHINCS_V2_SIG_LEN} from "../src/Verifiers/SphincsVerifier_v2.sol";
import {SPHINCS_SIG_LEN} from "../src/Verifiers/SphincsVerifier.sol";
import {SPHINCS_STANDARD_SIG_LEN} from "../src/Verifiers/SphincsStandardVerifier.sol";
import {FORS_SIG_LEN} from "../src/Verifiers/ForsVerifier.sol";

/// @dev Layout, guard and reference-vector tests for SphincsVerifier_v2 (sphincs-g: standard FORS
///      under standard WOTS+, n=16 h=20 d=5 a=9 k=19 w=16). The positive vector is minted by
///      scripts/sphincs_v2_reference.py into test/vectors/sphincs-v2-reference-0.json.
contract SphincsVerifier_v2Test is Test {
    SphincsVerifier_v2 verifier;

    string constant VECTOR = "/test/vectors/sphincs-v2-reference-0.json";

    // n=16 h=20 d=5 a=9 k=19 w=16, l = len1 + len2 = 32 + 3
    uint256 constant N = 16;
    uint256 constant K = 19;
    uint256 constant A = 9;
    uint256 constant D = 5;
    uint256 constant SUBTREE_H = 4;
    uint256 constant LEN1 = 32;
    uint256 constant LEN2 = 3;
    uint256 constant W = 16;

    function setUp() public {
        verifier = new SphincsVerifier_v2();
    }

    function test_sigLenMatchesStandardLayout() public pure {
        uint256 expected = N * (1 + K + K * A) + D * (N * (LEN1 + LEN2) + N * SUBTREE_H);
        assertEq(expected, SPHINCS_V2_SIG_LEN, "layout != constant");
        assertEq(SPHINCS_V2_SIG_LEN, 6176);
    }

    function test_publicConstants() public view {
        assertEq(verifier.SIG_LEN(), SPHINCS_V2_SIG_LEN);
        assertEq(verifier.PARAMETER_SET(), "sphincs-g");
        assertEq(verifier.HMSG_INPUT_BYTES(), 32 + 3 * N + 32);
    }

    function test_hypertreeStartOffset() public pure {
        assertEq(N * (1 + K + K * A), 3056);
    }

    /// @dev FORS indices + hypertree index must fit in one keccak word.
    function test_digestBudget() public pure {
        assertLe(K * A + SUBTREE_H * D, 256);
    }

    /// @dev len1 digits must cover the 128-bit WOTS message; len2 must cover the maximum checksum.
    function test_wotsEncodingIsSufficient() public pure {
        assertEq(LEN1 * 4, 128);
        uint256 maxCsum = LEN1 * (W - 1);
        assertEq(maxCsum, 480);
        assertLt(maxCsum, W ** LEN2, "csum does not fit in len2 digits");
    }

    function test_lengthsAreDisjoint() public pure {
        assertTrue(SPHINCS_V2_SIG_LEN != FORS_SIG_LEN);
        assertTrue(SPHINCS_V2_SIG_LEN != SPHINCS_SIG_LEN);
        assertTrue(SPHINCS_V2_SIG_LEN != SPHINCS_STANDARD_SIG_LEN);
        uint256 minEnvelope = 3 + FORS_SIG_LEN;
        assertTrue(
            SPHINCS_V2_SIG_LEN < minEnvelope || (SPHINCS_V2_SIG_LEN - minEnvelope) % 32 != 0,
            "collides with activation envelope set"
        );
    }

    function test_verify_wrongLength_reverts() public {
        bytes memory sig = new bytes(SPHINCS_V2_SIG_LEN - 1);
        vm.expectRevert("Invalid sig length");
        verifier.verify(bytes32(0), bytes32(0), bytes32(0), sig);
    }

    function test_verify_otherVerifierLengths_revert() public {
        bytes memory a = new bytes(SPHINCS_SIG_LEN);
        vm.expectRevert("Invalid sig length");
        verifier.verify(bytes32(0), bytes32(0), bytes32(0), a);

        bytes memory b = new bytes(SPHINCS_STANDARD_SIG_LEN);
        vm.expectRevert("Invalid sig length");
        verifier.verify(bytes32(0), bytes32(0), bytes32(0), b);
    }

    function test_verify_nonCanonicalPubkey_reverts() public {
        bytes memory sig = new bytes(SPHINCS_V2_SIG_LEN);
        vm.expectRevert("Invalid public key");
        verifier.verify(bytes32(uint256(1)), bytes32(0), bytes32(0), sig);
    }

    function testFuzz_verify_garbageReturnsFalse(bytes32 message, bytes32 rWord) public view {
        bytes memory sig = new bytes(SPHINCS_V2_SIG_LEN);
        bytes32 r = bytes32(uint256(rWord) & uint256(bytes32(hex"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000")));
        assembly {
            mstore(add(sig, 0x20), r)
        }
        assertFalse(verifier.verify(bytes32(0), bytes32(0), message, sig));
    }

    // ------------------------------------------------------------ reference vector

    function _vector() internal view returns (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), VECTOR));
        pkSeed = vm.parseJsonBytes32(json, ".pkSeed");
        pkRoot = vm.parseJsonBytes32(json, ".pkRoot");
        message = vm.parseJsonBytes32(json, ".message");
        sig = vm.parseJsonBytes(json, ".signature");
    }

    function test_referenceVector_verifies() public view {
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _vector();
        assertEq(sig.length, SPHINCS_V2_SIG_LEN);
        assertTrue(verifier.verify(pkSeed, pkRoot, message, sig));
    }

    function test_referenceVector_wrongMessage_fails() public view {
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _vector();
        assertFalse(verifier.verify(pkSeed, pkRoot, bytes32(uint256(message) ^ 1), sig));
    }

    /// @dev Flipping any 16-byte element (R, a FORS secret, a FORS auth node, a WOTS chain, a
    ///      subtree auth node) must break verification.
    function testFuzz_referenceVector_tamper_fails(uint256 element) public view {
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _vector();
        uint256 off = bound(element, 0, SPHINCS_V2_SIG_LEN / N - 1) * N;
        sig[off] = bytes1(uint8(sig[off]) ^ 0x01);
        assertFalse(verifier.verify(pkSeed, pkRoot, message, sig));
    }

    function test_referenceVector_gas() public {
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _vector();
        uint256 g = gasleft();
        verifier.verify(pkSeed, pkRoot, message, sig);
        emit log_named_uint("verify gas", g - gasleft());
    }
}
