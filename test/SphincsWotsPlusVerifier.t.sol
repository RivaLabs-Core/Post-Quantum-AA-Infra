// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {
    SphincsWotsPlusVerifier, SPHINCS_WOTSPLUS_SIG_LEN
} from "../src/Verifiers/SphincsWotsPlusVerifier.sol";
import {SPHINCS_SIG_LEN} from "../src/Verifiers/SphincsVerifier.sol";
import {FORS_SIG_LEN} from "../src/Verifiers/ForsVerifier.sol";

/// @dev Guard + structural tests for the standard-WOTS+ variant. As with the WOTS+C sibling there
///      is NO reference vector yet (no signer emits this parameter set), so nothing here asserts a
///      positive verification — only the reject paths, the length arithmetic, and the checksum
///      encoding are covered.
contract SphincsWotsPlusVerifierTest is Test {
    SphincsWotsPlusVerifier verifier;

    // n=16 h=20 d=4 a=7 k=29 w=4, l = len1 + len2 = 64 + 4
    uint256 constant N = 16;
    uint256 constant K = 29;
    uint256 constant A = 7;
    uint256 constant D = 4;
    uint256 constant SUBTREE_H = 5;
    uint256 constant LEN1 = 64;
    uint256 constant LEN2 = 4;
    uint256 constant W = 4;

    function setUp() public {
        verifier = new SphincsWotsPlusVerifier();
    }

    /// @dev The constant must equal the layout it claims: R + FORS secrets + FORS auth paths
    ///      + per-layer (WOTS chains + subtree auth). Crucially there is NO counter field.
    function test_sigLenMatchesLayout() public pure {
        uint256 expected =
            N * (1 + K + (K - 1) * A) + D * (N * (LEN1 + LEN2) + N * SUBTREE_H);
        assertEq(expected, SPHINCS_WOTSPLUS_SIG_LEN, "layout != constant");
        assertEq(SPHINCS_WOTSPLUS_SIG_LEN, 8288);
    }

    /// @dev It must be exactly 4 bytes/layer shorter than the WOTS+C variant would be at l=68:
    ///      the dropped grinding counter. (WOTS+C at l=64 is the deployed 8048.)
    function test_counterFieldIsAbsent() public pure {
        uint256 wotsCAtSameL = N * (1 + K + (K - 1) * A) + D * (N * (LEN1 + LEN2) + 4 + N * SUBTREE_H);
        assertEq(wotsCAtSameL - SPHINCS_WOTSPLUS_SIG_LEN, D * 4, "counter not dropped");
    }

    /// @dev len2 must be the standard WOTS+ checksum length, and 4 base-w digits must cover the
    ///      maximum checksum. If either fails the checksum silently truncates and the scheme breaks.
    function test_checksumEncodingIsSufficient() public pure {
        uint256 maxCsum = LEN1 * (W - 1);
        assertEq(maxCsum, 192);
        assertLt(maxCsum, W ** LEN2, "csum does not fit in len2 digits");
    }

    /// @dev Length-dispatch classes must stay mutually distinct.
    function test_lengthsAreDisjoint() public pure {
        assertTrue(SPHINCS_WOTSPLUS_SIG_LEN != FORS_SIG_LEN);
        assertTrue(SPHINCS_WOTSPLUS_SIG_LEN != SPHINCS_SIG_LEN);
        uint256 minEnvelope = 3 + FORS_SIG_LEN;
        assertTrue(
            SPHINCS_WOTSPLUS_SIG_LEN < minEnvelope || (SPHINCS_WOTSPLUS_SIG_LEN - minEnvelope) % 32 != 0,
            "collides with activation envelope set"
        );
    }

    function test_verify_wrongLength_reverts() public {
        bytes memory sig = new bytes(SPHINCS_WOTSPLUS_SIG_LEN - 1);
        vm.expectRevert("Invalid sig length");
        verifier.verify(bytes32(0), bytes32(0), bytes32(0), sig);
    }

    /// @dev The WOTS+C variant's blob length must NOT be accepted here.
    function test_verify_wotsCLength_reverts() public {
        bytes memory sig = new bytes(SPHINCS_SIG_LEN);
        vm.expectRevert("Invalid sig length");
        verifier.verify(bytes32(0), bytes32(0), bytes32(0), sig);
    }

    function test_verify_nonCanonicalPubkey_reverts() public {
        bytes memory sig = new bytes(SPHINCS_WOTSPLUS_SIG_LEN);
        vm.expectRevert("Invalid public key");
        verifier.verify(bytes32(uint256(1)), bytes32(0), bytes32(0), sig);
    }

    /// @dev A garbage signature must return false, not revert (uniform soundness contract).
    function testFuzz_verify_garbageReturnsFalse(bytes32 message, bytes32 rWord) public view {
        bytes memory sig = new bytes(SPHINCS_WOTSPLUS_SIG_LEN);
        bytes32 r = bytes32(uint256(rWord) & uint256(bytes32(hex"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000")));
        assembly {
            mstore(add(sig, 0x20), r)
        }
        assertFalse(verifier.verify(bytes32(0), bytes32(0), message, sig));
    }
}
