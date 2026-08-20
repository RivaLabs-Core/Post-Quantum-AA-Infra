// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {
    SphincsStandardVerifier, SPHINCS_STANDARD_SIG_LEN
} from "../src/Verifiers/SphincsStandardVerifier.sol";
import {SPHINCS_SIG_LEN} from "../src/Verifiers/SphincsVerifier.sol";
import {FORS_SIG_LEN} from "../src/Verifiers/ForsVerifier.sol";

/// @dev Guard + layout tests for the fully-standard variant (standard FORS under standard WOTS+).
///      No reference vector is committed, so nothing here asserts a positive verification — only
///      reject paths, the length arithmetic, and the checksum encoding are covered.
contract SphincsStandardVerifierTest is Test {
    SphincsStandardVerifier verifier;

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
        verifier = new SphincsStandardVerifier();
    }

    /// @dev The constant must equal the standard layout: R + k secrets + k FULL auth paths
    ///      + per-layer (WOTS chains + subtree auth). No counter, no omitted auth path.
    function test_sigLenMatchesStandardLayout() public pure {
        uint256 expected = N * (1 + K + K * A) + D * (N * (LEN1 + LEN2) + N * SUBTREE_H);
        assertEq(expected, SPHINCS_STANDARD_SIG_LEN, "layout != constant");
        assertEq(SPHINCS_STANDARD_SIG_LEN, 8400);
    }

    /// @dev The FORS+C construction omits the last tree's auth path. The standard blob must be
    ///      exactly one auth path (a*n = 112 B) longer — this is the discrepancy that showed up
    ///      against the real signer.
    function test_isOneForsAuthPathLongerThanForsC() public pure {
        uint256 forsCVariant = N * (1 + K + (K - 1) * A) + D * (N * (LEN1 + LEN2) + N * SUBTREE_H);
        assertEq(SPHINCS_STANDARD_SIG_LEN - forsCVariant, A * N, "gap != one FORS auth path");
        assertEq(SPHINCS_STANDARD_SIG_LEN - forsCVariant, 112);
    }

    /// @dev HT_START must sit immediately after k full FORS auth paths.
    function test_hypertreeStartOffset() public pure {
        assertEq(N * (1 + K + K * A), 3728);
    }

    /// @dev len2 must cover the maximum checksum, else it silently truncates.
    function test_checksumEncodingIsSufficient() public pure {
        uint256 maxCsum = LEN1 * (W - 1);
        assertEq(maxCsum, 192);
        assertLt(maxCsum, W ** LEN2, "csum does not fit in len2 digits");
    }

    /// @dev Length-dispatch classes must stay mutually distinct.
    function test_lengthsAreDisjoint() public pure {
        assertTrue(SPHINCS_STANDARD_SIG_LEN != FORS_SIG_LEN);
        assertTrue(SPHINCS_STANDARD_SIG_LEN != SPHINCS_SIG_LEN);
        uint256 minEnvelope = 3 + FORS_SIG_LEN;
        assertTrue(
            SPHINCS_STANDARD_SIG_LEN < minEnvelope || (SPHINCS_STANDARD_SIG_LEN - minEnvelope) % 32 != 0,
            "collides with activation envelope set"
        );
    }

    function test_verify_wrongLength_reverts() public {
        bytes memory sig = new bytes(SPHINCS_STANDARD_SIG_LEN - 1);
        vm.expectRevert("Invalid sig length");
        verifier.verify(bytes32(0), bytes32(0), bytes32(0), sig);
    }

    /// @dev The FORS+C-based blob lengths must NOT be accepted here.
    function test_verify_forsCLengths_revert() public {
        bytes memory a = new bytes(SPHINCS_SIG_LEN); // 8048, FORS+C + WOTS+C
        vm.expectRevert("Invalid sig length");
        verifier.verify(bytes32(0), bytes32(0), bytes32(0), a);

        bytes memory b = new bytes(8288); // FORS+C + WOTS+, the superseded hybrid
        vm.expectRevert("Invalid sig length");
        verifier.verify(bytes32(0), bytes32(0), bytes32(0), b);
    }

    function test_verify_nonCanonicalPubkey_reverts() public {
        bytes memory sig = new bytes(SPHINCS_STANDARD_SIG_LEN);
        vm.expectRevert("Invalid public key");
        verifier.verify(bytes32(uint256(1)), bytes32(0), bytes32(0), sig);
    }

    /// @dev Garbage must return false, not revert. Note there is no forced-zero gate here, so
    ///      every call walks the full FORS forest and hypertree before failing the root compare.
    function testFuzz_verify_garbageReturnsFalse(bytes32 message, bytes32 rWord) public view {
        bytes memory sig = new bytes(SPHINCS_STANDARD_SIG_LEN);
        bytes32 r = bytes32(uint256(rWord) & uint256(bytes32(hex"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000")));
        assembly {
            mstore(add(sig, 0x20), r)
        }
        assertFalse(verifier.verify(bytes32(0), bytes32(0), message, sig));
    }
}
