// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SphincsVerifier_v5, SPHINCS_V5_SIG_LEN} from "../src/Verifiers/SphincsVerifier_v5.sol";
import {SPHINCS_V6_SIG_LEN} from "../src/Verifiers/SphincsVerifier_v6.sol";
import {SPHINCS_V2_SIG_LEN} from "../src/Verifiers/SphincsVerifier_v2.sol";
import {SPHINCS_SIG_LEN} from "../src/Verifiers/SphincsVerifier.sol";
import {SPHINCS_STANDARD_SIG_LEN} from "../src/Verifiers/SphincsStandardVerifier.sol";
import {FORS_SIG_LEN} from "../src/Verifiers/ForsVerifier.sol";

/// @dev Layout and guard tests for SphincsVerifier_v5 (standard FORS k=24 a=10 under WOTS+C w=4,
///      hypertree 8-8-10 from the bottom, n=16, compact tweakable hash). Positive vectors live in the
///      benchmark suite.
contract SphincsVerifier_v5Test is Test {
    SphincsVerifier_v5 verifier;

    uint256 constant N = 16;
    uint256 constant K = 24;
    uint256 constant A = 10;
    uint256 constant D = 3;
    uint256 constant H = 26;
    uint256 constant LEN = 64;
    uint256 constant W = 4;
    uint256 constant COUNT_BYTES = 4;

    function setUp() public {
        verifier = new SphincsVerifier_v5();
    }

    function test_sigLenMatchesLayout() public pure {
        // Subtree heights 8, 8, 10: the auth paths total H nodes.
        uint256 expected = N * (1 + K + K * A) + D * (N * LEN + COUNT_BYTES) + N * H;
        assertEq(expected, SPHINCS_V5_SIG_LEN, "layout != constant");
        assertEq(SPHINCS_V5_SIG_LEN, 7740);
    }

    function test_publicConstants() public view {
        assertEq(verifier.SIG_LEN(), SPHINCS_V5_SIG_LEN);
        assertEq(verifier.PARAMETER_SET(), "sphincs-wotsc-h26-8.8.10-w4-k24a10");
        assertEq(verifier.HMSG_INPUT_BYTES(), 32 + 3 * N + 32);
        assertEq(verifier.TARGET_SUM(), 120);
    }

    function test_hypertreeStartOffset() public pure {
        assertEq(N * (1 + K + K * A), 4240);
    }

    /// @dev FORS indices fill one keccak word on their own; the hypertree index needs the second hash.
    function test_digestBudget() public pure {
        assertLe(K * A, 256);
        assertGt(K * A + H, 256);
        assertLe(H, 256);
    }

    /// @dev len base-4 digits must cover the 128-bit WOTS message, and the target sum must lie
    ///      between the mean digit sum and the maximum; verifier work is len*(w-1) - target.
    function test_wotsEncoding() public view {
        assertEq(LEN * 2, 128);
        uint256 target = verifier.TARGET_SUM();
        assertGe(target, LEN * (W - 1) / 2);
        assertLt(target, LEN * (W - 1));
        assertEq(LEN * (W - 1) - target, 72, "chain hashes per layer");
    }

    function test_lengthsAreDisjoint() public pure {
        assertTrue(SPHINCS_V5_SIG_LEN != FORS_SIG_LEN);
        assertTrue(SPHINCS_V5_SIG_LEN != SPHINCS_SIG_LEN);
        assertTrue(SPHINCS_V5_SIG_LEN != SPHINCS_V2_SIG_LEN);
        assertTrue(SPHINCS_V5_SIG_LEN != SPHINCS_V6_SIG_LEN);
        assertTrue(SPHINCS_V5_SIG_LEN != SPHINCS_STANDARD_SIG_LEN);
        uint256 minEnvelope = 3 + FORS_SIG_LEN;
        assertTrue(
            SPHINCS_V5_SIG_LEN < minEnvelope || (SPHINCS_V5_SIG_LEN - minEnvelope) % 32 != 0,
            "collides with activation envelope set"
        );
    }

    function test_verify_wrongLength_reverts() public {
        bytes memory sig = new bytes(SPHINCS_V5_SIG_LEN - 1);
        vm.expectRevert("Invalid sig length");
        verifier.verify(bytes32(0), bytes32(0), bytes32(0), sig);
    }

    function test_verify_otherVerifierLengths_revert() public {
        uint256[4] memory lens = [SPHINCS_SIG_LEN, SPHINCS_V2_SIG_LEN, SPHINCS_V6_SIG_LEN, SPHINCS_STANDARD_SIG_LEN];
        for (uint256 i = 0; i < lens.length; i++) {
            bytes memory sig = new bytes(lens[i]);
            vm.expectRevert("Invalid sig length");
            verifier.verify(bytes32(0), bytes32(0), bytes32(0), sig);
        }
    }

    function test_verify_nonCanonicalPubkey_reverts() public {
        bytes memory sig = new bytes(SPHINCS_V5_SIG_LEN);
        vm.expectRevert("Invalid public key");
        verifier.verify(bytes32(uint256(1)), bytes32(0), bytes32(0), sig);
    }

    function testFuzz_verify_garbageReturnsFalse(bytes32 message, bytes32 rWord) public view {
        bytes memory sig = new bytes(SPHINCS_V5_SIG_LEN);
        bytes32 r = bytes32(uint256(rWord) & uint256(bytes32(hex"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000")));
        assembly {
            mstore(add(sig, 0x20), r)
        }
        assertFalse(verifier.verify(bytes32(0), bytes32(0), message, sig));
    }
}
