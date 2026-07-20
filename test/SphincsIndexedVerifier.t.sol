// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SphincsIndexedVerifier, SPHINCS_INDEXED_SIG_LEN} from "../src/Verifiers/SphincsIndexedVerifier.sol";

/// @dev Structural / guard tests for the explicit-index SPHINCS- variant.
///
///      There is NO positive (happy-path) test: the verifier is meaningless without a matching
///      signer, and no reference vector exists yet (verifier-only delivery). These tests exercise
///      the always-on guards and the new explicit-index handling on the real contract, with no
///      signature material. Add vector-backed positive/tamper tests once the signer emits the
///      3720-byte format (see docs/sphincs-indexed-signing.md).
contract SphincsIndexedVerifierTest is Test {
    SphincsIndexedVerifier verifier;

    // Canonical (top-128-bit-aligned) dummy public-key word for the guard tests.
    bytes32 constant PK = bytes32(uint256(0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1) << 128);
    uint256 constant MAX_IDX = 0x3FFFFF; // 2^22 - 1

    function setUp() public {
        verifier = new SphincsIndexedVerifier();
    }

    function test_sigLenConstant() public pure {
        assertEq(SPHINCS_INDEXED_SIG_LEN, 3720);
        assertEq(SPHINCS_INDEXED_SIG_LEN, 3688 + 32);
    }

    // ---- reverts (structural / malformed inputs) ----

    function test_verify_wrongLength_reverts() public {
        bytes memory sig = new bytes(SPHINCS_INDEXED_SIG_LEN - 1);
        vm.expectRevert(bytes("Invalid sig length"));
        verifier.verify(PK, PK, bytes32("msg"), sig);
    }

    function test_verify_statelessLength_reverts() public {
        // The stateless SphincsVerifier length (3688) must be rejected by this variant.
        bytes memory sig = new bytes(3688);
        vm.expectRevert(bytes("Invalid sig length"));
        verifier.verify(PK, PK, bytes32("msg"), sig);
    }

    function test_verify_nonCanonicalPubkey_reverts() public {
        bytes memory sig = new bytes(SPHINCS_INDEXED_SIG_LEN);
        bytes32 bad = bytes32(uint256(1)); // low bit set -> not top-128-aligned
        vm.expectRevert(bytes("Invalid public key"));
        verifier.verify(bad, PK, bytes32("msg"), sig);
    }

    // ---- explicit index handling (returns false, never reverts) ----

    function test_verify_outOfRangeIndex_returnsFalse() public view {
        bytes memory sig = _sigWithIndex(MAX_IDX + 1); // 2^22, out of range
        assertFalse(verifier.verify(PK, PK, bytes32("msg"), sig), "out-of-range index must be rejected");
    }

    function test_verify_hugeIndex_returnsFalse() public view {
        bytes memory sig = _sigWithIndex(type(uint256).max);
        assertFalse(verifier.verify(PK, PK, bytes32("msg"), sig));
    }

    function test_verify_canonicalIndex_garbageSig_returnsFalse() public view {
        // A canonical index with an otherwise-zero signature is well-formed but invalid:
        // it passes length/pubkey/index guards and is rejected by the crypto (returns false).
        bytes memory sig = _sigWithIndex(0);
        assertFalse(verifier.verify(PK, PK, bytes32("msg"), sig));
    }

    function test_verify_maxCanonicalIndex_doesNotRevert() public view {
        // htIdx == 2^22-1 is the inclusive upper bound: it must pass the index guard (no revert)
        // and be rejected only by the crypto (false).
        bytes memory sig = _sigWithIndex(MAX_IDX);
        assertFalse(verifier.verify(PK, PK, bytes32("msg"), sig));
    }

    // ---- helper ----

    /// @dev Full-length (3720) zero blob with the trailing 32-byte index word set to `idx`.
    function _sigWithIndex(uint256 idx) internal pure returns (bytes memory sig) {
        sig = new bytes(SPHINCS_INDEXED_SIG_LEN);
        assembly {
            // data starts at sig+0x20; index word is at data offset 3688.
            mstore(add(add(sig, 0x20), 3688), idx)
        }
    }
}
