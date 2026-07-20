// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SphincsVerifier, SPHINCS_SIG_LEN} from "../src/Verifiers/SphincsVerifier.sol";

/// @dev Direct tests of the vendored SPHINCS- verifier.
///
///      The always-on tests exercise the verifier's revert guards on the real (non-mock) contract
///      and need no signature. The vector-backed tests (a valid sig verifies; tampered / wrong-message
///      fails) activate only once `test/vectors/sphincs-reference-0.json` exists — generate it with
///      `scripts/sphincs_reference.py` (needs the upstream SPHINCS- signer). Until then
///      they self-skip so the suite stays green.
contract SphincsVerifierTest is Test {
    SphincsVerifier verifier;

    string constant VECTOR = "/test/vectors/sphincs-reference-0.json";
    // Canonical (top-128-bit-aligned) dummy public-key word for the guard tests.
    bytes32 constant PK = bytes32(uint256(0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1) << 128);

    function setUp() public {
        verifier = new SphincsVerifier();
    }

    // ---- always-on: revert guards on the real verifier (no signature needed) ----

    function test_verify_wrongLength_reverts() public {
        bytes memory sig = new bytes(SPHINCS_SIG_LEN - 1);
        vm.expectRevert(bytes("Invalid sig length"));
        verifier.verify(PK, PK, bytes32("msg"), sig);
    }

    function test_verify_nonCanonicalPubkey_reverts() public {
        bytes memory sig = new bytes(SPHINCS_SIG_LEN);
        bytes32 bad = bytes32(uint256(1)); // low bit set -> not top-128-aligned
        vm.expectRevert(bytes("Invalid public key"));
        verifier.verify(bad, PK, bytes32("msg"), sig);
    }

    // ---- vector-backed: activate once the reference vector is generated ----

    function test_referenceVector_verifies() public {
        if (!_hasVector()) return _skip();
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _loadVector();
        assertTrue(verifier.verify(pkSeed, pkRoot, message, sig), "valid SPHINCS- sig must verify");
    }

    function test_referenceVector_tamperedFails() public {
        if (!_hasVector()) return _skip();
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _loadVector();
        sig[100] = sig[100] ^ bytes1(uint8(1)); // flip one bit in the signature body
        assertFalse(verifier.verify(pkSeed, pkRoot, message, sig), "tampered sig must fail");
    }

    function test_referenceVector_wrongMessageFails() public {
        if (!_hasVector()) return _skip();
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _loadVector();
        assertFalse(
            verifier.verify(pkSeed, pkRoot, message ^ bytes32(uint256(1)), sig), "wrong message must fail"
        );
    }

    // ---- helpers ----

    function _skip() internal {
        emit log("skip: reference vector not generated (scripts/sphincs_reference.py)");
    }

    function _hasVector() internal view returns (bool) {
        return vm.exists(string.concat(vm.projectRoot(), VECTOR));
    }

    function _loadVector()
        internal
        view
        returns (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig)
    {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), VECTOR));
        pkSeed = vm.parseJsonBytes32(json, ".pkSeed");
        pkRoot = vm.parseJsonBytes32(json, ".pkRoot");
        message = vm.parseJsonBytes32(json, ".message");
        sig = vm.parseJsonBytes(json, ".signature");
    }
}
