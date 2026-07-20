// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SphincsVerifier, SPHINCS_SIG_LEN} from "../src/Verifiers/SphincsVerifier.sol";
import {SphincsParamVerifier} from "../src/Verifiers/SphincsParamVerifier.sol";
import {SphincsParamsLib} from "../src/Verifiers/SphincsParamsLib.sol";

/// @dev Tests of the flexible (parametric) SPHINCS- verifier.
///
///      The correctness argument is DIFFERENTIAL: with the canonical parameter set the flexible
///      verifier must agree with the fixed `SphincsVerifier` (vendored upstream logic) on every
///      input — same bools, driven as deep as the inputs allow. The always-on tests need no
///      signature; the vector-backed ones activate once `test/vectors/sphincs-reference-0.json`
///      exists (see scripts/sphincs_reference.py) and self-skip until then.
contract SphincsParamVerifierTest is Test {
    SphincsVerifier fixedVerifier;
    SphincsParamVerifier flexVerifier;
    uint256 packedCanonical;

    string constant VECTOR = "/test/vectors/sphincs-reference-0.json";
    // Canonical (top-128-bit-aligned) dummy public-key words for the guard tests.
    bytes32 constant PK = bytes32(uint256(0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1) << 128);
    bytes32 constant N_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000;

    function setUp() public {
        fixedVerifier = new SphincsVerifier();
        flexVerifier = new SphincsParamVerifier();
        packedCanonical = SphincsParamsLib.pack(SphincsParamsLib.canonical());
    }

    // ---- always-on: input guards on the real verifier (no signature needed) ----

    function test_verify_wrongLength_reverts() public {
        bytes memory sig = new bytes(SPHINCS_SIG_LEN - 1);
        vm.expectRevert(bytes("Invalid sig length"));
        flexVerifier.verify(PK, PK, bytes32("msg"), packedCanonical, sig);
    }

    function test_verify_nonCanonicalPubkey_reverts() public {
        bytes memory sig = new bytes(SPHINCS_SIG_LEN);
        bytes32 bad = bytes32(uint256(1)); // low bit set -> not top-128-aligned
        vm.expectRevert(bytes("Invalid public key"));
        flexVerifier.verify(bad, PK, bytes32("msg"), packedCanonical, sig);
    }

    function test_verify_highBitsInPackedParams_reverts() public {
        bytes memory sig = new bytes(SPHINCS_SIG_LEN);
        vm.expectRevert(bytes("Invalid params"));
        flexVerifier.verify(PK, PK, bytes32("msg"), packedCanonical | (uint256(1) << 64), sig);
    }

    function test_verify_invalidParams_revert() public {
        bytes memory sig = new bytes(SPHINCS_SIG_LEN);
        vm.expectRevert(bytes("SphincsParams: zero param"));
        flexVerifier.verify(PK, PK, bytes32("msg"), 0, sig);
    }

    /// @dev Length is checked against the SUPPLIED params, not the canonical set: a valid set with
    ///      a different blob length must demand exactly that length.
    function test_verify_lengthFollowsParams() public {
        SphincsParamsLib.Params memory p =
            SphincsParamsLib.Params({h: 8, d: 1, k: 10, a: 12, logW: 4, l: 64, targetSum: 480});
        uint256 packed = SphincsParamsLib.pack(p);

        vm.expectRevert(bytes("Invalid sig length"));
        flexVerifier.verify(PK, PK, bytes32("msg"), packed, new bytes(SPHINCS_SIG_LEN));

        // Correct length for THIS set (3060) passes the guards and returns a bool.
        flexVerifier.verify(PK, PK, bytes32("msg"), packed, new bytes(3060));
    }

    // ---- always-on differential: flexible(canonical) ≡ fixed on guard-passing inputs ----

    /// @dev Zeroed signature body, fuzzed message/pk/R-word: both verifiers must return the same
    ///      bool (exercises H_msg, htIdx extraction and the forced-zero early return in lockstep;
    ///      inputs that survive forced-zero walk the full FORS + hypertree pipeline).
    function testFuzz_differential_zeroSig(bytes32 message, uint256 seedWord, uint256 rootWord, bytes32 rWord)
        public
        view
    {
        bytes32 pkSeed = bytes32(seedWord) & N_MASK;
        bytes32 pkRoot = bytes32(rootWord) & N_MASK;
        bytes memory sig = new bytes(SPHINCS_SIG_LEN);
        // Splice a fuzzed randomizer R into the first 16 bytes to vary the digest path.
        for (uint256 i = 0; i < 16; i++) {
            sig[i] = rWord[i];
        }

        bool fixedResult = fixedVerifier.verify(pkSeed, pkRoot, message, sig);
        bool flexResult = flexVerifier.verify(pkSeed, pkRoot, message, packedCanonical, sig);
        assertEq(flexResult, fixedResult, "flexible(canonical) must agree with fixed verifier");
    }

    /// @dev Always-on DEEP differential. GRIND_R was ground offline so that
    ///      H_msg(GRIND_SEED, GRIND_ROOT, GRIND_R, GRIND_MSG) passes the FORS+C forced-zero check
    ///      (digest bits [114,133) zero) — the digest ignores the signature body, so EVERY body
    ///      mutation below still walks the full FORS + compress + hypertree pipeline in both
    ///      verifiers instead of stopping at the forced-zero early return.
    function testFuzz_differential_deepPath(uint16 index, uint8 mask) public view {
        bytes memory sig = new bytes(SPHINCS_SIG_LEN);
        for (uint256 i = 0; i < 16; i++) {
            sig[i] = GRIND_R[i];
        }
        // Tamper one body byte (never the R prefix — that would re-roll the digest).
        uint256 at = 16 + (uint256(index) % (SPHINCS_SIG_LEN - 16));
        sig[at] = sig[at] ^ bytes1(mask);

        bool fixedResult = fixedVerifier.verify(GRIND_SEED, GRIND_ROOT, GRIND_MSG, sig);
        bool flexResult = flexVerifier.verify(GRIND_SEED, GRIND_ROOT, GRIND_MSG, packedCanonical, sig);
        assertEq(flexResult, fixedResult, "flexible(canonical) must agree with fixed verifier (deep path)");
    }

    bytes32 constant GRIND_SEED = bytes32(uint256(0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1) << 128);
    bytes32 constant GRIND_ROOT = bytes32(uint256(0xB2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2) << 128);
    bytes32 constant GRIND_MSG = keccak256("deep-differential");
    bytes32 constant GRIND_R = bytes32(uint256(0x91ac2) << 128);

    function test_grindRStillPassesForcedZero() public pure {
        // Re-derives the offline grind so the deep-path test can't silently go shallow.
        uint256 digest = uint256(
            keccak256(abi.encodePacked(GRIND_SEED, GRIND_ROOT, GRIND_R, GRIND_MSG, bytes32(type(uint256).max)))
        );
        assertEq((digest >> 114) & 0x7FFFF, 0, "grind R no longer passes the forced-zero check");
    }

    // ---- vector-backed: activate once the reference vector is generated ----

    function test_referenceVector_verifies() public {
        if (!_hasVector()) return _skip();
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _loadVector();
        assertTrue(
            flexVerifier.verify(pkSeed, pkRoot, message, packedCanonical, sig),
            "valid SPHINCS- sig must verify under canonical params"
        );
    }

    function test_referenceVector_tamperedFails() public {
        if (!_hasVector()) return _skip();
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _loadVector();
        sig[100] = sig[100] ^ bytes1(uint8(1));
        assertFalse(flexVerifier.verify(pkSeed, pkRoot, message, packedCanonical, sig), "tampered sig must fail");
    }

    function test_referenceVector_wrongMessageFails() public {
        if (!_hasVector()) return _skip();
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _loadVector();
        assertFalse(
            flexVerifier.verify(pkSeed, pkRoot, message ^ bytes32(uint256(1)), packedCanonical, sig),
            "wrong message must fail"
        );
    }

    /// @dev The strongest differential: single-byte tampering of a REAL signature drives both
    ///      verifiers deep into FORS/hypertree with occasionally-agreeing, occasionally-failing
    ///      paths — they must return identical bools on every mutation.
    function testFuzz_referenceVector_tamperDifferential(uint16 index, uint8 mask) public {
        if (!_hasVector()) return _skip();
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _loadVector();
        sig[index % sig.length] = sig[index % sig.length] ^ bytes1(mask);

        bool fixedResult = fixedVerifier.verify(pkSeed, pkRoot, message, sig);
        bool flexResult = flexVerifier.verify(pkSeed, pkRoot, message, packedCanonical, sig);
        assertEq(flexResult, fixedResult, "flexible(canonical) must agree with fixed verifier");
    }

    // ---- helpers (house pattern from SphincsVerifier.t.sol) ----

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
