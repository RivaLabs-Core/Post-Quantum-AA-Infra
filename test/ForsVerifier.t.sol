// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {
    ForsVerifier,
    FORS_K,
    FORS_A,
    FORS_SIG_LEN,
    FORS_R_OFFSET,
    FORS_PKSEED_OFFSET,
    FORS_SECTION_OFFSET,
    FORS_TREE_LEN,
    FORS_COUNTER_OFFSET,
    FORS_DOM,
    FORS_TYPE_FORS_TREE,
    FORS_TYPE_FORS_ROOTS
} from "../src/Verifiers/ForsVerifier.sol";

/// @dev Test-only FORS+C signer. Mirrors ForsVerifier exactly: same ADRS
///      shapes, same hash inputs, same hash padding convention.
///
///      Memory budget per round-trip: ~25 × bytes16[64] = ~50 KB allocated
///      across derive() + sign(); tractable at K=26, A=5 (~2.4k keccaks).
///      For larger A this approach OOMs — the K=14, A=10 attempt died at
///      ~340k keccaks for that reason. K=26, A=5 stays well under.
library ForsSigner {
    uint256 internal constant TREE_NODES = 64; // bytes16[64] heap layout
    uint256 internal constant LEAVES_OFF = 32; // leaves at indices 32..63
    uint256 internal constant ROOT_IDX = 1; // root at index 1

    struct Key {
        bytes16 skSeed;
        bytes16 pkSeed;
        bytes16 pkRoot;
        address addr;
    }

    // ─────────────────────────── ADRS encoders ─────────────────────────

    function _adrsLeaf(uint256 t, uint256 mdT) private pure returns (bytes32) {
        // type=FORS_TREE, cp=0, ha = (t << A) | mdT
        return bytes32((FORS_TYPE_FORS_TREE << 96) | ((t << FORS_A) | mdT));
    }

    function _adrsNode(uint256 t, uint256 cp, uint256 idx) private pure returns (bytes32) {
        // type=FORS_TREE, cp=cp, ha = (t << (A-cp)) | idx
        return bytes32((FORS_TYPE_FORS_TREE << 96) | (cp << 32) | ((t << (FORS_A - cp)) | idx));
    }

    function _adrsRoots() private pure returns (bytes32) {
        return bytes32(FORS_TYPE_FORS_ROOTS << 96);
    }

    // ───────────────────── Hash primitives (match verifier) ────────────

    /// @dev PRF: keccak(pkSeed_padded || ADRS) trunc 16. Used for leaf-secret
    ///      derivation and the per-signature randomizer R.
    function _PRF(bytes16 seed, bytes32 adrs) private pure returns (bytes16) {
        // 32 + 32 = 64 bytes hashed (pkSeed_top16 || zero_16 || ADRS).
        return bytes16(keccak256(abi.encodePacked(seed, bytes16(0), adrs)));
    }

    /// @dev F: keccak(pkSeed || zero || ADRS || sk || zero) trunc 16. 96 B in.
    function _F(bytes16 pkSeed, bytes32 adrs, bytes16 sk) private pure returns (bytes16) {
        return bytes16(keccak256(abi.encodePacked(pkSeed, bytes16(0), adrs, sk, bytes16(0))));
    }

    /// @dev H: keccak(pkSeed || zero || ADRS || left || right_padded?) — 128 B.
    ///      Matches the verifier's mstore layout: pkSeed_padded_32 ‖ ADRS_32 ‖
    ///      left_padded_32 ‖ right_padded_32. left and right each occupy a
    ///      32-byte slot with the value in the top 16 and zeros in the bottom.
    function _H(bytes16 pkSeed, bytes32 adrs, bytes16 left, bytes16 right) private pure returns (bytes16) {
        return bytes16(keccak256(abi.encodePacked(pkSeed, bytes16(0), adrs, left, bytes16(0), right, bytes16(0))));
    }

    // ─────────────────────────── Tree builder ──────────────────────────

    /// @dev Build tree `t` into `tree`. Heap layout: leaves at 32..63, root at 1.
    function _buildTreeInto(bytes16 skSeed, bytes16 pkSeed, uint256 t, bytes16[TREE_NODES] memory tree) private pure {
        // Leaves: index 32..63, leaf l → tree[32 + l]
        uint256 nLeaves = uint256(1) << FORS_A; // 32
        for (uint256 l = 0; l < nLeaves; l++) {
            bytes32 adrs = _adrsLeaf(t, l);
            bytes16 sk = _PRF(skSeed, adrs);
            tree[LEAVES_OFF + l] = _F(pkSeed, adrs, sk);
        }
        // Internals: build bottom-up. Level h has 2^(A-h) nodes at
        // indices [2^(A-h), 2*2^(A-h)). Parent of node `idx` is `idx/2`.
        for (uint256 h = 1; h <= FORS_A; h++) {
            uint256 nodesAtLevel = uint256(1) << (FORS_A - h);
            uint256 levelStart = nodesAtLevel; // = 2^(A-h)
            for (uint256 p = 0; p < nodesAtLevel; p++) {
                uint256 idx = levelStart + p;
                bytes16 left = tree[idx * 2];
                bytes16 right = tree[idx * 2 + 1];
                tree[idx] = _H(pkSeed, _adrsNode(t, h, p), left, right);
            }
        }
    }

    // ─────────────────────────── Public API ───────────────────────────

    /// @dev Deterministic keypair derivation from `material`.
    function derive(bytes32 material) internal pure returns (Key memory k) {
        k.skSeed = bytes16(keccak256(abi.encodePacked(material, "sk")));
        k.pkSeed = bytes16(keccak256(abi.encodePacked(material, "pk")));

        // Build K-1 trees, harvest roots.
        uint256 KM1 = FORS_K - 1;
        bytes16[FORS_K - 1] memory roots;
        for (uint256 t = 0; t < KM1; t++) {
            bytes16[TREE_NODES] memory tree;
            _buildTreeInto(k.skSeed, k.pkSeed, t, tree);
            roots[t] = tree[ROOT_IDX];
        }

        // pkRoot = T_K(pkSeed, ADRS_FORS_ROOTS, root_0..root_{K-2}).
        // Hash input = pkSeed_padded(32) + ADRS(32) + (K-1)·32 with each root
        // padded to 32 bytes — total (K+1)*32 bytes, matching the verifier.
        bytes memory buf = new bytes((FORS_K + 1) * 32);
        // pkSeed_padded at [0..32)
        for (uint256 b = 0; b < 16; b++) {
            buf[b] = k.pkSeed[b];
        }
        // ADRS at [32..64)
        bytes32 adrsRoots = _adrsRoots();
        for (uint256 b = 0; b < 32; b++) {
            buf[32 + b] = adrsRoots[b];
        }
        // Roots padded at [64 + t*32 + 0..16)
        for (uint256 t = 0; t < KM1; t++) {
            bytes16 r = roots[t];
            uint256 off = 64 + t * 32;
            for (uint256 b = 0; b < 16; b++) {
                buf[off + b] = r[b];
            }
        }
        k.pkRoot = bytes16(keccak256(buf));

        // address = keccak(pkSeed_padded || pkRoot_padded)[12:32].
        k.addr = address(uint160(uint256(keccak256(abi.encodePacked(k.pkSeed, bytes16(0), k.pkRoot, bytes16(0))))));
    }

    /// @dev Sign `digest` with `k`. Produces a FORS_SIG_LEN blob that verifies
    ///      against `k.addr`. Grinds the counter to satisfy the FORS+C
    ///      zero-bit constraint.
    function sign(Key memory k, bytes32 digest) internal pure returns (bytes memory blob) {
        bytes16 R = bytes16(keccak256(abi.encodePacked(k.skSeed, "R", digest)));

        // Grind counter ~2^A attempts on average until bottom A bits of dVal
        // (read at position (K-1)·A) are zero.
        uint256 maskBits = (uint256(1) << FORS_A) - 1;
        uint256 shiftBits = (FORS_K - 1) * FORS_A;
        uint256 maxIter = uint256(1) << (FORS_A + 6); // 64× expected, ample
        bytes16 counter;
        bytes32 dVal;
        bool found;
        for (uint256 i = 0; i < maxIter; i++) {
            counter = bytes16(uint128(i));
            dVal = keccak256(
                abi.encodePacked(k.pkSeed, bytes16(0), R, bytes16(0), digest, bytes32(FORS_DOM), counter, bytes16(0))
            );
            if ((uint256(dVal) >> shiftBits) & maskBits == 0) {
                found = true;
                break;
            }
        }
        require(found, "ForsSigner: grind failed");

        blob = new bytes(FORS_SIG_LEN);
        // R at [0..16), pkSeed at [16..32)
        for (uint256 b = 0; b < 16; b++) {
            blob[b] = R[b];
        }
        for (uint256 b = 0; b < 16; b++) {
            blob[16 + b] = k.pkSeed[b];
        }

        // For each tree t in 0..K-2: extract sk for revealed leaf + auth path.
        uint256 KM1 = FORS_K - 1;
        for (uint256 t = 0; t < KM1; t++) {
            uint256 mdT = (uint256(dVal) >> (FORS_A * t)) & maskBits;

            // Rebuild this tree (we don't cache — keeps memory bounded).
            bytes16[TREE_NODES] memory tree;
            _buildTreeInto(k.skSeed, k.pkSeed, t, tree);

            uint256 treeOff = FORS_SECTION_OFFSET + t * FORS_TREE_LEN;

            // sk = PRF(skSeed, ADRS_leaf(t, mdT))
            bytes16 sk = _PRF(k.skSeed, _adrsLeaf(t, mdT));
            for (uint256 b = 0; b < 16; b++) {
                blob[treeOff + b] = sk[b];
            }

            // Auth path: walk up from leaf at index (32 + mdT), at each level
            // record the sibling, then move to the parent.
            uint256 idx = LEAVES_OFF + mdT;
            for (uint256 j = 0; j < FORS_A; j++) {
                bytes16 sib = tree[idx ^ 1];
                uint256 dst = treeOff + 16 + j * 16;
                for (uint256 b = 0; b < 16; b++) {
                    blob[dst + b] = sib[b];
                }
                idx >>= 1;
            }
        }

        // Counter at [COUNTER_OFFSET..COUNTER_OFFSET+16)
        for (uint256 b = 0; b < 16; b++) {
            blob[FORS_COUNTER_OFFSET + b] = counter[b];
        }
    }
}

/// @dev Gas-measurement harness for the FORS+C verifier.
contract ForsVerifierGasTest is Test {
    ForsVerifier verifier;

    function setUp() public {
        verifier = new ForsVerifier();
    }

    /// @dev Builds a 2336-byte blob with: random R, random pkSeed, random
    ///      tree contents, and a counter chosen so the bottom (K-1)·A bits
    ///      of dVal contain a zero in the K-th A-bit field. The verifier
    ///      will not find a sensible address in the result, but it will
    ///      execute the full tree-open path before producing one — which
    ///      is what we want to measure.
    function _craftGasBlob(bytes32 digest, bytes32 salt) internal pure returns (bytes memory blob) {
        bytes16 R = bytes16(keccak256(abi.encode("R", salt)));
        bytes16 pkSeed = bytes16(keccak256(abi.encode("pkSeed", salt)));

        // Grind in assembly using FMP-rooted scratch — Solidity's
        // abi.encodePacked would allocate 160 fresh bytes per iteration and
        // blow up memory expansion gas quadratically over ~1024 attempts.
        // We don't bump FMP; subsequent Solidity allocations reuse this
        // region. Memory-safe.
        uint256 counterWord;
        {
            uint256 R_w = uint256(uint128(R)) << 128;
            uint256 pkSeed_w = uint256(uint128(pkSeed)) << 128;
            uint256 dom = FORS_DOM;
            uint256 maskBits = (uint256(1) << FORS_A) - 1;
            uint256 shiftBits = (FORS_K - 1) * FORS_A;
            uint256 maxIter = uint256(1) << (FORS_A + 4); // 16× expected
            bool found;
            assembly ("memory-safe") {
                let scratch := mload(0x40)
                mstore(scratch, pkSeed_w)
                mstore(add(scratch, 0x20), R_w)
                mstore(add(scratch, 0x40), digest)
                mstore(add(scratch, 0x60), dom)
                for { let i := 0 } lt(i, maxIter) { i := add(i, 1) } {
                    let c := shl(128, i)
                    mstore(add(scratch, 0x80), c)
                    let dVal := keccak256(scratch, 0xa0)
                    if iszero(and(shr(shiftBits, dVal), maskBits)) {
                        counterWord := c
                        found := 1
                        break
                    }
                }
            }
            require(found, "could not grind counter");
        }
        bytes16 counter = bytes16(uint128(counterWord >> 128));

        blob = new bytes(FORS_SIG_LEN);
        // R at [0..16)
        for (uint256 i = 0; i < 16; i++) {
            blob[i] = R[i];
        }
        // pkSeed at [16..32)
        for (uint256 i = 0; i < 16; i++) {
            blob[16 + i] = pkSeed[i];
        }
        // Tree section: random fill — auth-path correctness is irrelevant
        // for gas; only the work the verifier performs matters.
        for (uint256 t = 0; t < FORS_K - 1; t++) {
            uint256 off = FORS_SECTION_OFFSET + t * FORS_TREE_LEN;
            bytes32 fill = keccak256(abi.encode("tree", salt, t));
            for (uint256 b = 0; b < FORS_TREE_LEN; b++) {
                blob[off + b] = fill[b % 32];
            }
        }
        // Counter at [COUNTER_OFFSET..COUNTER_OFFSET+16)
        for (uint256 i = 0; i < 16; i++) {
            blob[FORS_COUNTER_OFFSET + i] = counter[i];
        }
    }

    /// @dev Measures verification gas. Independent of whether the recovered
    ///      address is "valid" — the verifier does the same work either way.
    function test_gas_verify_oneShot() public view {
        bytes32 digest = keccak256("gas-one-shot");
        bytes memory blob = _craftGasBlob(digest, bytes32(uint256(0xFEED)));

        uint256 before = gasleft();
        verifier.recover(blob, digest);
        uint256 used = before - gasleft();

        console.log("ForsVerifier.recover one-shot gas:", used);
    }

    /// @dev Average across a few salts to smooth out call-frame noise.
    ///      FORS+C work is constant in K, A by construction (no per-leaf
    ///      branching), so the variance is tiny — but we report an avg
    ///      for symmetry with the WOTS+C suite.
    function test_gas_verify_average() public view {
        uint256 N = 5;
        uint256 totalGas;
        for (uint256 i = 0; i < N; i++) {
            bytes32 digest = keccak256(abi.encode("gas", i));
            bytes memory blob = _craftGasBlob(digest, bytes32(i));

            uint256 before = gasleft();
            verifier.recover(blob, digest);
            uint256 used = before - gasleft();

            totalGas += used;
        }
        console.log("ForsVerifier.recover avg gas (N=5):", totalGas / N);
    }

    /// @dev Sanity: bad-length blobs early-return cheaply.
    function test_gas_verify_badLength() public view {
        bytes memory blob = new bytes(FORS_SIG_LEN - 1);
        uint256 before = gasleft();
        verifier.recover(blob, keccak256("anything"));
        uint256 used = before - gasleft();
        console.log("ForsVerifier.recover bad-length gas:", used);
    }
}

/// @dev Round-trip tests using the in-Solidity ForsSigner library. First
///      tests in the suite that actually exercise ForsVerifier.recover() with
///      real signatures (the gas tests above use crafted blobs with random
///      tree contents).
contract ForsVerifierRoundTripTest is Test {
    using ForsSigner for ForsSigner.Key;

    ForsVerifier verifier;
    ForsSigner.Key k;

    function setUp() public {
        verifier = new ForsVerifier();
        k = ForsSigner.derive(bytes32(uint256(0xC0FFEE)));
    }

    // =========================================================================
    // Happy path
    // =========================================================================

    function test_signAndRecover_happyPath() public view {
        bytes32 digest = keccak256("hello world");
        bytes memory blob = ForsSigner.sign(k, digest);

        assertEq(blob.length, FORS_SIG_LEN);
        assertEq(verifier.recover(blob, digest), k.addr);
    }

    function test_signAndRecover_multipleMessagesSameKey() public view {
        for (uint256 i = 0; i < 3; i++) {
            bytes32 digest = keccak256(abi.encode("m", i));
            bytes memory blob = ForsSigner.sign(k, digest);
            assertEq(verifier.recover(blob, digest), k.addr);
        }
    }

    function test_derive_deterministic() public pure {
        ForsSigner.Key memory a = ForsSigner.derive(bytes32(uint256(42)));
        ForsSigner.Key memory b = ForsSigner.derive(bytes32(uint256(42)));
        assertEq(a.addr, b.addr);
        assertEq(a.pkRoot, b.pkRoot);
    }

    function test_derive_differentMaterialDifferentAddress() public pure {
        ForsSigner.Key memory a = ForsSigner.derive(bytes32(uint256(1)));
        ForsSigner.Key memory b = ForsSigner.derive(bytes32(uint256(2)));
        assertTrue(a.addr != b.addr);
    }

    // =========================================================================
    // Tamper detection
    // =========================================================================

    function test_recover_wrongDigest_returnsDifferentAddress() public view {
        bytes memory blob = ForsSigner.sign(k, keccak256("msg-1"));
        assertTrue(verifier.recover(blob, keccak256("different")) != k.addr);
    }

    function test_recover_tamperedR_returnsDifferentAddress() public view {
        bytes32 digest = keccak256("hello");
        bytes memory blob = ForsSigner.sign(k, digest);
        blob[0] ^= bytes1(uint8(0x01));
        assertTrue(verifier.recover(blob, digest) != k.addr);
    }

    function test_recover_tamperedPkSeed_returnsDifferentAddress() public view {
        bytes32 digest = keccak256("hello");
        bytes memory blob = ForsSigner.sign(k, digest);
        blob[16] ^= bytes1(uint8(0x01));
        assertTrue(verifier.recover(blob, digest) != k.addr);
    }

    function test_recover_tamperedSk_returnsDifferentAddress() public view {
        bytes32 digest = keccak256("hello");
        bytes memory blob = ForsSigner.sign(k, digest);
        blob[FORS_SECTION_OFFSET] ^= bytes1(uint8(0x01));
        assertTrue(verifier.recover(blob, digest) != k.addr);
    }

    function test_recover_tamperedAuthPath_returnsDifferentAddress() public view {
        bytes32 digest = keccak256("hello");
        bytes memory blob = ForsSigner.sign(k, digest);
        // First auth-path sibling lives at section + 16
        blob[FORS_SECTION_OFFSET + 16] ^= bytes1(uint8(0x01));
        assertTrue(verifier.recover(blob, digest) != k.addr);
    }

    function test_recover_tamperedCounter_returnsDifferentAddress() public view {
        bytes32 digest = keccak256("hello");
        bytes memory blob = ForsSigner.sign(k, digest);
        blob[FORS_COUNTER_OFFSET] ^= bytes1(uint8(0x01));
        // Tampering the counter almost certainly breaks the grinding check
        // → early-return address(0).
        address rec = verifier.recover(blob, digest);
        assertTrue(rec != k.addr);
    }
}
