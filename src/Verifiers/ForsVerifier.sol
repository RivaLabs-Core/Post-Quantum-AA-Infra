// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISignatureVerifier} from "../Interfaces/ISignatureVerifier.sol";

/*
 * Standalone FORS+C signature verifier (Keccak variant).
 *
 * FORS-only post-quantum few-time signature scheme using the same hash
 * primitives, ADRS layout, and 16-byte hash truncation as the FORS sub-
 * component of our SLH-DSA-Keccak-128-24 SphincsVerifier. No XMSS
 * hypertree above — the public key is the FORS roots compression alone.
 *
 * The +C variant (Hülsing–Kudinov–Ronen–Yogev, 2023; see also Kudinov–Nick
 * 2025-12-05 "Hash-based Signature Schemes for Bitcoin", §9.2) trims one
 * full FORS tree out of the signer's work and one full auth path out of
 * the signature, paid for by a per-signature grinding step:
 *
 *   - The signer iterates a 16-byte counter until the digest
 *         dVal = keccak(pkSeed ‖ R ‖ digest ‖ dom_FORS ‖ counter)
 *     has its highest A-bit field equal to zero (i.e. the K-th tree's
 *     index would be 0).
 *   - The K-th tree is then never computed, never opened, and never
 *     transmitted; the verifier just checks the zero-bit constraint and
 *     compresses K-1 real roots into pkRoot.
 *
 * Used as a primary signer (parallel to ECDSA / WOTS+C). Account-side
 * convention is to rotate the owner address on every signed UserOp,
 * matching WOTS+C semantics. Compared to WOTS+C the security degrades
 * gracefully on accidental key reuse instead of breaking immediately.
 *
 * Domain byte 0xFF..FD separates this scheme from spec SPHINCS+ and the
 * keccak-128-24 SLH-DSA family member.
 *
 * ─────────────────────────── Current selection: K=26, A=5 ─────────────
 *
 *  Signature size:  2,448 B
 *  Signer work:     ~2.4k keccak / signature
 *                   (≈ 2.4 ms on a laptop with hashlib-backed keccak;
 *                   ≈ 7 s on Ledger SE with software Keccak — usable!)
 *
 *  Security at q signatures (bits, classical):
 *      q=1: 128     q=2: 104     q=3: 89      q=4: 78      q=5: 70
 *
 *  q=1 is at the 128-bit NIST Level 1 ceiling (K·A = 130 just clears
 *  the hash-output cap). q-degradation is steep — reuse beyond q=2
 *  drops below Level 1. Justified by the rotation-per-UserOp model:
 *  the normal path is q=1, and the two-forest cache (see
 *  docs/fors-two-forest-cache.md) bounds the worst-case-reuse to a
 *  small budget (typically ≤ 2..3) for replacement / dropped-tx flows.
 *
 *  The signer-cost win over K=14, A=10 is ~17× (2^10 → 2^5 leaves per
 *  tree dominates), making this set viable on hardware wallets.
 *
 *  Full discussion of the scheme, parameter sweep, and rationale lives
 *  in docs/fors-parameters.md and docs/fors-two-forest-cache.md.
 *
 * ──────────────────────────────────────────────────────────────────────
 *
 * Measured verification cost at K=26, A=5: ~38.1k gas cold call,
 * ~34.1k gas warm call.
 */

// --- Primary parameters ---

uint256 constant FORS_N = 16; // hash truncation / node size
uint256 constant FORS_K = 26; // FORS trees (paper-style; only K-1 are real under +C)
uint256 constant FORS_A = 5; // FORS tree height; auth climb is unrolled below

// --- Derived: signature layout ---
//
// Layout (FORS+C):
//   [0      ..16   ) : R          (16 B, kept in top half of a 32-byte slot)
//   [16     ..32   ) : pkSeed     (16 B, ditto)
//   [32     ..2432 ) : (K-1)=25 trees, each (sk‖auth_path) of 16 + A·16 = 96 B
//   [2432   ..2448 ) : counter    (16 B, top half; bottom half is unused)
//
// The K-th tree's auth path is omitted entirely; the verifier knows
// mdT[K-1] = 0 from the grinding constraint and never opens that tree.

uint256 constant FORS_R_LEN = 16;
uint256 constant FORS_PKSEED_LEN = 16;
uint256 constant FORS_TREE_LEN = 16 + FORS_A * 16; // 96
uint256 constant FORS_SECTION_LEN = (FORS_K - 1) * FORS_TREE_LEN; // 2,400
uint256 constant FORS_COUNTER_LEN = 16;
uint256 constant FORS_SIG_LEN = FORS_R_LEN + FORS_PKSEED_LEN + FORS_SECTION_LEN + FORS_COUNTER_LEN; // 2,448

uint256 constant FORS_R_OFFSET = 0;
uint256 constant FORS_PKSEED_OFFSET = FORS_R_OFFSET + FORS_R_LEN; // 16
uint256 constant FORS_SECTION_OFFSET = FORS_PKSEED_OFFSET + FORS_PKSEED_LEN; // 32
uint256 constant FORS_COUNTER_OFFSET = FORS_SECTION_OFFSET + FORS_SECTION_LEN; // 2,432
uint256 constant FORS_ROOTS_HASH_LEN = (FORS_K + 1) * 32; // 864
uint256 constant FORS_SCRATCH_OFFSET = 0x380;

// The verifier below is intentionally specialized for the current gas target:
// A=5 is unrolled, and scratch memory must sit after the roots hash input.
uint256 constant FORS_A_UNROLL_GUARD = 1 / (FORS_A == 5 ? 1 : 0);
uint256 constant FORS_SCRATCH_ALIGN_GUARD = 1 / (FORS_SCRATCH_OFFSET % 64 == 0 ? 1 : 0);
uint256 constant FORS_SCRATCH_OVERLAP_GUARD = 1 / (FORS_SCRATCH_OFFSET >= FORS_ROOTS_HASH_LEN ? 1 : 0);

// --- Derived: bit ops ---

uint256 constant FORS_TOP_N_MASK = type(uint256).max << ((32 - FORS_N) * 8);

// Domain separation byte for Hmsg (32-byte big-endian, last byte = 0xFD).
uint256 constant FORS_DOM = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD;

// --- ADRS types (matches SPHINCS+ family) ---

uint256 constant FORS_TYPE_FORS_TREE = 3;
uint256 constant FORS_TYPE_FORS_ROOTS = 4;

/// @title ForsVerifier
/// @notice Standalone FORS+C verifier (Keccak primitive).
contract ForsVerifier is ISignatureVerifier {
    // --- Public parameters (ABI-readable) ---

    uint256 public constant N = FORS_N;
    uint256 public constant K = FORS_K;
    uint256 public constant A = FORS_A;
    uint256 public constant SIG_LEN = FORS_SIG_LEN;

    /// @inheritdoc ISignatureVerifier
    function recover(bytes calldata sig, bytes32 digest) external pure override returns (address) {
        // Hoist computed constants into locals — Solidity inline assembly
        // only accepts numeric literals or value-typed locals as operands.
        // The Merkle climb below is intentionally unrolled for A=5; changing
        // FORS_A requires updating that block, not only these locals.
        uint256 SIG_LEN_ = FORS_SIG_LEN;
        uint256 N_MASK = FORS_TOP_N_MASK;
        uint256 DOM = FORS_DOM;
        uint256 SECTION_OFF = FORS_SECTION_OFFSET;
        uint256 COUNTER_OFF = FORS_COUNTER_OFFSET;
        uint256 TREE_LEN_ = FORS_TREE_LEN; // 16 + A·16
        uint256 ROOTS_HASH_LEN = FORS_ROOTS_HASH_LEN; // pkSeed + ADRS + (K-1)·N

        // Parameter-derived loop bounds and bit masks:
        uint256 KMINUS1 = FORS_K - 1; // outer tree-open loop bound
        uint256 MD_MASK = (uint256(1) << FORS_A) - 1; // mdT mask = (1<<A) - 1
        uint256 KMINUS1_A = (FORS_K - 1) * FORS_A; // bit offset of the K-th mdT field in dVal

        if (sig.length != SIG_LEN_) return address(0);

        assembly ("memory-safe") {
            let sigBase := sig.offset

            // R, pkSeed, counter: each is 16 B kept in the top half of a
            // 32-byte word, with the next 16 B masked off.
            let R := and(calldataload(sigBase), N_MASK)
            let pkSeed := and(calldataload(add(sigBase, 16)), N_MASK)
            let counter := and(calldataload(add(sigBase, COUNTER_OFF)), N_MASK)

            // ─── Hmsg = keccak(pkSeed ‖ R ‖ digest ‖ dom_FORS ‖ counter) = 160 B ───
            mstore(0x00, pkSeed)
            mstore(0x20, R)
            mstore(0x40, digest)
            mstore(0x60, DOM)
            mstore(0x80, counter)
            let dVal := keccak256(0x00, 0xa0)

            // FORS+C grinding check: the K-th A-bit field of dVal (bits
            // (K-1)·A .. K·A-1) must be zero. If the signer didn't grind
            // to satisfy this, reject with address(0).
            if and(shr(KMINUS1_A, dVal), MD_MASK) {
                mstore(0x00, 0)
                return(0x00, 0x20)
            }

            // md[t] = (dVal >> (A·t)) & ((1<<A) - 1)   for t = 0..K-2
            // (LSB-first; (K-1) · A bits of dVal are consumed.)

            // Keep pkSeed at 0x00 for final compression/address. Tree hashes
            // use 0x40-aligned scratch after the K=26 roots buffer so roots
            // can be written directly at 0x40 + 32*t. If K grows past this
            // layout, move the scratch base before retuning.
            mstore(0x380, pkSeed)

            // ─── FORS tree verification (K-1 real trees) ───
            //   ADRS base for FORS at this standalone keypair:
            //   type=3 at FIPS 205 bytes 16..20, layer=tree=kp=0
            let forsBase := shl(96, 3)

            for {
                let t := 0
                let treePtr := add(sigBase, SECTION_OFF)
                let rootPtr := 0x40
                let tLeafBase := 0
                let dCursor := dVal
            } lt(t, KMINUS1) {
                t := add(t, 1)
                treePtr := add(treePtr, TREE_LEN_)
                rootPtr := add(rootPtr, 0x20)
                tLeafBase := add(tLeafBase, 0x20)
                dCursor := shr(5, dCursor)
            } {
                // mdT = (dVal >> (A·t)) & MD_MASK
                let mdT := and(dCursor, MD_MASK)
                let sk := and(calldataload(treePtr), N_MASK)

                // Leaf ADRS: cp=0, ha = (t << A) | mdT
                mstore(0x3a0, or(forsBase, or(tLeafBase, mdT)))
                mstore(0x3c0, sk)
                let node := and(keccak256(0x380, 0x60), N_MASK)

                // Climb the fixed A=5 auth-path. Scratch is 0x40-aligned so
                // xor(base, 0x20) swaps left/right without branching.
                let pathIdx := mdT

                {
                    let s := shl(5, and(pathIdx, 1))
                    pathIdx := shr(1, pathIdx)
                    let globalY := or(shl(4, t), pathIdx)
                    mstore(0x3a0, or(forsBase, or(0x100000000, globalY)))
                    mstore(xor(0x3c0, s), node)
                    mstore(xor(0x3e0, s), and(calldataload(add(treePtr, 16)), N_MASK))
                    node := and(keccak256(0x380, 0x80), N_MASK)
                }
                {
                    let s := shl(5, and(pathIdx, 1))
                    pathIdx := shr(1, pathIdx)
                    let globalY := or(shl(3, t), pathIdx)
                    mstore(0x3a0, or(forsBase, or(0x200000000, globalY)))
                    mstore(xor(0x3c0, s), node)
                    mstore(xor(0x3e0, s), and(calldataload(add(treePtr, 32)), N_MASK))
                    node := and(keccak256(0x380, 0x80), N_MASK)
                }
                {
                    let s := shl(5, and(pathIdx, 1))
                    pathIdx := shr(1, pathIdx)
                    let globalY := or(shl(2, t), pathIdx)
                    mstore(0x3a0, or(forsBase, or(0x300000000, globalY)))
                    mstore(xor(0x3c0, s), node)
                    mstore(xor(0x3e0, s), and(calldataload(add(treePtr, 48)), N_MASK))
                    node := and(keccak256(0x380, 0x80), N_MASK)
                }
                {
                    let s := shl(5, and(pathIdx, 1))
                    pathIdx := shr(1, pathIdx)
                    let globalY := or(shl(1, t), pathIdx)
                    mstore(0x3a0, or(forsBase, or(0x400000000, globalY)))
                    mstore(xor(0x3c0, s), node)
                    mstore(xor(0x3e0, s), and(calldataload(add(treePtr, 64)), N_MASK))
                    node := and(keccak256(0x380, 0x80), N_MASK)
                }
                {
                    let s := shl(5, and(pathIdx, 1))
                    pathIdx := shr(1, pathIdx)
                    let globalY := or(t, pathIdx)
                    mstore(0x3a0, or(forsBase, or(0x500000000, globalY)))
                    mstore(xor(0x3c0, s), node)
                    mstore(xor(0x3e0, s), and(calldataload(add(treePtr, 80)), N_MASK))
                    node := and(keccak256(0x380, 0x80), N_MASK)
                }
                mstore(rootPtr, node)
            }

            // ─── Compress K-1 FORS roots ───
            //   T(seed, ADRS_roots, root_0..root_{K-2}) over (K+1)·32 bytes
            mstore(0x20, shl(96, 4)) // type=FORS_ROOTS at bytes 16..20, kp=0
            let pkRoot := and(keccak256(0x00, ROOTS_HASH_LEN), N_MASK)

            // ─── Address = keccak256(pad32(pkSeed) || pad32(pkRoot))[12:32] ───
            // pkSeed is still at 0x00 from the Hmsg setup — no rewrite needed.
            mstore(0x20, pkRoot)
            let signer := and(keccak256(0x00, 0x40), 0x000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)

            mstore(0x00, signer)
            return(0x00, 0x20)
        }
    }
}
