// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Signature length of the SphincsVerifier_v5 blob (no prefix). MUST equal `SIG_LEN` and the
///      length check in `SphincsVerifier_v5.verify` (7740). Distinct from `SPHINCS_SIG_LEN` (3688),
///      `SPHINCS_V2_SIG_LEN` (6176), `SPHINCS_V6_SIG_LEN` (6524), `SPHINCS_STANDARD_SIG_LEN` (8400)
///      and `FORS_SIG_LEN` (2448).
uint256 constant SPHINCS_V5_SIG_LEN = 7740;

/// @title SphincsVerifier_v5 — experimental SPHINCS- verifier, standard FORS under WOTS+C (w=4), compact hash
/// @notice n=16 h=26 d=3 (subtree heights 8, 8, 10 from the bottom; the top subtree is the tall
///         one) a=10 k=24 w=4 len=64, 7,740-byte signature, public key = (pkSeed, pkRoot). Standard
///         FORS (no +C grinding) under WOTS+C (no checksum chains; a per-layer counter is ground
///         until the digit sum hits TARGET_SUM). NOT standardized SLH-DSA. Same tweakable hash,
///         ADRS, H_msg and WOTS+C as `SphincsVerifier_v6`; FORS is k=24 a=10, the top subtree is
///         height 10 (fixed per key, so a signer can cache it), and the hypertree index comes from a
///         second hash because k*a + h = 266 bits exceeds one digest.
///
///         Tweakable hash (compact, NOT the FIPS 205 / sphincs-g 32-byte-slot form):
///           T(PK.seed, ADRS, v_1..v_m) = keccak256(PK.seed[16] ‖ ADRS[16] ‖ v_1[16] ‖ ... ‖ v_m[16])[:16]
///
///         Compressed ADRS, 16 bytes big-endian:
///           byte  0       layer address
///           bytes 1.. 9   tree address      (64 bits)
///           byte  9       type              (0 WOTS_HASH, 1 WOTS_PK, 2 TREE, 3 FORS_TREE, 4 FORS_ROOTS)
///           bytes 10..12  key_pair_address  (16 bits; 0 for TREE)
///           byte  12      word2             (chain_address / tree_height; 0 otherwise)
///           bytes 13..16  word3             (hash_address / tree_index, 24 bits; 0 otherwise)
///         FORS tree_index folds the k trees into one index space, (i << a) | leaf, as FIPS 205.
///
///         digest = H_msg = keccak256(0xFF..FF ‖ R ‖ PK.seed ‖ PK.root ‖ M), 112 bytes (as sphincs-g).
///         FORS indices are read LSB-first out of it, idx_i = (digest >> (i*a)) & (2^a - 1), using
///         bits [0, 240). The hypertree index is htIdx = keccak256(digest) & (2^26 - 1); bottom
///         layer leaf = htIdx & 0xFF, middle = (htIdx >> 8) & 0xFF, top = htIdx >> 16 (10 bits).
///
///         WOTS+C (per hypertree layer):
///           * d = keccak256(PK.seed[16] ‖ ADRS[16] ‖ node[16] ‖ count[4]), ADRS = WOTS_HASH for the
///             keypair with chain = hash = 0. count is the 4-byte big-endian value stored after the
///             64 chains.
///           * The 64 message digits are the top 128 bits of d, read MSB-first in base 4.
///           * The signature is valid only if SUM(digits) == TARGET_SUM = 120 (mean 96). Each chain
///             is then walked from `digit` up to w-1, so the verifier always does exactly
///             len*(w-1) - TARGET_SUM = 72 chain hashes per layer. The signer grinds ~830 counter
///             tries per layer; two digit vectors with the same sum can never dominate one another.
///
///         Signature budget: with 2^26 FORS instances of k=24 a=10, FORS stays at the 128-bit cap
///         up to about 2^30 signatures per key (~94 bits at 2^32). Not enforced on-chain.
///
///         Signature blob layout:
///           R(16) ‖ 24 x [ FORS sk (16) ‖ auth path (10*16) ]
///           ‖ 2 x [ 64 WOTS chains (16 each) ‖ count (4) ‖ subtree auth path (8*16) ]
///           ‖     [ 64 WOTS chains (16 each) ‖ count (4) ‖ top subtree auth path (10*16) ]
///           = 16 + 24*176 + 2*1156 + 1188 = 7740
///
/// @dev    Gas layout (as `SphincsVerifier_v6`). Word 0x00 holds PK.seed ‖ ADRS, so one mstore sets both; payloads
///         start at 0x20. Hash outputs are stored as full words and never masked: a value written
///         with mstore is either followed by a 16-byte calldatacopy over its low half or lies at the
///         end of the hashed window. The 64 chains of a layer are fully unrolled, each dispatched on
///         its digit through a 2-level switch. A chain that hashes sets the whole seed ‖ ADRS word
///         (chain and first hash address) in one store, later steps rewrite only the hash-address
///         byte (0x1f), and a chain whose digit is w-1 writes no ADRS at all. FORS (all 24 trees) and subtree auth paths are unrolled; tree_index at height z is
///         (leafIndex >> z). FORS roots and WOTS chain ends are written straight into a second
///         window at 0x80 (PK.seed ‖ ADRS, then 16-byte values) and compressed in place.
///
///         The unrolled fragments are generated; keep them in sync with the parameters above.
///
/// @dev    The assembly clobbers scratch/FMP memory and always returns directly to the caller:
///         do not mark it memory-safe or allow fall-through. UNAUDITED research prototype.
contract SphincsVerifier_v5 {
    string public constant PARAMETER_SET = "sphincs-wotsc-h26-8.8.10-w4-k24a10";
    uint256 public constant SIG_LEN = SPHINCS_V5_SIG_LEN;
    uint256 public constant HMSG_INPUT_BYTES = 112;
    uint256 public constant TARGET_SUM = 120;

    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external
        pure
        returns (bool)
    {
        require(sig.length == SPHINCS_V5_SIG_LEN, "Invalid sig length");
        require((uint256(pkSeed) & type(uint128).max) == 0 && (uint256(pkRoot) & type(uint128).max) == 0, "Invalid public key");

        assembly {
            let sigBase := sig.offset

            // Compact H_msg: ff32 || R16 || seed16 || root16 || message32.
            // Overlapping stores pack 112 bytes, without padding the 16-byte fields.
            mstore(0x00, not(0))
            mstore(0x20, calldataload(sigBase))
            mstore(0x30, pkSeed)
            mstore(0x40, pkRoot)
            mstore(0x50, message)
            let digest := keccak256(0x00, 0x70)

            // k*a + h = 266 > 256: FORS uses digest bits [0, 240), and the 26-bit hypertree index
            // comes from a second hash, htIdx = keccak256(digest) & (2^26 - 1).
            mstore(0x00, digest)
            let htIdx := and(keccak256(0x00, 0x20), 0x3FFFFFF)
            // seed ‖ FORS_TREE ADRS for layer 0: tree = htIdx >> 8 (shl 56), type 3 (shl 48),
            // kp = htIdx & 0xFF (shl 32). Per hash we OR in height (shl 24) and tree_index.
            // Built as one shifted term so the optimizer cannot split the type constant back out
            // into every FORS hash.
            let forsBase := or(pkSeed, shl(32, or(shl(24, shr(8, htIdx)), or(0x30000, and(htIdx, 0xFF)))))

            // ─── Standard FORS: 24 trees, each sk ‖ 10 auth nodes (176 bytes) ───
            // Fully unrolled over the 24 trees: tree i reads sk at sigBase + 16 + 176i, takes
            // idx_i = (digest >> 10i) & 0x3FF and writes its root at 0xA0 + 16i.
            {
                let leafIdx := and(digest, 0x3ff)
                let authPtr := add(sigBase, 32)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 16), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0xa0, node)
            }
            {
                let leafIdx := or(0x400, and(shr(10, digest), 0x3ff))
                let authPtr := add(sigBase, 208)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 192), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0xb0, node)
            }
            {
                let leafIdx := or(0x800, and(shr(20, digest), 0x3ff))
                let authPtr := add(sigBase, 384)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 368), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0xc0, node)
            }
            {
                let leafIdx := or(0xc00, and(shr(30, digest), 0x3ff))
                let authPtr := add(sigBase, 560)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 544), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0xd0, node)
            }
            {
                let leafIdx := or(0x1000, and(shr(40, digest), 0x3ff))
                let authPtr := add(sigBase, 736)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 720), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0xe0, node)
            }
            {
                let leafIdx := or(0x1400, and(shr(50, digest), 0x3ff))
                let authPtr := add(sigBase, 912)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 896), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0xf0, node)
            }
            {
                let leafIdx := or(0x1800, and(shr(60, digest), 0x3ff))
                let authPtr := add(sigBase, 1088)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 1072), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0x100, node)
            }
            {
                let leafIdx := or(0x1c00, and(shr(70, digest), 0x3ff))
                let authPtr := add(sigBase, 1264)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 1248), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0x110, node)
            }
            {
                let leafIdx := or(0x2000, and(shr(80, digest), 0x3ff))
                let authPtr := add(sigBase, 1440)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 1424), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0x120, node)
            }
            {
                let leafIdx := or(0x2400, and(shr(90, digest), 0x3ff))
                let authPtr := add(sigBase, 1616)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 1600), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0x130, node)
            }
            {
                let leafIdx := or(0x2800, and(shr(100, digest), 0x3ff))
                let authPtr := add(sigBase, 1792)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 1776), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0x140, node)
            }
            {
                let leafIdx := or(0x2c00, and(shr(110, digest), 0x3ff))
                let authPtr := add(sigBase, 1968)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 1952), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0x150, node)
            }
            {
                let leafIdx := or(0x3000, and(shr(120, digest), 0x3ff))
                let authPtr := add(sigBase, 2144)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 2128), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0x160, node)
            }
            {
                let leafIdx := or(0x3400, and(shr(130, digest), 0x3ff))
                let authPtr := add(sigBase, 2320)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 2304), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0x170, node)
            }
            {
                let leafIdx := or(0x3800, and(shr(140, digest), 0x3ff))
                let authPtr := add(sigBase, 2496)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 2480), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0x180, node)
            }
            {
                let leafIdx := or(0x3c00, and(shr(150, digest), 0x3ff))
                let authPtr := add(sigBase, 2672)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 2656), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0x190, node)
            }
            {
                let leafIdx := or(0x4000, and(shr(160, digest), 0x3ff))
                let authPtr := add(sigBase, 2848)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 2832), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0x1a0, node)
            }
            {
                let leafIdx := or(0x4400, and(shr(170, digest), 0x3ff))
                let authPtr := add(sigBase, 3024)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 3008), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0x1b0, node)
            }
            {
                let leafIdx := or(0x4800, and(shr(180, digest), 0x3ff))
                let authPtr := add(sigBase, 3200)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 3184), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0x1c0, node)
            }
            {
                let leafIdx := or(0x4c00, and(shr(190, digest), 0x3ff))
                let authPtr := add(sigBase, 3376)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 3360), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0x1d0, node)
            }
            {
                let leafIdx := or(0x5000, and(shr(200, digest), 0x3ff))
                let authPtr := add(sigBase, 3552)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 3536), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0x1e0, node)
            }
            {
                let leafIdx := or(0x5400, and(shr(210, digest), 0x3ff))
                let authPtr := add(sigBase, 3728)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 3712), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0x1f0, node)
            }
            {
                let leafIdx := or(0x5800, and(shr(220, digest), 0x3ff))
                let authPtr := add(sigBase, 3904)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 3888), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0x200, node)
            }
            {
                let leafIdx := or(0x5c00, and(shr(230, digest), 0x3ff))
                let authPtr := add(sigBase, 4080)
                mstore(0x00, or(forsBase, leafIdx))
                calldatacopy(0x20, add(sigBase, 4064), 16)
                let node := keccak256(0x00, 0x30)
                {
                    let s := and(shl(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x1000000, shr(1, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), authPtr, 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x2000000, shr(2, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x3000000, shr(3, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shl(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x4000000, shr(4, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(leafIdx, 0x10)
                    mstore(0x00, or(forsBase, or(0x5000000, shr(5, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(1, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x6000000, shr(6, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(2, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x7000000, shr(7, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(3, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x8000000, shr(8, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(4, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0x9000000, shr(9, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                    node := keccak256(0x00, 0x40)
                }
                {
                    let s := and(shr(5, leafIdx), 0x10)
                    mstore(0x00, or(forsBase, or(0xa000000, shr(10, leafIdx))))
                    mstore(add(0x20, s), node)
                    calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                    node := keccak256(0x00, 0x40)
                }
                mstore(0x210, node)
            }

            // Compress the 24 FORS roots in place: seed ‖ FORS_ROOTS ADRS ‖ 24 roots = 416 bytes.
            mstore(0x80, or(pkSeed, or(shl(56, shr(8, htIdx)), or(shl(48, 4), shl(32, and(htIdx, 0xFF))))))
            let currentNode := keccak256(0x80, 0x1A0)

            // ─── Hypertree: 3 layers of WOTS+C (64 chains) + subtree auth path (8, 8, 10 levels) ───
            let idxTree := htIdx
            let layerPtr := add(sigBase, 4240)
            for { let layer := 0 } lt(layer, 3) { layer := add(layer, 1) } {
                // The top layer's subtree is height 10: 10-bit leaf index, tree address 0.
                let isTop := eq(layer, 2)
                let idxLeaf := and(idxTree, or(0xFF, mul(isTop, 0x300)))
                idxTree := shr(add(8, shl(1, isTop)), idxTree)
                // seed ‖ (layer, tree) part of ADRS; type and kp are ORed in per use.
                let layerBase := or(pkSeed, or(shl(120, layer), shl(56, idxTree)))

                // WOTS+C digest: seed ‖ WOTS_HASH ADRS (chain = hash = 0) ‖ node ‖ count[4] = 52 bytes.
                let wotsBase := or(layerBase, shl(32, idxLeaf))
                mstore(0x00, wotsBase)
                mstore(0x20, currentNode)
                calldatacopy(0x30, add(layerPtr, 1024), 4)
                let d := keccak256(0x00, 0x34)

                // Digit sum of the 64 top base-4 digits (SWAR): 2-bit -> 4-bit -> 8-bit -> 16-bit
                // lanes, then one multiply folds the 8 lanes into bits [112, 128).
                {
                    let x := shr(128, d)
                    x := add(and(x, 0x33333333333333333333333333333333), and(shr(2, x), 0x33333333333333333333333333333333))
                    x := add(and(x, 0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F), and(shr(4, x), 0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F))
                    x := add(and(x, 0x00FF00FF00FF00FF00FF00FF00FF00FF), and(shr(8, x), 0x00FF00FF00FF00FF00FF00FF00FF00FF))
                    // A digit-sum mismatch is a well-formed-but-invalid signature: return false.
                    if iszero(eq(and(shr(112, mul(x, 0x00010001000100010001000100010001)), 0xFFFF), 120)) {
                        mstore(0x00, 0)
                        return(0x00, 0x20)
                    }
                }

                // 64 chains, fully unrolled. A chain that hashes sets seed ‖ WOTS_HASH ADRS in one
                // store on its first step (wotsBase | chain << 24 | hash); later steps rewrite only
                // hash_address (byte 0x1f). A chain whose digit is w-1 writes no ADRS at all.
                // Chain ends land at 0xA0 + 16j in ascending order, so each 32-byte store's low half
                // is overwritten by the next end.
                {
                    let digit := shr(254, d)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, layerPtr, 16)
                            mstore(0x00, or(wotsBase, 0x0))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0xa0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, layerPtr, 16)
                            mstore(0x00, or(wotsBase, 0x1))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0xa0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, layerPtr, 16)
                            mstore(0x00, or(wotsBase, 0x2))
                            mstore(0xa0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0xa0, layerPtr, 16)
                        }
                    }
                }
                {
                    let digit := and(shr(252, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 16), 16)
                            mstore(0x00, or(wotsBase, 0x1000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0xb0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 16), 16)
                            mstore(0x00, or(wotsBase, 0x1000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0xb0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 16), 16)
                            mstore(0x00, or(wotsBase, 0x1000002))
                            mstore(0xb0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0xb0, add(layerPtr, 16), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(250, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 32), 16)
                            mstore(0x00, or(wotsBase, 0x2000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0xc0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 32), 16)
                            mstore(0x00, or(wotsBase, 0x2000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0xc0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 32), 16)
                            mstore(0x00, or(wotsBase, 0x2000002))
                            mstore(0xc0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0xc0, add(layerPtr, 32), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(248, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 48), 16)
                            mstore(0x00, or(wotsBase, 0x3000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0xd0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 48), 16)
                            mstore(0x00, or(wotsBase, 0x3000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0xd0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 48), 16)
                            mstore(0x00, or(wotsBase, 0x3000002))
                            mstore(0xd0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0xd0, add(layerPtr, 48), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(246, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 64), 16)
                            mstore(0x00, or(wotsBase, 0x4000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0xe0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 64), 16)
                            mstore(0x00, or(wotsBase, 0x4000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0xe0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 64), 16)
                            mstore(0x00, or(wotsBase, 0x4000002))
                            mstore(0xe0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0xe0, add(layerPtr, 64), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(244, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 80), 16)
                            mstore(0x00, or(wotsBase, 0x5000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0xf0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 80), 16)
                            mstore(0x00, or(wotsBase, 0x5000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0xf0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 80), 16)
                            mstore(0x00, or(wotsBase, 0x5000002))
                            mstore(0xf0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0xf0, add(layerPtr, 80), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(242, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 96), 16)
                            mstore(0x00, or(wotsBase, 0x6000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x100, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 96), 16)
                            mstore(0x00, or(wotsBase, 0x6000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x100, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 96), 16)
                            mstore(0x00, or(wotsBase, 0x6000002))
                            mstore(0x100, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x100, add(layerPtr, 96), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(240, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 112), 16)
                            mstore(0x00, or(wotsBase, 0x7000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x110, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 112), 16)
                            mstore(0x00, or(wotsBase, 0x7000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x110, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 112), 16)
                            mstore(0x00, or(wotsBase, 0x7000002))
                            mstore(0x110, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x110, add(layerPtr, 112), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(238, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 128), 16)
                            mstore(0x00, or(wotsBase, 0x8000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x120, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 128), 16)
                            mstore(0x00, or(wotsBase, 0x8000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x120, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 128), 16)
                            mstore(0x00, or(wotsBase, 0x8000002))
                            mstore(0x120, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x120, add(layerPtr, 128), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(236, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 144), 16)
                            mstore(0x00, or(wotsBase, 0x9000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x130, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 144), 16)
                            mstore(0x00, or(wotsBase, 0x9000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x130, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 144), 16)
                            mstore(0x00, or(wotsBase, 0x9000002))
                            mstore(0x130, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x130, add(layerPtr, 144), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(234, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 160), 16)
                            mstore(0x00, or(wotsBase, 0xa000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x140, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 160), 16)
                            mstore(0x00, or(wotsBase, 0xa000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x140, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 160), 16)
                            mstore(0x00, or(wotsBase, 0xa000002))
                            mstore(0x140, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x140, add(layerPtr, 160), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(232, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 176), 16)
                            mstore(0x00, or(wotsBase, 0xb000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x150, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 176), 16)
                            mstore(0x00, or(wotsBase, 0xb000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x150, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 176), 16)
                            mstore(0x00, or(wotsBase, 0xb000002))
                            mstore(0x150, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x150, add(layerPtr, 176), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(230, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 192), 16)
                            mstore(0x00, or(wotsBase, 0xc000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x160, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 192), 16)
                            mstore(0x00, or(wotsBase, 0xc000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x160, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 192), 16)
                            mstore(0x00, or(wotsBase, 0xc000002))
                            mstore(0x160, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x160, add(layerPtr, 192), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(228, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 208), 16)
                            mstore(0x00, or(wotsBase, 0xd000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x170, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 208), 16)
                            mstore(0x00, or(wotsBase, 0xd000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x170, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 208), 16)
                            mstore(0x00, or(wotsBase, 0xd000002))
                            mstore(0x170, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x170, add(layerPtr, 208), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(226, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 224), 16)
                            mstore(0x00, or(wotsBase, 0xe000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x180, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 224), 16)
                            mstore(0x00, or(wotsBase, 0xe000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x180, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 224), 16)
                            mstore(0x00, or(wotsBase, 0xe000002))
                            mstore(0x180, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x180, add(layerPtr, 224), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(224, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 240), 16)
                            mstore(0x00, or(wotsBase, 0xf000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x190, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 240), 16)
                            mstore(0x00, or(wotsBase, 0xf000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x190, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 240), 16)
                            mstore(0x00, or(wotsBase, 0xf000002))
                            mstore(0x190, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x190, add(layerPtr, 240), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(222, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 256), 16)
                            mstore(0x00, or(wotsBase, 0x10000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x1a0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 256), 16)
                            mstore(0x00, or(wotsBase, 0x10000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x1a0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 256), 16)
                            mstore(0x00, or(wotsBase, 0x10000002))
                            mstore(0x1a0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x1a0, add(layerPtr, 256), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(220, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 272), 16)
                            mstore(0x00, or(wotsBase, 0x11000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x1b0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 272), 16)
                            mstore(0x00, or(wotsBase, 0x11000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x1b0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 272), 16)
                            mstore(0x00, or(wotsBase, 0x11000002))
                            mstore(0x1b0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x1b0, add(layerPtr, 272), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(218, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 288), 16)
                            mstore(0x00, or(wotsBase, 0x12000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x1c0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 288), 16)
                            mstore(0x00, or(wotsBase, 0x12000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x1c0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 288), 16)
                            mstore(0x00, or(wotsBase, 0x12000002))
                            mstore(0x1c0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x1c0, add(layerPtr, 288), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(216, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 304), 16)
                            mstore(0x00, or(wotsBase, 0x13000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x1d0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 304), 16)
                            mstore(0x00, or(wotsBase, 0x13000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x1d0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 304), 16)
                            mstore(0x00, or(wotsBase, 0x13000002))
                            mstore(0x1d0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x1d0, add(layerPtr, 304), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(214, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 320), 16)
                            mstore(0x00, or(wotsBase, 0x14000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x1e0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 320), 16)
                            mstore(0x00, or(wotsBase, 0x14000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x1e0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 320), 16)
                            mstore(0x00, or(wotsBase, 0x14000002))
                            mstore(0x1e0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x1e0, add(layerPtr, 320), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(212, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 336), 16)
                            mstore(0x00, or(wotsBase, 0x15000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x1f0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 336), 16)
                            mstore(0x00, or(wotsBase, 0x15000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x1f0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 336), 16)
                            mstore(0x00, or(wotsBase, 0x15000002))
                            mstore(0x1f0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x1f0, add(layerPtr, 336), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(210, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 352), 16)
                            mstore(0x00, or(wotsBase, 0x16000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x200, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 352), 16)
                            mstore(0x00, or(wotsBase, 0x16000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x200, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 352), 16)
                            mstore(0x00, or(wotsBase, 0x16000002))
                            mstore(0x200, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x200, add(layerPtr, 352), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(208, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 368), 16)
                            mstore(0x00, or(wotsBase, 0x17000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x210, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 368), 16)
                            mstore(0x00, or(wotsBase, 0x17000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x210, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 368), 16)
                            mstore(0x00, or(wotsBase, 0x17000002))
                            mstore(0x210, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x210, add(layerPtr, 368), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(206, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 384), 16)
                            mstore(0x00, or(wotsBase, 0x18000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x220, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 384), 16)
                            mstore(0x00, or(wotsBase, 0x18000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x220, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 384), 16)
                            mstore(0x00, or(wotsBase, 0x18000002))
                            mstore(0x220, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x220, add(layerPtr, 384), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(204, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 400), 16)
                            mstore(0x00, or(wotsBase, 0x19000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x230, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 400), 16)
                            mstore(0x00, or(wotsBase, 0x19000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x230, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 400), 16)
                            mstore(0x00, or(wotsBase, 0x19000002))
                            mstore(0x230, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x230, add(layerPtr, 400), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(202, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 416), 16)
                            mstore(0x00, or(wotsBase, 0x1a000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x240, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 416), 16)
                            mstore(0x00, or(wotsBase, 0x1a000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x240, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 416), 16)
                            mstore(0x00, or(wotsBase, 0x1a000002))
                            mstore(0x240, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x240, add(layerPtr, 416), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(200, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 432), 16)
                            mstore(0x00, or(wotsBase, 0x1b000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x250, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 432), 16)
                            mstore(0x00, or(wotsBase, 0x1b000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x250, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 432), 16)
                            mstore(0x00, or(wotsBase, 0x1b000002))
                            mstore(0x250, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x250, add(layerPtr, 432), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(198, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 448), 16)
                            mstore(0x00, or(wotsBase, 0x1c000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x260, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 448), 16)
                            mstore(0x00, or(wotsBase, 0x1c000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x260, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 448), 16)
                            mstore(0x00, or(wotsBase, 0x1c000002))
                            mstore(0x260, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x260, add(layerPtr, 448), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(196, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 464), 16)
                            mstore(0x00, or(wotsBase, 0x1d000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x270, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 464), 16)
                            mstore(0x00, or(wotsBase, 0x1d000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x270, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 464), 16)
                            mstore(0x00, or(wotsBase, 0x1d000002))
                            mstore(0x270, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x270, add(layerPtr, 464), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(194, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 480), 16)
                            mstore(0x00, or(wotsBase, 0x1e000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x280, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 480), 16)
                            mstore(0x00, or(wotsBase, 0x1e000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x280, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 480), 16)
                            mstore(0x00, or(wotsBase, 0x1e000002))
                            mstore(0x280, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x280, add(layerPtr, 480), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(192, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 496), 16)
                            mstore(0x00, or(wotsBase, 0x1f000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x290, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 496), 16)
                            mstore(0x00, or(wotsBase, 0x1f000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x290, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 496), 16)
                            mstore(0x00, or(wotsBase, 0x1f000002))
                            mstore(0x290, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x290, add(layerPtr, 496), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(190, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 512), 16)
                            mstore(0x00, or(wotsBase, 0x20000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x2a0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 512), 16)
                            mstore(0x00, or(wotsBase, 0x20000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x2a0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 512), 16)
                            mstore(0x00, or(wotsBase, 0x20000002))
                            mstore(0x2a0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x2a0, add(layerPtr, 512), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(188, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 528), 16)
                            mstore(0x00, or(wotsBase, 0x21000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x2b0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 528), 16)
                            mstore(0x00, or(wotsBase, 0x21000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x2b0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 528), 16)
                            mstore(0x00, or(wotsBase, 0x21000002))
                            mstore(0x2b0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x2b0, add(layerPtr, 528), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(186, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 544), 16)
                            mstore(0x00, or(wotsBase, 0x22000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x2c0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 544), 16)
                            mstore(0x00, or(wotsBase, 0x22000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x2c0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 544), 16)
                            mstore(0x00, or(wotsBase, 0x22000002))
                            mstore(0x2c0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x2c0, add(layerPtr, 544), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(184, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 560), 16)
                            mstore(0x00, or(wotsBase, 0x23000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x2d0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 560), 16)
                            mstore(0x00, or(wotsBase, 0x23000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x2d0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 560), 16)
                            mstore(0x00, or(wotsBase, 0x23000002))
                            mstore(0x2d0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x2d0, add(layerPtr, 560), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(182, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 576), 16)
                            mstore(0x00, or(wotsBase, 0x24000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x2e0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 576), 16)
                            mstore(0x00, or(wotsBase, 0x24000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x2e0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 576), 16)
                            mstore(0x00, or(wotsBase, 0x24000002))
                            mstore(0x2e0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x2e0, add(layerPtr, 576), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(180, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 592), 16)
                            mstore(0x00, or(wotsBase, 0x25000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x2f0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 592), 16)
                            mstore(0x00, or(wotsBase, 0x25000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x2f0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 592), 16)
                            mstore(0x00, or(wotsBase, 0x25000002))
                            mstore(0x2f0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x2f0, add(layerPtr, 592), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(178, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 608), 16)
                            mstore(0x00, or(wotsBase, 0x26000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x300, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 608), 16)
                            mstore(0x00, or(wotsBase, 0x26000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x300, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 608), 16)
                            mstore(0x00, or(wotsBase, 0x26000002))
                            mstore(0x300, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x300, add(layerPtr, 608), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(176, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 624), 16)
                            mstore(0x00, or(wotsBase, 0x27000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x310, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 624), 16)
                            mstore(0x00, or(wotsBase, 0x27000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x310, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 624), 16)
                            mstore(0x00, or(wotsBase, 0x27000002))
                            mstore(0x310, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x310, add(layerPtr, 624), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(174, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 640), 16)
                            mstore(0x00, or(wotsBase, 0x28000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x320, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 640), 16)
                            mstore(0x00, or(wotsBase, 0x28000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x320, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 640), 16)
                            mstore(0x00, or(wotsBase, 0x28000002))
                            mstore(0x320, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x320, add(layerPtr, 640), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(172, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 656), 16)
                            mstore(0x00, or(wotsBase, 0x29000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x330, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 656), 16)
                            mstore(0x00, or(wotsBase, 0x29000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x330, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 656), 16)
                            mstore(0x00, or(wotsBase, 0x29000002))
                            mstore(0x330, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x330, add(layerPtr, 656), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(170, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 672), 16)
                            mstore(0x00, or(wotsBase, 0x2a000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x340, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 672), 16)
                            mstore(0x00, or(wotsBase, 0x2a000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x340, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 672), 16)
                            mstore(0x00, or(wotsBase, 0x2a000002))
                            mstore(0x340, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x340, add(layerPtr, 672), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(168, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 688), 16)
                            mstore(0x00, or(wotsBase, 0x2b000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x350, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 688), 16)
                            mstore(0x00, or(wotsBase, 0x2b000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x350, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 688), 16)
                            mstore(0x00, or(wotsBase, 0x2b000002))
                            mstore(0x350, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x350, add(layerPtr, 688), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(166, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 704), 16)
                            mstore(0x00, or(wotsBase, 0x2c000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x360, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 704), 16)
                            mstore(0x00, or(wotsBase, 0x2c000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x360, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 704), 16)
                            mstore(0x00, or(wotsBase, 0x2c000002))
                            mstore(0x360, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x360, add(layerPtr, 704), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(164, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 720), 16)
                            mstore(0x00, or(wotsBase, 0x2d000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x370, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 720), 16)
                            mstore(0x00, or(wotsBase, 0x2d000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x370, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 720), 16)
                            mstore(0x00, or(wotsBase, 0x2d000002))
                            mstore(0x370, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x370, add(layerPtr, 720), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(162, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 736), 16)
                            mstore(0x00, or(wotsBase, 0x2e000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x380, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 736), 16)
                            mstore(0x00, or(wotsBase, 0x2e000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x380, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 736), 16)
                            mstore(0x00, or(wotsBase, 0x2e000002))
                            mstore(0x380, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x380, add(layerPtr, 736), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(160, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 752), 16)
                            mstore(0x00, or(wotsBase, 0x2f000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x390, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 752), 16)
                            mstore(0x00, or(wotsBase, 0x2f000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x390, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 752), 16)
                            mstore(0x00, or(wotsBase, 0x2f000002))
                            mstore(0x390, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x390, add(layerPtr, 752), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(158, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 768), 16)
                            mstore(0x00, or(wotsBase, 0x30000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x3a0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 768), 16)
                            mstore(0x00, or(wotsBase, 0x30000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x3a0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 768), 16)
                            mstore(0x00, or(wotsBase, 0x30000002))
                            mstore(0x3a0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x3a0, add(layerPtr, 768), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(156, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 784), 16)
                            mstore(0x00, or(wotsBase, 0x31000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x3b0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 784), 16)
                            mstore(0x00, or(wotsBase, 0x31000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x3b0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 784), 16)
                            mstore(0x00, or(wotsBase, 0x31000002))
                            mstore(0x3b0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x3b0, add(layerPtr, 784), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(154, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 800), 16)
                            mstore(0x00, or(wotsBase, 0x32000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x3c0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 800), 16)
                            mstore(0x00, or(wotsBase, 0x32000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x3c0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 800), 16)
                            mstore(0x00, or(wotsBase, 0x32000002))
                            mstore(0x3c0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x3c0, add(layerPtr, 800), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(152, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 816), 16)
                            mstore(0x00, or(wotsBase, 0x33000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x3d0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 816), 16)
                            mstore(0x00, or(wotsBase, 0x33000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x3d0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 816), 16)
                            mstore(0x00, or(wotsBase, 0x33000002))
                            mstore(0x3d0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x3d0, add(layerPtr, 816), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(150, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 832), 16)
                            mstore(0x00, or(wotsBase, 0x34000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x3e0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 832), 16)
                            mstore(0x00, or(wotsBase, 0x34000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x3e0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 832), 16)
                            mstore(0x00, or(wotsBase, 0x34000002))
                            mstore(0x3e0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x3e0, add(layerPtr, 832), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(148, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 848), 16)
                            mstore(0x00, or(wotsBase, 0x35000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x3f0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 848), 16)
                            mstore(0x00, or(wotsBase, 0x35000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x3f0, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 848), 16)
                            mstore(0x00, or(wotsBase, 0x35000002))
                            mstore(0x3f0, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x3f0, add(layerPtr, 848), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(146, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 864), 16)
                            mstore(0x00, or(wotsBase, 0x36000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x400, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 864), 16)
                            mstore(0x00, or(wotsBase, 0x36000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x400, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 864), 16)
                            mstore(0x00, or(wotsBase, 0x36000002))
                            mstore(0x400, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x400, add(layerPtr, 864), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(144, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 880), 16)
                            mstore(0x00, or(wotsBase, 0x37000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x410, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 880), 16)
                            mstore(0x00, or(wotsBase, 0x37000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x410, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 880), 16)
                            mstore(0x00, or(wotsBase, 0x37000002))
                            mstore(0x410, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x410, add(layerPtr, 880), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(142, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 896), 16)
                            mstore(0x00, or(wotsBase, 0x38000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x420, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 896), 16)
                            mstore(0x00, or(wotsBase, 0x38000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x420, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 896), 16)
                            mstore(0x00, or(wotsBase, 0x38000002))
                            mstore(0x420, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x420, add(layerPtr, 896), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(140, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 912), 16)
                            mstore(0x00, or(wotsBase, 0x39000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x430, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 912), 16)
                            mstore(0x00, or(wotsBase, 0x39000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x430, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 912), 16)
                            mstore(0x00, or(wotsBase, 0x39000002))
                            mstore(0x430, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x430, add(layerPtr, 912), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(138, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 928), 16)
                            mstore(0x00, or(wotsBase, 0x3a000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x440, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 928), 16)
                            mstore(0x00, or(wotsBase, 0x3a000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x440, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 928), 16)
                            mstore(0x00, or(wotsBase, 0x3a000002))
                            mstore(0x440, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x440, add(layerPtr, 928), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(136, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 944), 16)
                            mstore(0x00, or(wotsBase, 0x3b000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x450, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 944), 16)
                            mstore(0x00, or(wotsBase, 0x3b000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x450, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 944), 16)
                            mstore(0x00, or(wotsBase, 0x3b000002))
                            mstore(0x450, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x450, add(layerPtr, 944), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(134, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 960), 16)
                            mstore(0x00, or(wotsBase, 0x3c000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x460, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 960), 16)
                            mstore(0x00, or(wotsBase, 0x3c000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x460, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 960), 16)
                            mstore(0x00, or(wotsBase, 0x3c000002))
                            mstore(0x460, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x460, add(layerPtr, 960), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(132, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 976), 16)
                            mstore(0x00, or(wotsBase, 0x3d000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x470, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 976), 16)
                            mstore(0x00, or(wotsBase, 0x3d000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x470, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 976), 16)
                            mstore(0x00, or(wotsBase, 0x3d000002))
                            mstore(0x470, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x470, add(layerPtr, 976), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(130, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 992), 16)
                            mstore(0x00, or(wotsBase, 0x3e000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x480, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 992), 16)
                            mstore(0x00, or(wotsBase, 0x3e000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x480, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 992), 16)
                            mstore(0x00, or(wotsBase, 0x3e000002))
                            mstore(0x480, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x480, add(layerPtr, 992), 16)
                        }
                    }
                }
                {
                    let digit := and(shr(128, d), 3)
                    switch and(digit, 2)
                    case 0 {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 1008), 16)
                            mstore(0x00, or(wotsBase, 0x3f000000))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 1)
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x490, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x20, add(layerPtr, 1008), 16)
                            mstore(0x00, or(wotsBase, 0x3f000001))
                            mstore(0x20, keccak256(0x00, 0x30))
                            mstore8(0x1f, 2)
                            mstore(0x490, keccak256(0x00, 0x30))
                        }
                    }
                    default {
                        switch and(digit, 1)
                        case 0 {
                            calldatacopy(0x20, add(layerPtr, 1008), 16)
                            mstore(0x00, or(wotsBase, 0x3f000002))
                            mstore(0x490, keccak256(0x00, 0x30))
                        }
                        default {
                            calldatacopy(0x490, add(layerPtr, 1008), 16)
                        }
                    }
                }

                // WOTS_PK compression in place: seed ‖ WOTS_PK ADRS ‖ 64 ends = 1056 bytes.
                mstore(0x80, or(layerBase, or(shl(48, 1), shl(32, idxLeaf))))
                let node := keccak256(0x80, 0x420)

                // Subtree auth path: TREE ADRS (kp = 0), height, tree_index = idxLeaf >> height.
                // 8 levels on every layer, plus levels 9 and 10 on the top layer.
                {
                    let treeBase := or(layerBase, shl(48, 2))
                    let authPtr := add(layerPtr, 1028)
                    {
                        let s := and(shl(4, idxLeaf), 0x10)
                        mstore(0x00, or(treeBase, or(0x1000000, shr(1, idxLeaf))))
                        mstore(add(0x20, s), node)
                        calldatacopy(sub(0x30, s), authPtr, 16)
                        node := keccak256(0x00, 0x40)
                    }
                    {
                        let s := and(shl(3, idxLeaf), 0x10)
                        mstore(0x00, or(treeBase, or(0x2000000, shr(2, idxLeaf))))
                        mstore(add(0x20, s), node)
                        calldatacopy(sub(0x30, s), add(authPtr, 16), 16)
                        node := keccak256(0x00, 0x40)
                    }
                    {
                        let s := and(shl(2, idxLeaf), 0x10)
                        mstore(0x00, or(treeBase, or(0x3000000, shr(3, idxLeaf))))
                        mstore(add(0x20, s), node)
                        calldatacopy(sub(0x30, s), add(authPtr, 32), 16)
                        node := keccak256(0x00, 0x40)
                    }
                    {
                        let s := and(shl(1, idxLeaf), 0x10)
                        mstore(0x00, or(treeBase, or(0x4000000, shr(4, idxLeaf))))
                        mstore(add(0x20, s), node)
                        calldatacopy(sub(0x30, s), add(authPtr, 48), 16)
                        node := keccak256(0x00, 0x40)
                    }
                    {
                        let s := and(idxLeaf, 0x10)
                        mstore(0x00, or(treeBase, or(0x5000000, shr(5, idxLeaf))))
                        mstore(add(0x20, s), node)
                        calldatacopy(sub(0x30, s), add(authPtr, 64), 16)
                        node := keccak256(0x00, 0x40)
                    }
                    {
                        let s := and(shr(1, idxLeaf), 0x10)
                        mstore(0x00, or(treeBase, or(0x6000000, shr(6, idxLeaf))))
                        mstore(add(0x20, s), node)
                        calldatacopy(sub(0x30, s), add(authPtr, 80), 16)
                        node := keccak256(0x00, 0x40)
                    }
                    {
                        let s := and(shr(2, idxLeaf), 0x10)
                        mstore(0x00, or(treeBase, or(0x7000000, shr(7, idxLeaf))))
                        mstore(add(0x20, s), node)
                        calldatacopy(sub(0x30, s), add(authPtr, 96), 16)
                        node := keccak256(0x00, 0x40)
                    }
                    {
                        let s := and(shr(3, idxLeaf), 0x10)
                        mstore(0x00, or(treeBase, or(0x8000000, shr(8, idxLeaf))))
                        mstore(add(0x20, s), node)
                        calldatacopy(sub(0x30, s), add(authPtr, 112), 16)
                        node := keccak256(0x00, 0x40)
                    }
                    if isTop {
                        {
                            let s := and(shr(4, idxLeaf), 0x10)
                            mstore(0x00, or(treeBase, or(0x9000000, shr(9, idxLeaf))))
                            mstore(add(0x20, s), node)
                            calldatacopy(sub(0x30, s), add(authPtr, 128), 16)
                            node := keccak256(0x00, 0x40)
                        }
                        {
                            let s := and(shr(5, idxLeaf), 0x10)
                            mstore(0x00, or(treeBase, or(0xa000000, shr(10, idxLeaf))))
                            mstore(add(0x20, s), node)
                            calldatacopy(sub(0x30, s), add(authPtr, 144), 16)
                            node := keccak256(0x00, 0x40)
                        }
                    }
                }

                currentNode := node
                layerPtr := add(layerPtr, 1156)
            }

            mstore(0x00, eq(shr(128, currentNode), shr(128, pkRoot)))
            return(0x00, 0x20)
        }
    }
}
