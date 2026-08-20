// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Signature length of the SPHINCS- signature blob (no prefix). MUST equal the in-assembly
///      `sig.length` check in `SphincsVerifier.verify` (8048), and stay disjoint from
///      `FORS_SIG_LEN` and the activation-envelope length set — enforced by a constructor
///      guard in SimpleAccount and a Foundry test.
uint256 constant SPHINCS_SIG_LEN = 8048;

/// @title SphincsVerifier — stateless SPHINCS- verifier (shared, Yul-optimized, keccak256)
/// @notice EVM-optimized SPHINCS+/SLH-DSA verifier (FORS-under-WOTS+-hypertree, n=16 / 128-bit):
///         h=20 d=4 a=7 k=29 w=4 l=64, 8,048-byte signature, public key = (pkSeed, pkRoot).
/// @dev    Address layout: FIPS 205 §4.2 / §11.2.2 uncompressed 32-byte ADRS (the SHAKE
///         instantiation form) with keccak256 substituted for SHAKE-256 to stay native on EVM.
///
///         ADRS layout (32 bytes, big-endian, FIPS 205 §4.2 Algorithm 1):
///           bytes  0.. 4   layer address          (uint32)
///           bytes  4..16   tree address           (96 bits, big-endian)
///           bytes 16..20   type                   (uint32)
///           bytes 20..24   word1 (type-dependent)
///           bytes 24..28   word2 (type-dependent)
///           bytes 28..32   word3 (type-dependent)
///
///         Type → (word1, word2, word3):
///           0 WOTS_HASH   (key_pair_address, chain_address, hash_address)
///           1 WOTS_PK     (key_pair_address, 0,             0)
///           2 TREE        (0,                tree_height,   tree_index)
///           3 FORS_TREE   (key_pair_address, tree_height,   tree_index)
///           4 FORS_ROOTS  (key_pair_address, 0,             0)
///
///         Tweakable hash: keccak256(seed32 ‖ adrs32 ‖ payload). Domain-separated
///         H_msg (160 bytes). Branchless Merkle swap (Solady), hoisted chain
///         address base.
/// @dev DERIVED (MIT) from the SPHINCS- reference implementation — the assembly verification
///      logic below is upstream's, with the parameter set retargeted from the canonical
///      {h=22 d=2 a=19 k=7 w=8 l=43 target_sum=208, 3,688 B} to
///      {h=20 d=4 a=7 k=29 w=4 l=64 target_sum=96, 8,048 B}; every "PARAM IDENTITIES" callout
///      below records the substitution. Structure, ADRS semantics and hash inputs are unchanged,
///      so a signer configured for this set interoperates bit-for-bit. Provenance and source
///      link: see docs/sphincs-backup-recovery.md.
///
///      WOTS+C note: this is the constant-sum Winternitz variant — there are NO checksum
///      chains. All l=64 chains carry message digits (64 x logW=2 bits = the full 8n=128-bit
///      digest); the checksum's role is played by the `digitSum == TARGET_SUM` equality below.
///      TARGET_SUM = 96 is the mean of the digit-sum distribution (l*(w-1)/2 = 64*3/2), which
///      minimises the signer's counter-grinding cost (~22 attempts on average).
///
///      H_msg pad 0xFF..FF is distinct from NiceTry FORS+C's 0xFF..FD, so the two schemes never
///      collide on a digest. UNAUDITED research prototype; gate any real-funds use on an audit
///      of this contract.
contract SphincsVerifier {

    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external pure returns (bool valid)
    {
        // NOTE: this block intentionally uses Solidity's free-memory-pointer slot
        // (0x40) and the zero slot (0x60) as scratch and writes high memory without
        // updating the FMP. That is only sound because every exit below is an
        // unconditional in-assembly `return`/`revert`, so Solidity never regains
        // control with a clobbered FMP. It is therefore NOT `memory-safe` in the
        // Yul sense — do not add the ("memory-safe") annotation and do not introduce
        // a normal (fall-through) exit from this block. (review evm-f1)
        //
        // Memory high-water mark for this parameter set: the WOTS chain-head buffer
        // spans 0x80 + 32*i for i < l=64, ending at 0x880; the WOTS_PK compression
        // window is keccak256(0x00, 0x840). Both are well clear of the FORS phase,
        // which ends at 0x420.
        assembly {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            if iszero(eq(sig.length, 8048)) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }

            // Reject non-canonical public keys (low 128 bits must be zero), mirroring
            // the SLH-DSA-SHA2 verifier. Without this a non-top-aligned pkRoot can
            // never equal the always-N_MASK'd `currentNode` (line ~"valid := eq"),
            // silently bricking the account; pkSeed would also diverge from the
            // signer which always masks. Fail loudly instead. (review V-f1)
            if or(iszero(eq(pkSeed, and(pkSeed, N_MASK))), iszero(eq(pkRoot, and(pkRoot, N_MASK)))) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid public key")
                revert(0x00, 0x64)
            }

            let seed := pkSeed
            let root := pkRoot
            mstore(0x00, seed)

            // H_msg (domain-separated, 160 bytes)
            let R := and(calldataload(sig.offset), N_MASK)
            mstore(0x20, root)
            mstore(0x40, R)
            mstore(0x60, message)
            mstore(0x80, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            let digest := keccak256(0x00, 0xA0)

            // htIdx = (digest >> 203) & (2^20-1)
            // PARAM IDENTITIES (must hold or signer/verifier desync silently —
            // review V-f4): 203 = K*A = 29*7 ; 0xFFFFF = 2^H-1 = 2^20-1.
            // Digest budget: K*A + H = 203 + 20 = 223 <= 256.
            let htIdx := and(shr(203, digest), 0xFFFFF)

            // FORS+C (K=29, A=7)
            //
            // FORS addressing — exact FIPS 205 FORS field split: the FORS
            // instance is keyed by the per-message hypertree leaf via the
            // canonical address fields —
            //   tree address      = idxTree0 = htIdx >> SUBTREE_H (bottom subtree)
            //   word1/kp           = idxLeaf0 = htIdx & (2^SUBTREE_H-1) (bottom leaf)
            //   word3/tree_index   = (forsTree << (A-height)) | node  (k FORS trees
            //                        indexed as one forest, FIPS 205 Alg. 17)
            //   word2/tree_height  = height
            // so each of the 2^h hypertree leaves selects a distinct FORS
            // instance. Matches C12 / SLH-DSA-SHA2 field semantics; the signer
            // mirrors this and derives the leaf secrets from the same leaf.
            let dVal := digest
            // Forced-zero: last FORS index (i=K-1=28) occupies bits [196,203)
            // (7-bit field). PARAM IDENTITIES (review V-f4): 196 = (K-1)*A =
            // 28*7 ; 0x7F = 2^A-1 = 2^7-1.
            // A well-formed-but-invalid signature is rejected by returning `false`
            // (the bool contract), NOT by an empty revert — so all soundness
            // rejections are uniform across callers. (review V-f2 / evm-f2)
            if and(shr(196, dVal), 0x7F) { mstore(0x00, 0) return(0x00, 0x20) }

            let sigBase := sig.offset

            // SUBTREE_H = 5 (h/d = 20/4): split htIdx into bottom subtree + leaf.
            // PARAM IDENTITIES (review V-f4): 0x1F = 2^SUBTREE_H-1 = 2^5-1 ;
            // shift 5 = SUBTREE_H.
            let idxLeaf0 := and(htIdx, 0x1F)
            let idxTree0 := shr(5, htIdx)
            // forsBase: tree=idxTree0 (shl 128), type=3 (shl 96), kp=idxLeaf0 (shl 64).
            // Per-site we OR in word2=height (shl 32) and word3=tree_index (shl 0).
            let forsBase := or(shl(128, idxTree0), or(shl(96, 3), shl(64, idxLeaf0)))
            // K-1=28 normal trees
            for { let i := 0 } lt(i, 28) { i := add(i, 1) } {
                let treeIdx := and(shr(mul(i, 7), dVal), 0x7F) // 7=A-bit indices, shift i*A
                let secretVal := and(calldataload(add(sigBase, add(16, shl(4, i)))), N_MASK)
                // Leaf hash (height 0): word3 = (i << A) | treeIdx, A=7 (folds the k
                // FORS trees into one tree_index space; review V-f4)
                let leafAdrs := or(forsBase, or(shl(7, i), treeIdx))
                mstore(0x20, leafAdrs)
                mstore(0x40, secretVal)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                let pathIdx := treeIdx
                // AUTH_START = 16 + K*N = 480, auth per tree = A*N = 7*16 = 112
                let authPtr := add(sigBase, add(480, mul(i, 112)))

                // Walk A=7 auth path levels
                for { let h := 0 } lt(h, 7) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(authPtr, shl(4, h))), N_MASK)
                    let parentIdx := shr(1, pathIdx)
                    // word2=height=h+1; word3 = (i << (A-1-h)) | parentIdx.
                    // PARAM IDENTITY (review V-f4): 6 = A-1; sub(6,h) stays
                    // >= 0 for h in [0,6] (the A=7 auth levels).
                    mstore(0x20, or(forsBase, or(shl(32, add(h, 1)), or(shl(sub(6, h), i), parentIdx))))
                    // Branchless Merkle swap (Solady)
                    let s := shl(5, and(pathIdx, 1))
                    mstore(xor(0x40, s), node)
                    mstore(xor(0x60, s), sibling)
                    node := and(keccak256(0x00, 0x80), N_MASK)
                    pathIdx := parentIdx
                }
                mstore(add(0x80, shl(5, i)), node)
            }

            // Last tree (forced-zero): secret is the revealed root, hashed under FORS_TREE leaf ADRS
            {
                let lastSecret := and(calldataload(add(sigBase, add(16, shl(4, 28)))), N_MASK) // 16+(K-1)*16=464
                // Forced-zero tree (forsTree=K-1=28) as leaf node 0: word3 = (28 << A).
                // PARAM IDENTITY (review V-f4): 7 = A, 28 = K-1.
                mstore(0x20, or(forsBase, shl(7, 28)))
                mstore(0x40, lastSecret)
                // 0x80 + 28*0x20 = 0x80 + 0x380 = 0x400
                mstore(0x400, and(keccak256(0x00, 0x60), N_MASK))
            }

            // Compress K=29 roots: keccak256(seed || FORS_ROOTS-ADRS || 29 roots)
            // FORS_ROOTS: tree=idxTree0, type=4 (shl 96), kp=idxLeaf0 (shl 64).
            // = 32 + 32 + 29*32 = 992 = 0x3E0
            // The copy below is descending-safe: dest 0x40+32i is two slots BELOW
            // src 0x80+32i, so slot i's source is only clobbered at iteration i+2,
            // long after it has been read.
            mstore(0x20, or(shl(128, idxTree0), or(shl(96, 4), shl(64, idxLeaf0))))
            for { let i := 0 } lt(i, 29) { i := add(i, 1) } {
                mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
            }
            let forsPk := and(keccak256(0x00, 0x3E0), N_MASK)

            // ============================================================
            // Hypertree (D=4, subtree_h=5, w=4, l=64, target_sum=96)
            //
            // FIPS ADRS bit positions:
            //   layer        at shl(224, …)  bytes 0..4
            //   tree         at shl(128, …)  bytes 4..16 (96-bit address; top 4 B always 0)
            //   type         at shl( 96, …)  bytes 16..20
            //   word1 (kp)   at shl( 64, …)  bytes 20..24
            //   word2 (...)  at shl( 32, …)  bytes 24..28
            //   word3 (...)  at shl(  0, …)  bytes 28..32
            // ============================================================
            let currentNode := forsPk
            let idxTree := htIdx
            let sigOff := 3616 // HT_START = AUTH_START + (K-1)*A*N = 480 + 3136

            for { let layer := 0 } lt(layer, 4) { layer := add(layer, 1) } {
                let idxLeaf := and(idxTree, 0x1F) // 2^5 - 1
                idxTree := shr(5, idxTree)

                // WOTS_HASH base ADRS for this WOTS keypair (type=0 implicit):
                //   layer, tree=idxTree, word1=idxLeaf (key_pair_address)
                let wotsAdrs := or(shl(224, layer), or(shl(128, idxTree), shl(64, idxLeaf)))
                // countOff = sigOff + l*N = sigOff + 1024
                let countOff := add(sigOff, 1024)
                let count := shr(224, calldataload(add(sigBase, countOff)))

                // WOTS-message digest: hashAdrs is the WOTS_HASH base with word2/word3 = 0
                mstore(0x20, wotsAdrs)
                mstore(0x40, currentNode)
                mstore(0x60, count)
                let d := keccak256(0x00, 0x80)

                // Validate WOTS+C digit sum == TARGET_SUM (64 base-4 digits, 2 bits
                // each). PARAM IDENTITIES (review V-f4): loop bound 64 = L ;
                // digit shift 2 = LOG_W ; mask 0x3 = W-1 = 2^LOG_W-1 ; 96 = TARGET_SUM.
                // Digit budget: L*LOG_W = 128 <= 256, drawn from this layer's own
                // keccak word (independent of the H_msg digest budget above).
                // A digit-sum mismatch is a well-formed-but-invalid signature ->
                // return `false` (uniform with the forced-zero path; review
                // V-f2 / evm-f2), not an empty revert.
                let digitSum := 0
                for { let ii := 0 } lt(ii, 64) { ii := add(ii, 1) } {
                    digitSum := add(digitSum, and(shr(mul(ii, 2), d), 0x3))
                }
                if iszero(eq(digitSum, 96)) { mstore(0x00, 0) return(0x00, 0x20) }

                // 64 WOTS chains (w=4: max 3 steps per chain)
                let wotsPtr := add(sigBase, sigOff)
                for { let i := 0 } lt(i, 64) { i := add(i, 1) } {
                    let digit := and(shr(mul(i, 2), d), 0x3)
                    let steps := sub(3, digit)
                    let val := and(calldataload(add(wotsPtr, shl(4, i))), N_MASK)
                    // FIPS WOTS_HASH: word2=chain_address=i, word3=hash_address=digit+step
                    // wotsAdrs already has word2=word3=0; OR in chain_address here.
                    let chainBase := or(wotsAdrs, shl(32, i))

                    for { let step := 0 } lt(step, steps) { step := add(step, 1) } {
                        mstore(0x20, or(chainBase, add(digit, step)))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), N_MASK)
                    }
                    mstore(add(0x80, shl(5, i)), val)
                }

                // WOTS_PK compression: type=1, word1=idxLeaf
                // = 32+32+64*32 = 2112 = 0x840
                let pkAdrs := or(shl(224, layer), or(shl(128, idxTree), or(shl(96, 1), shl(64, idxLeaf))))
                mstore(0x20, pkAdrs)
                for { let i := 0 } lt(i, 64) { i := add(i, 1) } {
                    mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
                }
                let wotsPk := and(keccak256(0x00, 0x840), N_MASK)

                // TREE Merkle auth path (5 levels)
                //   type=2, word1=0 always, word2=tree_height, word3=tree_index
                let authOff := add(countOff, 4)
                let treeAdrs := or(shl(224, layer), or(shl(128, idxTree), shl(96, 2)))
                let merkleNode := wotsPk
                let mIdx := idxLeaf
                let merklePtr := add(sigBase, authOff)

                for { let h := 0 } lt(h, 5) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(merklePtr, shl(4, h))), N_MASK)
                    let parentIdx := shr(1, mIdx)
                    // treeAdrs has word1=0, word2=0, word3=0; OR in height and index.
                    mstore(0x20, or(treeAdrs, or(shl(32, add(h, 1)), parentIdx)))
                    let s := shl(5, and(mIdx, 1))
                    mstore(xor(0x40, s), merkleNode)
                    mstore(xor(0x60, s), sibling)
                    merkleNode := and(keccak256(0x00, 0x80), N_MASK)
                    mIdx := parentIdx
                }

                currentNode := merkleNode
                sigOff := add(authOff, 80) // 5*16
            }

            valid := eq(currentNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
