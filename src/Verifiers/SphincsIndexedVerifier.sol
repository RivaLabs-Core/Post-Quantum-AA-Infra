// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Signature length of the indexed SPHINCS- variant blob (no prefix). It is the stateless
///      SphincsVerifier blob (3688) plus a trailing 32-byte explicit-index word (canonical, high
///      bits zero, value < 2^H = 2^22). MUST equal the in-assembly `sig.length` check below (3720)
///      and, if ever wired into an account, stay disjoint from `FORS_SIG_LEN` and the
///      activation-envelope length set.
uint256 constant SPHINCS_INDEXED_SIG_LEN = 3720;

/// @title SphincsIndexedVerifier — STATEFUL, explicit-index SPHINCS- variant (Yul, keccak256)
/// @notice A variant of `SphincsVerifier` in which the hypertree leaf index `htIdx` — i.e. *which
///         FORS keypair the signer used* — is NOT derived from the message digest, but is passed
///         explicitly in the signature (a trailing 32-byte word) and bound into H_msg.
///
///         Consequence: unlike the stateless `SphincsVerifier` (where the message pseudo-randomly
///         selects the FORS keypair), this scheme is **STATEFUL** — the signer chooses `htIdx`
///         (a counter) and MUST use each of the 2^22 FORS keypairs at most within its few-time
///         budget (ideally exactly once, q=1). Reusing an index for two different messages
///         degrades that FORS keypair's security exactly like FORS+C reuse (q=2 ≈ 104-bit, …).
///         This trades SPHINCS+'s stateless robustness for explicit, ephemeral-key-style index
///         control. It is EUF-CMA secure with an honest, non-reusing signer: an attacker cannot
///         forge (no FORS secret), and the explicit index cannot be swapped on a valid signature
///         (it is bound both into H_msg and by the hypertree auth path).
///
///         Differences vs `SphincsVerifier` (everything else is byte-for-byte identical):
///           1. Signature is 3720 B: the original 3688-B blob followed by a 32-byte `htIdx` word.
///           2. `htIdx` is read from the signature (offset 3688), required canonical (< 2^22).
///           3. H_msg binds `htIdx`: keccak(pkSeed ‖ pkRoot ‖ R ‖ htIdx ‖ message ‖ PAD), 192 B.
///           4. Domain-separator PAD = 0xFF…FE (distinct from stateless SPHINCS- 0xFF…FF and
///              FORS+C 0xFF…FD) so the three schemes never collide on a digest even under a
///              shared public key.
///           5. `htIdx` is NO LONGER derived from the digest (the old `digest>>133` selection).
///
///         Params unchanged: n=16 (128-bit), h=22 d=2 a=19 k=7 w=8 l=43 target_sum=208, FORS+C
///         forced-zero last index. ADRS layout / tweakable-hash / FORS+hypertree logic identical
///         to `SphincsVerifier` — see that file's header and docs/sphincs-backup-recovery.md.
/// @dev VENDORED-DERIVED, UNAUDITED research prototype. The FORS/hypertree assembly is the
///      byte-for-byte upstream SPHINCS- logic; only the index sourcing, H_msg binding, PAD and
///      length were changed. A matching signer + reference vector are REQUIRED before any use;
///      gate any real-funds use on an audit of this contract.
contract SphincsIndexedVerifier {

    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external pure returns (bool valid)
    {
        // NOTE: this block intentionally uses Solidity's free-memory-pointer slot
        // (0x40) and the zero slot (0x60) as scratch and writes high memory without
        // updating the FMP. That is only sound because every exit below is an
        // unconditional in-assembly `return`/`revert`, so Solidity never regains
        // control with a clobbered FMP. It is therefore NOT `memory-safe` in the
        // Yul sense — do not add the ("memory-safe") annotation and do not introduce
        // a normal (fall-through) exit from this block.
        assembly {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            // 3720 = 3688 (stateless blob) + 32 (trailing explicit-index word)
            if iszero(eq(sig.length, 3720)) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }

            // Reject non-canonical public keys (low 128 bits must be zero), mirroring
            // SphincsVerifier: a non-top-aligned key can never equal the always-N_MASK'd
            // final node, silently bricking; fail loudly instead.
            if or(iszero(eq(pkSeed, and(pkSeed, N_MASK))), iszero(eq(pkRoot, and(pkRoot, N_MASK)))) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid public key")
                revert(0x00, 0x64)
            }

            // Explicit hypertree leaf index (which FORS keypair) — from the signature, not the
            // message. Trailing 32-byte word at offset 3688. Required canonical: high bits zero,
            // value < 2^H = 2^22. A non-canonical index is a malformed signature -> return `false`
            // (the bool contract; uniform with the other soundness rejections below), never revert.
            let htIdx := calldataload(add(sig.offset, 3688))
            if gt(htIdx, 0x3FFFFF) { mstore(0x00, 0) return(0x00, 0x20) }

            let seed := pkSeed
            let root := pkRoot
            mstore(0x00, seed)

            // H_msg (domain-separated, 192 bytes) — binds the EXPLICIT index htIdx:
            //   keccak256(pkSeed ‖ pkRoot ‖ R ‖ htIdx ‖ message ‖ PAD)
            // PAD = 0xFF…FE is distinct from stateless SPHINCS- (0xFF…FF) and FORS+C (0xFF…FD).
            let R := and(calldataload(sig.offset), N_MASK)
            mstore(0x20, root)
            mstore(0x40, R)
            mstore(0x60, htIdx)
            mstore(0x80, message)
            mstore(0xA0, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE)
            let digest := keccak256(0x00, 0xC0)

            // NOTE: htIdx is now supplied by the signature (above); it is NOT taken from
            // `digest >> 133` as in the stateless verifier. The message digest is used ONLY for the
            // FORS leaf indices md[0..K-1] (bits [0,133)); bits >= 133 are unused here.

            // FORS+C (K=7, A=19) — addressing keyed by the explicit hypertree leaf htIdx.
            let dVal := digest
            // Forced-zero: last FORS index (i=K-1=6) occupies bits [114,133) (19-bit field).
            // 114 = (K-1)*A = 6*19 ; 0x7FFFF = 2^A-1. Well-formed-but-invalid -> return false.
            if and(shr(114, dVal), 0x7FFFF) { mstore(0x00, 0) return(0x00, 0x20) }

            let sigBase := sig.offset

            // SUBTREE_H = 11 (h/d = 22/2): split htIdx into bottom subtree + leaf.
            let idxLeaf0 := and(htIdx, 0x7FF)
            let idxTree0 := shr(11, htIdx)
            // forsBase: tree=idxTree0 (shl 128), type=3 (shl 96), kp=idxLeaf0 (shl 64).
            let forsBase := or(shl(128, idxTree0), or(shl(96, 3), shl(64, idxLeaf0)))
            // K-1=6 normal trees
            for { let i := 0 } lt(i, 6) { i := add(i, 1) } {
                let treeIdx := and(shr(mul(i, 19), dVal), 0x7FFFF) // 19=A-bit indices, shift i*A
                let secretVal := and(calldataload(add(sigBase, add(16, shl(4, i)))), N_MASK)
                // Leaf hash (height 0): word3 = (i << A) | treeIdx, A=19
                let leafAdrs := or(forsBase, or(shl(19, i), treeIdx))
                mstore(0x20, leafAdrs)
                mstore(0x40, secretVal)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                let pathIdx := treeIdx
                // AUTH_START = 16 + K*N = 128, auth per tree = A*N = 19*16 = 304
                let authPtr := add(sigBase, add(128, mul(i, 304)))

                // Walk A=19 auth path levels
                for { let h := 0 } lt(h, 19) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(authPtr, shl(4, h))), N_MASK)
                    let parentIdx := shr(1, pathIdx)
                    // word2=height=h+1; word3 = (i << (A-1-h)) | parentIdx. 18 = A-1.
                    mstore(0x20, or(forsBase, or(shl(32, add(h, 1)), or(shl(sub(18, h), i), parentIdx))))
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
                let lastSecret := and(calldataload(add(sigBase, add(16, shl(4, 6)))), N_MASK) // 16+(K-1)*16=112
                // Forced-zero tree (forsTree=K-1=6) as leaf node 0: word3 = (6 << A). 19 = A, 6 = K-1.
                mstore(0x20, or(forsBase, shl(19, 6)))
                mstore(0x40, lastSecret)
                // 0x80 + 6*0x20 = 0x140
                mstore(0x140, and(keccak256(0x00, 0x60), N_MASK))
            }

            // Compress K=7 roots: keccak256(seed || FORS_ROOTS-ADRS || 7 roots)
            // FORS_ROOTS: tree=idxTree0, type=4 (shl 96), kp=idxLeaf0 (shl 64). = 32+32+7*32 = 0x120
            mstore(0x20, or(shl(128, idxTree0), or(shl(96, 4), shl(64, idxLeaf0))))
            for { let i := 0 } lt(i, 7) { i := add(i, 1) } {
                mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
            }
            let forsPk := and(keccak256(0x00, 0x120), N_MASK)

            // ============================================================
            // Hypertree (D=2, subtree_h=11, w=8, l=43, target_sum=208) — driven by the explicit htIdx
            // ============================================================
            let currentNode := forsPk
            let idxTree := htIdx
            let sigOff := 1952 // HT_START = AUTH_START + (K-1)*A*N = 128 + 1824

            for { let layer := 0 } lt(layer, 2) { layer := add(layer, 1) } {
                let idxLeaf := and(idxTree, 0x7FF) // 2^11 - 1
                idxTree := shr(11, idxTree)

                // WOTS_HASH base ADRS: layer, tree=idxTree, word1=idxLeaf (key_pair_address)
                let wotsAdrs := or(shl(224, layer), or(shl(128, idxTree), shl(64, idxLeaf)))
                // countOff = sigOff + l*N = sigOff + 688
                let countOff := add(sigOff, 688)
                let count := shr(224, calldataload(add(sigBase, countOff)))

                // WOTS-message digest
                mstore(0x20, wotsAdrs)
                mstore(0x40, currentNode)
                mstore(0x60, count)
                let d := keccak256(0x00, 0x80)

                // Validate WOTS+C digit sum == TARGET_SUM (43 base-8 digits). Invalid -> return false.
                let digitSum := 0
                for { let ii := 0 } lt(ii, 43) { ii := add(ii, 1) } {
                    digitSum := add(digitSum, and(shr(mul(ii, 3), d), 0x7))
                }
                if iszero(eq(digitSum, 208)) { mstore(0x00, 0) return(0x00, 0x20) }

                // 43 WOTS chains (w=8: max 7 steps per chain)
                let wotsPtr := add(sigBase, sigOff)
                for { let i := 0 } lt(i, 43) { i := add(i, 1) } {
                    let digit := and(shr(mul(i, 3), d), 0x7)
                    let steps := sub(7, digit)
                    let val := and(calldataload(add(wotsPtr, shl(4, i))), N_MASK)
                    let chainBase := or(wotsAdrs, shl(32, i))

                    for { let step := 0 } lt(step, steps) { step := add(step, 1) } {
                        mstore(0x20, or(chainBase, add(digit, step)))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), N_MASK)
                    }
                    mstore(add(0x80, shl(5, i)), val)
                }

                // WOTS_PK compression: type=1, word1=idxLeaf. = 32+32+43*32 = 0x5A0
                let pkAdrs := or(shl(224, layer), or(shl(128, idxTree), or(shl(96, 1), shl(64, idxLeaf))))
                mstore(0x20, pkAdrs)
                for { let i := 0 } lt(i, 43) { i := add(i, 1) } {
                    mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
                }
                let wotsPk := and(keccak256(0x00, 0x5A0), N_MASK)

                // TREE Merkle auth path (11 levels): type=2, word2=tree_height, word3=tree_index
                let authOff := add(countOff, 4)
                let treeAdrs := or(shl(224, layer), or(shl(128, idxTree), shl(96, 2)))
                let merkleNode := wotsPk
                let mIdx := idxLeaf
                let merklePtr := add(sigBase, authOff)

                for { let h := 0 } lt(h, 11) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(merklePtr, shl(4, h))), N_MASK)
                    let parentIdx := shr(1, mIdx)
                    mstore(0x20, or(treeAdrs, or(shl(32, add(h, 1)), parentIdx)))
                    let s := shl(5, and(mIdx, 1))
                    mstore(xor(0x40, s), merkleNode)
                    mstore(xor(0x60, s), sibling)
                    merkleNode := and(keccak256(0x00, 0x80), N_MASK)
                    mIdx := parentIdx
                }

                currentNode := merkleNode
                sigOff := add(authOff, 176) // 11*16
            }

            valid := eq(currentNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
