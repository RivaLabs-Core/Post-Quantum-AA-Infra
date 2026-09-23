// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Signature length of the SphincsVerifier_v2 blob (no prefix). MUST equal the in-assembly
///      `sig.length` check in `SphincsVerifier_v2.verify` (6176). Distinct from
///      `SPHINCS_SIG_LEN` (3688), `SPHINCS_STANDARD_SIG_LEN` (8400) and `FORS_SIG_LEN` (2448).
uint256 constant SPHINCS_V2_SIG_LEN = 6176;

/// @title SphincsVerifier_v2 — stateless SPHINCS- verifier, STANDARD on both layers
/// @notice n=16 h=20 d=5 h'=4 a=9 k=19 w=16 l=35, 6,176-byte signature, public key = (pkSeed, pkRoot).
///         Same construction as `SphincsStandardVerifier` (no FORS+C, no WOTS+C), different
///         parameter set:
///
///           * STANDARD FORS — all k=19 trees carry a revealed secret AND a full a=9 auth path.
///             No forced-zero last tree and no `R` grinding: every FORS index is used as drawn
///             from the digest, occupying bits [0,171).
///           * STANDARD WOTS+ — w=16 (log_w=4), l = len1 + len2 = 32 + 3 = 35. The first 32
///             chains carry the message digits, the last 3 the base-16 checksum
///             csum = SUM(w-1-digit_i) = 480 - digitSum, range [0,480], encoded as 3 base-16
///             digits (480 < 16^3). len2 = floor(log2(len1*(w-1))/log2 w) + 1.
///             No per-layer grinding counter and no digit-sum equality check.
///
///         Signature blob layout:
///           R(16) ‖ 19 FORS secrets (16 each) ‖ 19 FORS auth paths (9*16 each)
///           ‖ 5 x [ 35 WOTS chains (16 each) ‖ subtree auth path (4*16) ]
///           = 16 + 304 + 2736 + 5*624 = 6176
///
/// @dev    Address layout, tweakable hash, H_msg domain pad and DIGIT ORDER (LSB-first out of the
///         keccak word, for both WOTS digits and FORS indices) are identical to
///         `SphincsStandardVerifier` — see its header. A signer MUST mirror them.
///         Reference signer: scripts/sphincs_v2_reference.py.
///
/// @dev    UNAUDITED research prototype.
contract SphincsVerifier_v2 {

    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external pure returns (bool valid)
    {
        // NOTE: this block intentionally uses Solidity's free-memory-pointer slot (0x40) and the
        // zero slot (0x60) as scratch and writes high memory without updating the FMP. That is
        // only sound because every exit below is an unconditional in-assembly `return`/`revert`,
        // so Solidity never regains control with a clobbered FMP. It is therefore NOT
        // `memory-safe` in the Yul sense — do not add the ("memory-safe") annotation and do not
        // introduce a normal (fall-through) exit from this block.
        //
        // Memory high-water mark: the WOTS chain-head buffer spans 0x80 + 32*i for i < l=35,
        // ending at 0x4E0; the WOTS_PK compression window is keccak256(0x00, 0x4A0). The FORS
        // phase ends at 0x2E0 and is fully consumed before the hypertree starts.
        assembly {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            if iszero(eq(sig.length, 6176)) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }

            // Reject non-canonical public keys (low 128 bits must be zero): a non-top-aligned
            // pkRoot can never equal the always-N_MASK'd final node, which would silently brick
            // the account. Fail loudly instead.
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

            // htIdx = (digest >> 171) & (2^20-1). PARAM IDENTITIES: 171 = K*A = 19*9 ;
            // 0xFFFFF = 2^H-1 = 2^20-1. Digest budget: K*A + H = 191 <= 256.
            let htIdx := and(shr(171, digest), 0xFFFFF)

            // ============================================================
            // STANDARD FORS (K=19, A=9) — every tree has a secret and an auth path.
            // ============================================================
            let dVal := digest
            let sigBase := sig.offset

            // SUBTREE_H = 4 (h/d = 20/5). PARAM IDENTITIES: 0xF = 2^SUBTREE_H-1 ; shift 4.
            let idxLeaf0 := and(htIdx, 0xF)
            let idxTree0 := shr(4, htIdx)
            // forsBase: tree=idxTree0 (shl 128), type=3 (shl 96), kp=idxLeaf0 (shl 64).
            let forsBase := or(shl(128, idxTree0), or(shl(96, 3), shl(64, idxLeaf0)))

            for { let i := 0 } lt(i, 19) { i := add(i, 1) } {
                let treeIdx := and(shr(mul(i, 9), dVal), 0x1FF) // 9=A-bit indices, shift i*A
                let secretVal := and(calldataload(add(sigBase, add(16, shl(4, i)))), N_MASK)
                // Leaf hash (height 0): word3 = (i << A) | treeIdx, A=9 (folds the k FORS trees
                // into one tree_index space, FIPS 205 Alg. 17).
                mstore(0x20, or(forsBase, or(shl(9, i), treeIdx)))
                mstore(0x40, secretVal)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                let pathIdx := treeIdx
                // AUTH_START = 16 + K*N = 320, auth per tree = A*N = 144.
                // Last tree (i=18) spans [2912, 3056) = up to HT_START.
                let authPtr := add(sigBase, add(320, mul(i, 144)))

                for { let hh := 0 } lt(hh, 9) { hh := add(hh, 1) } {
                    let sibling := and(calldataload(add(authPtr, shl(4, hh))), N_MASK)
                    let parentIdx := shr(1, pathIdx)
                    // word2=height=hh+1; word3 = (i << (A-1-hh)) | parentIdx. 8 = A-1.
                    mstore(0x20, or(forsBase, or(shl(32, add(hh, 1)), or(shl(sub(8, hh), i), parentIdx))))
                    // Branchless Merkle swap (Solady)
                    let s := shl(5, and(pathIdx, 1))
                    mstore(xor(0x40, s), node)
                    mstore(xor(0x60, s), sibling)
                    node := and(keccak256(0x00, 0x80), N_MASK)
                    pathIdx := parentIdx
                }
                mstore(add(0x80, shl(5, i)), node)
            }

            // Compress K=19 roots: keccak256(seed || FORS_ROOTS-ADRS || 19 roots), window
            // 32 + 32 + 19*32 = 0x2A0. Copy is safe: dest 0x40+32i sits two slots below
            // src 0x80+32i, so slot i's source is only clobbered at iteration i+2.
            mstore(0x20, or(shl(128, idxTree0), or(shl(96, 4), shl(64, idxLeaf0))))
            for { let i := 0 } lt(i, 19) { i := add(i, 1) } {
                mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
            }
            let forsPk := and(keccak256(0x00, 0x2A0), N_MASK)

            // ============================================================
            // Hypertree (D=5, subtree_h=4, w=16, l=35 = 32 msg + 3 checksum, NO counter)
            // ============================================================
            let currentNode := forsPk
            let idxTree := htIdx
            let sigOff := 3056 // HT_START = 16 + K*N + K*A*N = 16 + 304 + 2736

            for { let layer := 0 } lt(layer, 5) { layer := add(layer, 1) } {
                let idxLeaf := and(idxTree, 0xF) // 2^4 - 1
                idxTree := shr(4, idxTree)

                // WOTS_HASH base ADRS for this WOTS keypair (type=0 implicit):
                //   layer, tree=idxTree, word1=idxLeaf (key_pair_address)
                let wotsAdrs := or(shl(224, layer), or(shl(128, idxTree), shl(64, idxLeaf)))

                // WOTS-message digest: 96 bytes (seed ‖ ADRS ‖ node), no counter word.
                mstore(0x20, wotsAdrs)
                mstore(0x40, currentNode)
                let dw := keccak256(0x00, 0x60)

                // Checksum over the 32 message digits: csum = SUM(w-1-digit) = 480 - digitSum.
                // PARAM IDENTITIES: bound 32 = LEN1 ; shift 4 = LOG_W ; mask 0xF = W-1 ;
                // 480 = LEN1*(W-1), the maximum csum and its value at digitSum == 0.
                let digitSum := 0
                for { let ii := 0 } lt(ii, 32) { ii := add(ii, 1) } {
                    digitSum := add(digitSum, and(shr(shl(2, ii), dw), 0xF))
                }
                let csum := sub(480, digitSum)

                // 35 WOTS chains (w=16: max 15 steps each). Chains [0,32) take message digits
                // from `dw`; chains [32,35) take the LEN2=3 base-16 digits of csum.
                let wotsPtr := add(sigBase, sigOff)
                for { let i := 0 } lt(i, 35) { i := add(i, 1) } {
                    let digit
                    switch lt(i, 32)
                    case 1 { digit := and(shr(shl(2, i), dw), 0xF) }
                    default { digit := and(shr(shl(2, sub(i, 32)), csum), 0xF) }

                    let steps := sub(15, digit)
                    let val := and(calldataload(add(wotsPtr, shl(4, i))), N_MASK)
                    // FIPS WOTS_HASH: word2=chain_address=i, word3=hash_address=digit+step.
                    let chainBase := or(wotsAdrs, shl(32, i))

                    for { let step := 0 } lt(step, steps) { step := add(step, 1) } {
                        mstore(0x20, or(chainBase, add(digit, step)))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), N_MASK)
                    }
                    mstore(add(0x80, shl(5, i)), val)
                }

                // WOTS_PK compression: type=1, word1=idxLeaf. Window 32+32+35*32 = 0x4A0.
                let pkAdrs := or(shl(224, layer), or(shl(128, idxTree), or(shl(96, 1), shl(64, idxLeaf))))
                mstore(0x20, pkAdrs)
                for { let i := 0 } lt(i, 35) { i := add(i, 1) } {
                    mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
                }
                let wotsPk := and(keccak256(0x00, 0x4A0), N_MASK)

                // TREE Merkle auth path (4 levels): type=2, word1=0, word2=height, word3=index.
                // authOff = sigOff + l*N = sigOff + 560.
                let authOff := add(sigOff, 560)
                let treeAdrs := or(shl(224, layer), or(shl(128, idxTree), shl(96, 2)))
                let merkleNode := wotsPk
                let mIdx := idxLeaf
                let merklePtr := add(sigBase, authOff)

                for { let hh := 0 } lt(hh, 4) { hh := add(hh, 1) } {
                    let sibling := and(calldataload(add(merklePtr, shl(4, hh))), N_MASK)
                    let parentIdx := shr(1, mIdx)
                    mstore(0x20, or(treeAdrs, or(shl(32, add(hh, 1)), parentIdx)))
                    let s := shl(5, and(mIdx, 1))
                    mstore(xor(0x40, s), merkleNode)
                    mstore(xor(0x60, s), sibling)
                    merkleNode := and(keccak256(0x00, 0x80), N_MASK)
                    mIdx := parentIdx
                }

                currentNode := merkleNode
                sigOff := add(authOff, 64) // 4*16
            }

            valid := eq(currentNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
