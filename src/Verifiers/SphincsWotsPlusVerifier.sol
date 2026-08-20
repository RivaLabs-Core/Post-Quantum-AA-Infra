// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Signature length of the standard-WOTS+ SPHINCS- blob (no prefix). MUST equal the
///      in-assembly `sig.length` check in `SphincsWotsPlusVerifier.verify` (8288). Distinct from
///      `SPHINCS_SIG_LEN` (8048, the WOTS+C variant) and from `FORS_SIG_LEN` (2448).
uint256 constant SPHINCS_WOTSPLUS_SIG_LEN = 8288;

/// @title SphincsWotsPlusVerifier — stateless SPHINCS- verifier using STANDARD WOTS+
/// @notice Same tree shape as `SphincsVerifier` (n=16 h=20 d=4 a=7 k=29 w=4) but the Winternitz
///         layer is **standard WOTS+ with checksum chains** instead of the constant-sum WOTS+C
///         variant: l = len1 + len2 = 64 + 4 = 68, 8,288-byte signature.
///
///         Difference from the WOTS+C sibling, in full:
///           * l = 68, of which the first 64 chains carry the message digits (64 x logW=2 bits =
///             the full 8n=128-bit digest) and the last 4 carry the base-w checksum.
///           * csum = SUM(w-1-digit_i) over the 64 message digits = 192 - digitSum, range [0,192],
///             encoded as len2=4 base-4 digits. len2 = floor(log2(len1*(w-1))/log2 w) + 1.
///           * There is NO per-layer 4-byte counter. WOTS+C needed one to grind the digit sum onto
///             TARGET_SUM; a checksum is deterministic, so the field is gone and the WOTS message
///             hash is keccak256(pkSeed ‖ ADRS ‖ node) — 96 bytes, not 128.
///           * There is NO digit-sum equality check. Forgery resistance comes from the checksum:
///             raising any message digit lowers csum, and a lower csum cannot be signed because
///             base-w value is monotone in every digit (positive weights), so at least one
///             checksum digit would have to be walked BACKWARD down its chain.
///
///         FORS+C is UNCHANGED — the forced-zero last FORS tree and the R-grinding it implies are
///         orthogonal to the Winternitz layer and are retained exactly as in `SphincsVerifier`.
///
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
///         Signature blob layout:
///           R(16) ‖ 29 FORS secrets (16 each) ‖ 28 FORS auth paths (7*16 each)
///           ‖ 4 x [ 68 WOTS chains (16 each) ‖ subtree auth path (5*16) ]
///
/// @dev    DIGIT ORDER (interop-critical): digits are read LSB-first out of the keccak word —
///         `digit_i = (d >> (i*logW)) & (w-1)` — and the checksum digits likewise
///         `(csum >> (j*logW)) & (w-1)`. This is this codebase's existing convention (see
///         `SphincsVerifier`), NOT the FIPS 205 `base_w` byte order, which reads most-significant
///         first. The scheme is sound either way (the monotonicity argument above depends only on
///         positional weights being positive, not on their order), but a signer MUST mirror this
///         choice or every signature fails.
///
/// @dev    DERIVED (MIT) from the SPHINCS- reference implementation via `SphincsVerifier.sol`.
///         UNAUDITED research prototype, and — like its sibling — it has never verified a real
///         signature, because no signer emits this parameter set yet. Gate any real-funds use on
///         an audit AND on end-to-end vectors.
contract SphincsWotsPlusVerifier {

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
        // Memory high-water mark: the WOTS chain-head buffer spans 0x80 + 32*i for i < l=68,
        // ending at 0x900; the WOTS_PK compression window is keccak256(0x00, 0x8C0). The FORS
        // phase below ends at 0x420 and is fully consumed before the hypertree starts.
        assembly {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            if iszero(eq(sig.length, 8288)) {
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

            // H_msg (domain-separated, 160 bytes) — identical to the WOTS+C sibling, so the two
            // variants share the FORS/hypertree index derivation.
            let R := and(calldataload(sig.offset), N_MASK)
            mstore(0x20, root)
            mstore(0x40, R)
            mstore(0x60, message)
            mstore(0x80, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            let digest := keccak256(0x00, 0xA0)

            // htIdx = (digest >> 203) & (2^20-1). PARAM IDENTITIES: 203 = K*A = 29*7 ;
            // 0xFFFFF = 2^H-1 = 2^20-1. Digest budget: K*A + H = 223 <= 256.
            let htIdx := and(shr(203, digest), 0xFFFFF)

            // ============================================================
            // FORS+C (K=29, A=7) — UNCHANGED from SphincsVerifier
            // ============================================================
            let dVal := digest
            // Forced-zero: last FORS index (i=K-1=28) occupies bits [196,203), a 7-bit field.
            // PARAM IDENTITIES: 196 = (K-1)*A = 28*7 ; 0x7F = 2^A-1.
            // Well-formed-but-invalid signatures return `false`, never an empty revert.
            if and(shr(196, dVal), 0x7F) { mstore(0x00, 0) return(0x00, 0x20) }

            let sigBase := sig.offset

            // SUBTREE_H = 5 (h/d = 20/4). PARAM IDENTITIES: 0x1F = 2^SUBTREE_H-1 ; shift 5.
            let idxLeaf0 := and(htIdx, 0x1F)
            let idxTree0 := shr(5, htIdx)
            // forsBase: tree=idxTree0 (shl 128), type=3 (shl 96), kp=idxLeaf0 (shl 64).
            let forsBase := or(shl(128, idxTree0), or(shl(96, 3), shl(64, idxLeaf0)))

            // K-1=28 normal trees
            for { let i := 0 } lt(i, 28) { i := add(i, 1) } {
                let treeIdx := and(shr(mul(i, 7), dVal), 0x7F) // 7=A-bit indices, shift i*A
                let secretVal := and(calldataload(add(sigBase, add(16, shl(4, i)))), N_MASK)
                // Leaf hash (height 0): word3 = (i << A) | treeIdx, A=7.
                mstore(0x20, or(forsBase, or(shl(7, i), treeIdx)))
                mstore(0x40, secretVal)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                let pathIdx := treeIdx
                // AUTH_START = 16 + K*N = 480, auth per tree = A*N = 112
                let authPtr := add(sigBase, add(480, mul(i, 112)))

                for { let hh := 0 } lt(hh, 7) { hh := add(hh, 1) } {
                    let sibling := and(calldataload(add(authPtr, shl(4, hh))), N_MASK)
                    let parentIdx := shr(1, pathIdx)
                    // word2=height=hh+1; word3 = (i << (A-1-hh)) | parentIdx. 6 = A-1.
                    mstore(0x20, or(forsBase, or(shl(32, add(hh, 1)), or(shl(sub(6, hh), i), parentIdx))))
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
                let lastSecret := and(calldataload(add(sigBase, add(16, shl(4, 28)))), N_MASK) // 464
                mstore(0x20, or(forsBase, shl(7, 28))) // word3 = (K-1) << A
                mstore(0x40, lastSecret)
                mstore(0x400, and(keccak256(0x00, 0x60), N_MASK)) // 0x80 + 28*0x20
            }

            // Compress K=29 roots: keccak256(seed || FORS_ROOTS-ADRS || 29 roots), window
            // 32 + 32 + 29*32 = 0x3E0. Copy is safe: dest 0x40+32i sits two slots below
            // src 0x80+32i, so slot i's source is only clobbered at iteration i+2.
            mstore(0x20, or(shl(128, idxTree0), or(shl(96, 4), shl(64, idxLeaf0))))
            for { let i := 0 } lt(i, 29) { i := add(i, 1) } {
                mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
            }
            let forsPk := and(keccak256(0x00, 0x3E0), N_MASK)

            // ============================================================
            // Hypertree (D=4, subtree_h=5, w=4, l=68 = 64 msg + 4 checksum, NO counter)
            // ============================================================
            let currentNode := forsPk
            let idxTree := htIdx
            let sigOff := 3616 // HT_START = 16 + K*N + (K-1)*A*N = 480 + 3136

            for { let layer := 0 } lt(layer, 4) { layer := add(layer, 1) } {
                let idxLeaf := and(idxTree, 0x1F) // 2^5 - 1
                idxTree := shr(5, idxTree)

                // WOTS_HASH base ADRS for this WOTS keypair (type=0 implicit):
                //   layer, tree=idxTree, word1=idxLeaf (key_pair_address)
                let wotsAdrs := or(shl(224, layer), or(shl(128, idxTree), shl(64, idxLeaf)))

                // WOTS-message digest. NO counter word: standard WOTS+ needs no grinding, so
                // this is 96 bytes (seed ‖ ADRS ‖ node) where WOTS+C hashed 128.
                mstore(0x20, wotsAdrs)
                mstore(0x40, currentNode)
                let dw := keccak256(0x00, 0x60)

                // Checksum over the 64 message digits: csum = SUM(w-1-digit) = 192 - digitSum.
                // PARAM IDENTITIES: bound 64 = LEN1 ; shift 2 = LOG_W ; mask 0x3 = W-1 ;
                // 192 = LEN1*(W-1), the maximum csum and the value at digitSum == 0.
                let digitSum := 0
                for { let ii := 0 } lt(ii, 64) { ii := add(ii, 1) } {
                    digitSum := add(digitSum, and(shr(mul(ii, 2), dw), 0x3))
                }
                let csum := sub(192, digitSum)

                // 68 WOTS chains (w=4: max 3 steps each). Chains [0,64) take message digits from
                // `dw`; chains [64,68) take the LEN2=4 base-4 digits of csum. csum <= 192 < 4^4,
                // so the 4 digits capture it exactly.
                let wotsPtr := add(sigBase, sigOff)
                for { let i := 0 } lt(i, 68) { i := add(i, 1) } {
                    let digit
                    switch lt(i, 64)
                    case 1 { digit := and(shr(mul(i, 2), dw), 0x3) }
                    default { digit := and(shr(mul(sub(i, 64), 2), csum), 0x3) }

                    let steps := sub(3, digit)
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

                // WOTS_PK compression: type=1, word1=idxLeaf. Window 32+32+68*32 = 0x8C0.
                let pkAdrs := or(shl(224, layer), or(shl(128, idxTree), or(shl(96, 1), shl(64, idxLeaf))))
                mstore(0x20, pkAdrs)
                for { let i := 0 } lt(i, 68) { i := add(i, 1) } {
                    mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
                }
                let wotsPk := and(keccak256(0x00, 0x8C0), N_MASK)

                // TREE Merkle auth path (5 levels): type=2, word1=0, word2=height, word3=index.
                // authOff = sigOff + l*N = sigOff + 1088 (no counter field in between).
                let authOff := add(sigOff, 1088)
                let treeAdrs := or(shl(224, layer), or(shl(128, idxTree), shl(96, 2)))
                let merkleNode := wotsPk
                let mIdx := idxLeaf
                let merklePtr := add(sigBase, authOff)

                for { let hh := 0 } lt(hh, 5) { hh := add(hh, 1) } {
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
                sigOff := add(authOff, 80) // 5*16
            }

            valid := eq(currentNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
