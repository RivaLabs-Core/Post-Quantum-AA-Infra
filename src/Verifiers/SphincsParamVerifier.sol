// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SphincsParamsLib} from "./SphincsParamsLib.sol";

/// @title SphincsParamVerifier — stateless PARAMETRIC SPHINCS- verifier (Yul, keccak256)
/// @notice Generalization of `SphincsVerifier` in which the SPHINCS- parameter set
///         (h, d, k, a, logW, l, targetSum — see `SphincsParamsLib`) is a runtime input instead
///         of a compile-time constant. With the canonical set {22,2,7,19,3,43,208} it reproduces
///         the fixed verifier bit-for-bit: identical H_msg (keccak(pkSeed ‖ pkRoot ‖ R ‖ message ‖
///         PAD 0xFF…FF), 160 bytes), identical FIPS 205 §4.2 uncompressed 32-byte ADRS layout,
///         identical FORS+C forced-zero-last-index and WOTS+C target-sum rules — so existing
///         signer tooling and the reference vector work unchanged. n is FIXED at 16
///         (top-128-bit-aligned words / N_MASK); only the tree-shape parameters vary.
///
///         Signature blob layout (lengths from `SphincsParamsLib.blobLen`):
///           R(16) ‖ k FORS secrets (16 each) ‖ (k-1) FORS auth paths (a*16 each)
///           ‖ d × [ l WOTS chains (16 each) ‖ counter(4) ‖ subtree auth path ((h/d)*16) ]
///
///         Soundness rejections (forced-zero violation, WOTS digit-sum mismatch, root mismatch)
///         uniformly return `false`; malformed INPUTS (bad params, wrong length, non-canonical
///         public key) revert — mirroring the fixed verifier's bool-vs-revert contract.
/// @dev DERIVED from `SphincsVerifier.sol` (itself vendored verbatim from the SPHINCS- reference
///      implementation, MIT — see docs/sphincs-backup-recovery.md for provenance). The FORS /
///      hypertree assembly below is the upstream logic with every hardcoded parameter identity
///      (the "PARAM IDENTITIES" callouts in the fixed file) replaced by the corresponding runtime
///      value; nothing else was changed. Param-derived scalars are spilled to fixed high-memory
///      slots (0x2100+) to keep Yul stack pressure low — see the memory map below. UNAUDITED
///      research prototype; gate any real-funds use on an audit of this contract.
///
///      FUTURE NOTE: a production deployment may instead restrict accounts to a predetermined
///      menu of parameter sets, each served by a fixed-constant verifier like `SphincsVerifier`
///      (cheaper, smaller audit surface) — removing this flexible verifier and the per-signer
///      params mapping entirely. This contract is the fully-general stepping stone.
///
///      Memory map inside `verify` (FMP deliberately not honored, see NOTE in the function):
///        0x00          pkSeed (persistent tweakable-hash prefix)
///        0x20..0x80    per-hash ADRS + payload scratch
///        0x80 + 32*i   node buffer (k FORS roots, then reused for l WOTS chain heads);
///                      k,l <= 255 (uint8) so all buffer/compress writes end below 0x2080
///        0x2100..      param spill slots (k, a, aMask, subtreeH, subtreeMask, l, logW, wMask,
///                      targetSum, d, k*a, authStart, htStart) — above every dynamic write
contract SphincsParamVerifier {
    uint256 private constant N_MASK_WORD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000;

    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, uint256 packedParams, bytes calldata sig)
        external
        pure
        returns (bool valid)
    {
        // ---- Solidity prelude: every malformed-INPUT revert lives here, so the assembly block
        //      below keeps the fixed verifier's contract (all soundness exits are in-asm returns).
        require(packedParams >> 64 == 0, "Invalid params");
        SphincsParamsLib.Params memory p = SphincsParamsLib.unpack(packedParams);
        SphincsParamsLib.validate(p); // reverts "SphincsParams: ..." on any inexecutable set

        require(sig.length == SphincsParamsLib.blobLen(p), "Invalid sig length");

        // Reject non-canonical public keys (low 128 bits must be zero) — a non-top-aligned key
        // can never equal the always-N_MASK'd final node, silently bricking; fail loudly instead.
        require(
            uint256(pkSeed) & N_MASK_WORD == uint256(pkSeed) && uint256(pkRoot) & N_MASK_WORD == uint256(pkRoot),
            "Invalid public key"
        );

        // NOTE: this block intentionally uses Solidity's free-memory-pointer slot (0x40) and the
        // zero slot (0x60) as scratch and writes high memory without updating the FMP. That is
        // only sound because every exit below is an unconditional in-assembly `return`, so
        // Solidity never regains control with a clobbered FMP (the prelude above has already
        // finished every Solidity-level computation). It is therefore NOT `memory-safe` in the
        // Yul sense — do not add the ("memory-safe") annotation and do not introduce a normal
        // (fall-through) exit from this block.
        assembly {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            // ---- Spill param-derived scalars to fixed slots above every dynamic buffer write
            //      (worst case k=l=255: buffer/compress writes end at 0x2080 < 0x2100). Keeps
            //      concurrent Yul stack depth in the hot loops at the fixed verifier's level.
            {
                let k := and(shr(16, packedParams), 0xFF)
                let a := and(shr(24, packedParams), 0xFF)
                mstore(0x2100, k)
                mstore(0x2120, a)
                mstore(0x2140, sub(shl(a, 1), 1)) // aMask = 2^a - 1
                let subtreeH := div(and(packedParams, 0xFF), and(shr(8, packedParams), 0xFF)) // h/d
                mstore(0x2160, subtreeH)
                mstore(0x2180, sub(shl(subtreeH, 1), 1)) // subtreeMask = 2^(h/d) - 1
                mstore(0x21A0, and(shr(40, packedParams), 0xFF)) // l
                mstore(0x21C0, and(shr(32, packedParams), 0xFF)) // logW
                mstore(0x21E0, sub(shl(and(shr(32, packedParams), 0xFF), 1), 1)) // wMask = w - 1
                mstore(0x2200, and(shr(48, packedParams), 0xFFFF)) // targetSum
                mstore(0x2220, and(shr(8, packedParams), 0xFF)) // d
                mstore(0x2240, mul(k, a)) // kA (htIdx shift; forced-zero shift = kA - a)
                mstore(0x2260, shl(4, add(1, k))) // AUTH_START = 16*(1 + k)
                mstore(0x2280, shl(4, add(add(1, k), mul(sub(k, 1), a)))) // HT_START = 16*(1 + k + (k-1)*a)
            }

            mstore(0x00, pkSeed)

            // H_msg (domain-separated, 160 bytes) — IDENTICAL to the fixed stateless verifier:
            // keccak256(pkSeed ‖ pkRoot ‖ R ‖ message ‖ PAD 0xFF…FF). PAD stays distinct from
            // FORS+C's 0xFF…FD and the indexed variant's 0xFF…FE.
            let R := and(calldataload(sig.offset), N_MASK)
            mstore(0x20, pkRoot)
            mstore(0x40, R)
            mstore(0x60, message)
            mstore(0x80, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            let digest := keccak256(0x00, 0xA0)

            // htIdx = (digest >> k*a) & (2^h - 1)   [fixed file: 133 = K*A, 0x3FFFFF = 2^H - 1]
            let htIdx := and(shr(mload(0x2240), digest), sub(shl(and(packedParams, 0xFF), 1), 1))

            // FORS+C forced-zero: the last FORS index (i = k-1) occupies digest bits
            // [(k-1)*a, k*a) and must be zero. A well-formed-but-invalid signature is rejected by
            // returning `false` (the bool contract), NOT by a revert — uniform across callers.
            if and(shr(sub(mload(0x2240), mload(0x2120)), digest), mload(0x2140)) {
                mstore(0x00, 0)
                return(0x00, 0x20)
            }

            let sigBase := sig.offset

            // Split htIdx into bottom subtree + leaf [fixed file: SUBTREE_H = 11].
            // forsBase: tree=idxTree0 (shl 128), type=3 (shl 96), kp=idxLeaf0 (shl 64); per-site
            // we OR in word2=height (shl 32) and word3=tree_index (shl 0).
            let forsBase :=
                or(
                    shl(128, shr(mload(0x2160), htIdx)),
                    or(shl(96, 3), shl(64, and(htIdx, mload(0x2180))))
                )

            // k-1 normal FORS trees (the k-th is the forced-zero tree, no auth path)
            {
                let a := mload(0x2120)
                let aMask := mload(0x2140)
                let kM1 := sub(mload(0x2100), 1)
                let authBase := add(sigBase, mload(0x2260))
                let authTreeLen := shl(4, a) // auth path bytes per tree = a*16
                for { let i := 0 } lt(i, kM1) { i := add(i, 1) } {
                    let treeIdx := and(shr(mul(i, a), digest), aMask)
                    // Leaf hash (height 0): word3 = (i << a) | treeIdx (folds the k FORS trees
                    // into one tree_index space, FIPS 205 Alg. 17)
                    mstore(0x20, or(forsBase, or(shl(a, i), treeIdx)))
                    mstore(0x40, and(calldataload(add(sigBase, add(16, shl(4, i)))), N_MASK))
                    let node := and(keccak256(0x00, 0x60), N_MASK)

                    let pathIdx := treeIdx
                    let authPtr := add(authBase, mul(i, authTreeLen))

                    // Walk a auth-path levels
                    for { let h := 0 } lt(h, a) { h := add(h, 1) } {
                        let parentIdx := shr(1, pathIdx)
                        // word2=height=h+1; word3 = (i << (a-1-h)) | parentIdx
                        mstore(0x20, or(forsBase, or(shl(32, add(h, 1)), or(shl(sub(sub(a, 1), h), i), parentIdx))))
                        // Branchless Merkle swap (Solady)
                        let s := shl(5, and(pathIdx, 1))
                        mstore(xor(0x40, s), node)
                        mstore(xor(0x60, s), and(calldataload(add(authPtr, shl(4, h))), N_MASK))
                        node := and(keccak256(0x00, 0x80), N_MASK)
                        pathIdx := parentIdx
                    }
                    mstore(add(0x80, shl(5, i)), node)
                }

                // Last tree (forced-zero): secret is the revealed root, hashed under FORS_TREE
                // leaf ADRS as leaf node 0: word3 = ((k-1) << a).
                mstore(0x20, or(forsBase, shl(a, kM1)))
                mstore(0x40, and(calldataload(add(sigBase, add(16, shl(4, kM1)))), N_MASK))
                mstore(add(0x80, shl(5, kM1)), and(keccak256(0x00, 0x60), N_MASK))
            }

            // Compress k roots: keccak256(seed ‖ FORS_ROOTS-ADRS ‖ k roots). FORS_ROOTS ADRS is
            // forsBase with type 3 -> 4 (word2/word3 zero in forsBase, so a plain +1<<96 works).
            let currentNode
            {
                let k := mload(0x2100)
                mstore(0x20, add(forsBase, shl(96, 1)))
                for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                    mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
                }
                currentNode := and(keccak256(0x00, add(0x40, shl(5, k))), N_MASK)
            }

            // ============================================================
            // Hypertree: d layers of [WOTS+C chain walk -> pk compress -> subtree Merkle walk]
            //
            // FIPS ADRS bit positions (as in the fixed file):
            //   layer at shl(224), tree at shl(128) (96-bit), type at shl(96),
            //   word1 (kp) at shl(64), word2 at shl(32), word3 at shl(0)
            // ============================================================
            let idxTree := htIdx
            let sigOff := mload(0x2280) // HT_START

            for { let layer := 0 } lt(layer, mload(0x2220)) { layer := add(layer, 1) } {
                let subtreeH := mload(0x2160)
                let idxLeaf := and(idxTree, mload(0x2180))
                idxTree := shr(subtreeH, idxTree)

                // WOTS_HASH base ADRS (type=0 implicit): layer, tree=idxTree, word1=idxLeaf
                let wotsAdrs := or(shl(224, layer), or(shl(128, idxTree), shl(64, idxLeaf)))
                let l := mload(0x21A0)
                let countOff := add(sigOff, shl(4, l)) // counter sits after the l chains

                // WOTS-message digest: keccak(seed ‖ wotsAdrs ‖ currentNode ‖ counter)
                mstore(0x20, wotsAdrs)
                mstore(0x40, currentNode)
                mstore(0x60, shr(224, calldataload(add(sigBase, countOff))))
                let d := keccak256(0x00, 0x80)

                let logW := mload(0x21C0)
                let wMask := mload(0x21E0)

                // Validate WOTS+C digit sum == targetSum (l base-w digits, logW bits each).
                // A mismatch is a well-formed-but-invalid signature -> return `false`.
                {
                    let digitSum := 0
                    for { let ii := 0 } lt(ii, l) { ii := add(ii, 1) } {
                        digitSum := add(digitSum, and(shr(mul(ii, logW), d), wMask))
                    }
                    if iszero(eq(digitSum, mload(0x2200))) {
                        mstore(0x00, 0)
                        return(0x00, 0x20)
                    }
                }

                // l WOTS chains (max w-1 steps per chain)
                let wotsPtr := add(sigBase, sigOff)
                for { let i := 0 } lt(i, l) { i := add(i, 1) } {
                    let digit := and(shr(mul(i, logW), d), wMask)
                    let steps := sub(wMask, digit)
                    let val := and(calldataload(add(wotsPtr, shl(4, i))), N_MASK)
                    // FIPS WOTS_HASH: word2=chain_address=i, word3=hash_address=digit+step
                    let chainBase := or(wotsAdrs, shl(32, i))

                    for { let step := 0 } lt(step, steps) { step := add(step, 1) } {
                        mstore(0x20, or(chainBase, add(digit, step)))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), N_MASK)
                    }
                    mstore(add(0x80, shl(5, i)), val)
                }

                // WOTS_PK compression: type=1, word1=idxLeaf (wotsAdrs has type/word2/word3 = 0)
                mstore(0x20, or(wotsAdrs, shl(96, 1)))
                for { let i := 0 } lt(i, l) { i := add(i, 1) } {
                    mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
                }
                currentNode := and(keccak256(0x00, add(0x40, shl(5, l))), N_MASK)

                // TREE Merkle auth path (h/d levels): type=2, word2=tree_height, word3=tree_index
                let authOff := add(countOff, 4)
                let treeAdrs := or(shl(224, layer), or(shl(128, idxTree), shl(96, 2)))
                let mIdx := idxLeaf
                let merklePtr := add(sigBase, authOff)

                for { let h := 0 } lt(h, subtreeH) { h := add(h, 1) } {
                    let parentIdx := shr(1, mIdx)
                    mstore(0x20, or(treeAdrs, or(shl(32, add(h, 1)), parentIdx)))
                    let s := shl(5, and(mIdx, 1))
                    mstore(xor(0x40, s), currentNode)
                    mstore(xor(0x60, s), and(calldataload(add(merklePtr, shl(4, h))), N_MASK))
                    currentNode := and(keccak256(0x00, 0x80), N_MASK)
                    mIdx := parentIdx
                }

                sigOff := add(authOff, shl(4, subtreeH))
            }

            valid := eq(currentNode, pkRoot)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
