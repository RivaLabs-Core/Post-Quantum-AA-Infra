// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ISphincsVerifier} from "../Interfaces/ISphincsVerifier.sol";

uint256 constant SPHINCS_FAST_TRADE_PLUS_SIG_LEN = 5804;
uint256 constant SPHINCS_DEFAULT_MINUS_SIG_LEN = 3976;
uint256 constant SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_SIG_LEN = 3028;
uint256 constant SPHINCS_PLUS_128S_SIG_LEN = 7856;

uint256 constant SPHINCS_PARAM_N = 16;

uint256 constant SPHINCS_FAST_TRADE_PLUS_H = 15;
uint256 constant SPHINCS_FAST_TRADE_PLUS_D = 3;
uint256 constant SPHINCS_FAST_TRADE_PLUS_SUBTREE_H = 5;
uint256 constant SPHINCS_FAST_TRADE_PLUS_A = 8;
uint256 constant SPHINCS_FAST_TRADE_PLUS_K = 25;
uint256 constant SPHINCS_FAST_TRADE_PLUS_W = 8;
uint256 constant SPHINCS_FAST_TRADE_PLUS_L = 43;
uint256 constant SPHINCS_FAST_TRADE_PLUS_TARGET_SUM = 196;

uint256 constant SPHINCS_DEFAULT_MINUS_H = 20;
uint256 constant SPHINCS_DEFAULT_MINUS_D = 2;
uint256 constant SPHINCS_DEFAULT_MINUS_SUBTREE_H = 10;
uint256 constant SPHINCS_DEFAULT_MINUS_A = 13;
uint256 constant SPHINCS_DEFAULT_MINUS_K = 11;
uint256 constant SPHINCS_DEFAULT_MINUS_W = 8;
uint256 constant SPHINCS_DEFAULT_MINUS_L = 43;
uint256 constant SPHINCS_DEFAULT_MINUS_TARGET_SUM = 215;

uint256 constant SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_H = 18;
uint256 constant SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_D = 1;
uint256 constant SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_SUBTREE_H = 18;
uint256 constant SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_A = 20;
uint256 constant SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_K = 7;
uint256 constant SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_W = 8;
uint256 constant SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_L = 43;
uint256 constant SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_TARGET_SUM = 217;

uint256 constant SPHINCS_PLUS_128S_H = 63;
uint256 constant SPHINCS_PLUS_128S_D = 7;
uint256 constant SPHINCS_PLUS_128S_SUBTREE_H = 9;
uint256 constant SPHINCS_PLUS_128S_A = 12;
uint256 constant SPHINCS_PLUS_128S_K = 14;
uint256 constant SPHINCS_PLUS_128S_W = 16;
uint256 constant SPHINCS_PLUS_128S_L = 35;

uint256 constant SPHINCS_TOP_N_MASK = type(uint256).max << 128;
uint256 constant SPHINCS_HMSG_DOM = type(uint256).max;

/// @dev Shared implementation for the extra SPHINCS parameter-set verifiers.
///      The assembly exits with raw ABI bool returns, exactly like the vendored
///      SphincsVerifier, so callers must not append post-processing after it.
library SphincsVerifierCore {
    function verifyMinus(
        bytes32 pkSeed,
        bytes32 pkRoot,
        bytes32 message,
        bytes calldata sig,
        uint256 sigLen,
        uint256 h,
        uint256 dLayers,
        uint256 subtreeH,
        uint256 a,
        uint256 k,
        uint256 l,
        uint256 targetSum
    ) internal pure returns (bool) {
        _checkCommon(pkSeed, pkRoot, sig, sigLen);

        uint256 nMask = SPHINCS_TOP_N_MASK;
        uint256 dom = SPHINCS_HMSG_DOM;
        uint256 hMask = (uint256(1) << h) - 1;
        uint256 aMask = (uint256(1) << a) - 1;
        uint256 subtreeMask = (uint256(1) << subtreeH) - 1;
        uint256 kMinus1 = k - 1;
        uint256 kA = k * a;
        uint256 kMinus1A = kMinus1 * a;
        uint256 authStart = 16 + k * 16;
        uint256 forsAuthTreeBytes = a * 16;
        uint256 htStart = authStart + kMinus1 * forsAuthTreeBytes;
        uint256 wotsBytes = l * 16;
        uint256 xmssAuthBytes = subtreeH * 16;
        uint256 forsRootsHashLen = 64 + k * 32;
        uint256 wotsPkHashLen = 64 + l * 32;

        assembly ("memory-safe") {
            let seed := pkSeed
            let root := pkRoot
            let sigBase := sig.offset

            mstore(0x00, seed)

            // H_msg = keccak256(seed || root || R || message || dom)
            let R := and(calldataload(sigBase), nMask)
            mstore(0x20, root)
            mstore(0x40, R)
            mstore(0x60, message)
            mstore(0x80, dom)
            let digest := keccak256(0x00, 0xa0)

            let htIdx := and(shr(kA, digest), hMask)
            let dVal := digest

            // FORS+C: the last A-bit FORS index is forced to zero and its auth
            // path is omitted from the signature.
            if and(shr(kMinus1A, dVal), aMask) {
                mstore(0x00, 0)
                return(0x00, 0x20)
            }

            let idxLeaf0 := and(htIdx, subtreeMask)
            let idxTree0 := shr(subtreeH, htIdx)
            let forsBase := or(shl(128, idxTree0), or(shl(96, 3), shl(64, idxLeaf0)))

            let forsIndices := dVal
            let secretPtr := add(sigBase, 16)
            let forsAuthPtr := add(sigBase, authStart)
            let forsRootPtr := 0x80

            for { let i := 0 } lt(i, kMinus1) { i := add(i, 1) } {
                let treeIdx := and(forsIndices, aMask)
                forsIndices := shr(a, forsIndices)
                let secretVal := and(calldataload(secretPtr), nMask)

                mstore(0x20, or(forsBase, or(shl(a, i), treeIdx)))
                mstore(0x40, secretVal)
                let node := and(keccak256(0x00, 0x60), nMask)

                let pathIdx := treeIdx
                let siblingPtr := forsAuthPtr

                for { let hh := 0 } lt(hh, a) { hh := add(hh, 1) } {
                    let sibling := and(calldataload(siblingPtr), nMask)
                    siblingPtr := add(siblingPtr, 16)
                    let parentIdx := shr(1, pathIdx)
                    mstore(0x20, or(forsBase, or(shl(32, add(hh, 1)), or(shl(sub(sub(a, 1), hh), i), parentIdx))))
                    let s := shl(5, and(pathIdx, 1))
                    mstore(xor(0x40, s), node)
                    mstore(xor(0x60, s), sibling)
                    node := and(keccak256(0x00, 0x80), nMask)
                    pathIdx := parentIdx
                }

                mstore(forsRootPtr, node)
                secretPtr := add(secretPtr, 16)
                forsAuthPtr := add(forsAuthPtr, forsAuthTreeBytes)
                forsRootPtr := add(forsRootPtr, 0x20)
            }

            {
                let lastSecret := and(calldataload(secretPtr), nMask)
                mstore(0x20, or(forsBase, shl(a, kMinus1)))
                mstore(0x40, lastSecret)
                mstore(forsRootPtr, and(keccak256(0x00, 0x60), nMask))
            }

            // Compress K FORS roots.
            mstore(0x20, or(shl(128, idxTree0), or(shl(96, 4), shl(64, idxLeaf0))))
            mcopy(0x40, 0x80, mul(k, 0x20))
            let currentNode := and(keccak256(0x00, forsRootsHashLen), nMask)

            let idxTree := htIdx
            let sigOff := htStart

            for { let layer := 0 } lt(layer, dLayers) { layer := add(layer, 1) } {
                let idxLeaf := and(idxTree, subtreeMask)
                idxTree := shr(subtreeH, idxTree)

                let wotsAdrs := or(shl(224, layer), or(shl(128, idxTree), shl(64, idxLeaf)))
                let countOff := add(sigOff, wotsBytes)
                let count := shr(224, calldataload(add(sigBase, countOff)))

                mstore(0x20, wotsAdrs)
                mstore(0x40, currentNode)
                mstore(0x60, count)
                let wotsDigest := keccak256(0x00, 0x80)

                // Sum the 43 packed base-8 digits in six reduction stages.
                let digitSum := and(wotsDigest, 0x1ffffffffffffffffffffffffffffffff)
                digitSum :=
                    add(
                        and(digitSum, 0x71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c7),
                        and(shr(3, digitSum), 0x71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c7)
                    )
                digitSum :=
                    add(
                        and(digitSum, 0xf03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f),
                        and(shr(6, digitSum), 0xf03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f)
                    )
                digitSum :=
                    add(
                        and(digitSum, 0x0fff000fff000fff000fff000fff000fff000fff000fff000fff000fff000fff),
                        and(shr(12, digitSum), 0x0fff000fff000fff000fff000fff000fff000fff000fff000fff000fff000fff)
                    )
                digitSum :=
                    add(
                        and(digitSum, 0xffff000000ffffff000000ffffff000000ffffff000000ffffff000000ffffff),
                        and(shr(24, digitSum), 0xffff000000ffffff000000ffffff000000ffffff000000ffffff000000ffffff)
                    )
                digitSum :=
                    add(
                        and(digitSum, 0x0000ffffffffffff000000000000ffffffffffff000000000000ffffffffffff),
                        and(shr(48, digitSum), 0x0000ffffffffffff000000000000ffffffffffff000000000000ffffffffffff)
                    )
                digitSum := add(and(digitSum, 0xffffffffffffffffffffffff), shr(96, digitSum))
                if iszero(eq(digitSum, targetSum)) {
                    mstore(0x00, 0)
                    return(0x00, 0x20)
                }

                let wotsPtr := add(sigBase, sigOff)
                let wotsResultPtr := 0x80
                let wotsDigits := wotsDigest
                for { let i := 0 } lt(i, l) { i := add(i, 1) } {
                    let digit := and(wotsDigits, 0x7)
                    wotsDigits := shr(3, wotsDigits)
                    let val := and(calldataload(wotsPtr), nMask)
                    let chainBase := or(wotsAdrs, shl(32, i))

                    let hashAddress := digit
                    for {} lt(hashAddress, 6) { hashAddress := add(hashAddress, 2) } {
                        mstore(0x20, or(chainBase, hashAddress))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), nMask)

                        mstore(0x20, or(chainBase, add(hashAddress, 1)))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), nMask)
                    }
                    if lt(hashAddress, 7) {
                        mstore(0x20, or(chainBase, hashAddress))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), nMask)
                    }
                    mstore(wotsResultPtr, val)
                    wotsPtr := add(wotsPtr, 16)
                    wotsResultPtr := add(wotsResultPtr, 0x20)
                }

                let pkAdrs := or(shl(224, layer), or(shl(128, idxTree), or(shl(96, 1), shl(64, idxLeaf))))
                mstore(0x20, pkAdrs)
                mcopy(0x40, 0x80, mul(l, 0x20))
                let wotsPk := and(keccak256(0x00, wotsPkHashLen), nMask)

                let authOff := add(countOff, 4)
                let treeAdrs := or(shl(224, layer), or(shl(128, idxTree), shl(96, 2)))
                let merkleNode := wotsPk
                let mIdx := idxLeaf
                let merklePtr := add(wotsPtr, 4)

                for { let hh := 0 } lt(hh, subtreeH) { hh := add(hh, 1) } {
                    let sibling := and(calldataload(merklePtr), nMask)
                    merklePtr := add(merklePtr, 16)
                    let parentIdx := shr(1, mIdx)
                    mstore(0x20, or(treeAdrs, or(shl(32, add(hh, 1)), parentIdx)))
                    let s := shl(5, and(mIdx, 1))
                    mstore(xor(0x40, s), merkleNode)
                    mstore(xor(0x60, s), sibling)
                    merkleNode := and(keccak256(0x00, 0x80), nMask)
                    mIdx := parentIdx
                }

                currentNode := merkleNode
                sigOff := add(authOff, xmssAuthBytes)
            }

            mstore(0x00, eq(currentNode, root))
            return(0x00, 0x20)
        }
    }

    function verifyPlus128s(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        internal
        pure
        returns (bool)
    {
        _checkCommon(pkSeed, pkRoot, sig, SPHINCS_PLUS_128S_SIG_LEN);

        uint256 nMask = SPHINCS_TOP_N_MASK;
        uint256 dom = SPHINCS_HMSG_DOM;
        uint256 hMask = (uint256(1) << SPHINCS_PLUS_128S_H) - 1;
        uint256 aMask = (uint256(1) << SPHINCS_PLUS_128S_A) - 1;
        uint256 subtreeMask = (uint256(1) << SPHINCS_PLUS_128S_SUBTREE_H) - 1;
        uint256 kA = SPHINCS_PLUS_128S_K * SPHINCS_PLUS_128S_A;
        uint256 forsTreeBytes = (1 + SPHINCS_PLUS_128S_A) * 16;
        uint256 htStart = 16 + SPHINCS_PLUS_128S_K * forsTreeBytes;
        uint256 wotsBytes = SPHINCS_PLUS_128S_L * 16;
        uint256 xmssAuthBytes = SPHINCS_PLUS_128S_SUBTREE_H * 16;

        assembly ("memory-safe") {
            let seed := pkSeed
            let root := pkRoot
            let sigBase := sig.offset

            mstore(0x00, seed)

            // H_msg = keccak256(seed || root || R || message || dom)
            let R := and(calldataload(sigBase), nMask)
            mstore(0x20, root)
            mstore(0x40, R)
            mstore(0x60, message)
            mstore(0x80, dom)
            let digest := keccak256(0x00, 0xa0)

            let htIdx := and(shr(kA, digest), hMask)
            let dVal := digest

            let idxLeaf0 := and(htIdx, subtreeMask)
            let idxTree0 := shr(SPHINCS_PLUS_128S_SUBTREE_H, htIdx)
            let forsBase := or(shl(128, idxTree0), or(shl(96, 3), shl(64, idxLeaf0)))

            // Standard FORS: every tree carries sk || A auth nodes.
            let forsTreePtr := add(sigBase, 16)
            let forsRootPtr := 0x80
            let forsIndices := dVal
            for { let i := 0 } lt(i, SPHINCS_PLUS_128S_K) { i := add(i, 1) } {
                let treeIdx := and(forsIndices, aMask)
                forsIndices := shr(SPHINCS_PLUS_128S_A, forsIndices)
                let secretVal := and(calldataload(forsTreePtr), nMask)

                mstore(0x20, or(forsBase, or(shl(SPHINCS_PLUS_128S_A, i), treeIdx)))
                mstore(0x40, secretVal)
                let node := and(keccak256(0x00, 0x60), nMask)

                let pathIdx := treeIdx
                let authPtr := add(forsTreePtr, 16)

                for { let hh := 0 } lt(hh, SPHINCS_PLUS_128S_A) { hh := add(hh, 1) } {
                    let sibling := and(calldataload(authPtr), nMask)
                    authPtr := add(authPtr, 16)
                    let parentIdx := shr(1, pathIdx)
                    mstore(
                        0x20,
                        or(
                            forsBase,
                            or(shl(32, add(hh, 1)), or(shl(sub(sub(SPHINCS_PLUS_128S_A, 1), hh), i), parentIdx))
                        )
                    )
                    let s := shl(5, and(pathIdx, 1))
                    mstore(xor(0x40, s), node)
                    mstore(xor(0x60, s), sibling)
                    node := and(keccak256(0x00, 0x80), nMask)
                    pathIdx := parentIdx
                }

                mstore(forsRootPtr, node)
                forsTreePtr := add(forsTreePtr, forsTreeBytes)
                forsRootPtr := add(forsRootPtr, 0x20)
            }

            // Compress K FORS roots.
            mstore(0x20, or(shl(128, idxTree0), or(shl(96, 4), shl(64, idxLeaf0))))
            mcopy(0x40, 0x80, mul(SPHINCS_PLUS_128S_K, 0x20))
            let currentNode := and(keccak256(0x00, 0x200), nMask)

            let idxTree := htIdx
            let sigOff := htStart

            for { let layer := 0 } lt(layer, SPHINCS_PLUS_128S_D) { layer := add(layer, 1) } {
                let idxLeaf := and(idxTree, subtreeMask)
                idxTree := shr(SPHINCS_PLUS_128S_SUBTREE_H, idxTree)

                let wotsAdrs := or(shl(224, layer), or(shl(128, idxTree), shl(64, idxLeaf)))
                let wotsPtr := add(sigBase, sigOff)
                let wotsResultPtr := 0x80

                // Standard WOTS+ for w=16: 32 message nibbles from the 16-byte
                // current root, followed by the 3-nibble checksum.
                let csum := 0
                let messageDigits := currentNode
                for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                    let digit := shr(252, messageDigits)
                    messageDigits := shl(4, messageDigits)
                    csum := add(csum, sub(15, digit))

                    let val := and(calldataload(wotsPtr), nMask)
                    let chainBase := or(wotsAdrs, shl(32, i))

                    let hashAddress := digit
                    for {} lt(hashAddress, 12) { hashAddress := add(hashAddress, 4) } {
                        mstore(0x20, or(chainBase, hashAddress))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), nMask)

                        mstore(0x20, or(chainBase, add(hashAddress, 1)))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), nMask)

                        mstore(0x20, or(chainBase, add(hashAddress, 2)))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), nMask)

                        mstore(0x20, or(chainBase, add(hashAddress, 3)))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), nMask)
                    }
                    for {} lt(hashAddress, 15) { hashAddress := add(hashAddress, 1) } {
                        mstore(0x20, or(chainBase, hashAddress))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), nMask)
                    }
                    mstore(wotsResultPtr, val)
                    wotsPtr := add(wotsPtr, 16)
                    wotsResultPtr := add(wotsResultPtr, 0x20)
                }

                let checksumDigits := shl(244, csum)
                for { let j := 0 } lt(j, 3) { j := add(j, 1) } {
                    let i := add(32, j)
                    let digit := shr(252, checksumDigits)
                    checksumDigits := shl(4, checksumDigits)
                    let val := and(calldataload(wotsPtr), nMask)
                    let chainBase := or(wotsAdrs, shl(32, i))

                    let hashAddress := digit
                    for {} lt(hashAddress, 12) { hashAddress := add(hashAddress, 4) } {
                        mstore(0x20, or(chainBase, hashAddress))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), nMask)

                        mstore(0x20, or(chainBase, add(hashAddress, 1)))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), nMask)

                        mstore(0x20, or(chainBase, add(hashAddress, 2)))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), nMask)

                        mstore(0x20, or(chainBase, add(hashAddress, 3)))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), nMask)
                    }
                    for {} lt(hashAddress, 15) { hashAddress := add(hashAddress, 1) } {
                        mstore(0x20, or(chainBase, hashAddress))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), nMask)
                    }
                    mstore(wotsResultPtr, val)
                    wotsPtr := add(wotsPtr, 16)
                    wotsResultPtr := add(wotsResultPtr, 0x20)
                }

                let pkAdrs := or(shl(224, layer), or(shl(128, idxTree), or(shl(96, 1), shl(64, idxLeaf))))
                mstore(0x20, pkAdrs)
                mcopy(0x40, 0x80, mul(SPHINCS_PLUS_128S_L, 0x20))
                let wotsPk := and(keccak256(0x00, 0x4a0), nMask)

                let authOff := add(sigOff, wotsBytes)
                let treeAdrs := or(shl(224, layer), or(shl(128, idxTree), shl(96, 2)))
                let merkleNode := wotsPk
                let mIdx := idxLeaf
                let merklePtr := wotsPtr

                for { let hh := 0 } lt(hh, SPHINCS_PLUS_128S_SUBTREE_H) { hh := add(hh, 1) } {
                    let sibling := and(calldataload(merklePtr), nMask)
                    merklePtr := add(merklePtr, 16)
                    let parentIdx := shr(1, mIdx)
                    mstore(0x20, or(treeAdrs, or(shl(32, add(hh, 1)), parentIdx)))
                    let s := shl(5, and(mIdx, 1))
                    mstore(xor(0x40, s), merkleNode)
                    mstore(xor(0x60, s), sibling)
                    merkleNode := and(keccak256(0x00, 0x80), nMask)
                    mIdx := parentIdx
                }

                currentNode := merkleNode
                sigOff := add(authOff, xmssAuthBytes)
            }

            mstore(0x00, eq(currentNode, root))
            return(0x00, 0x20)
        }
    }

    function _checkCommon(bytes32 pkSeed, bytes32 pkRoot, bytes calldata sig, uint256 sigLen) private pure {
        if (sig.length != sigLen) revert("Invalid sig length");
        if (
            uint256(pkSeed) != (uint256(pkSeed) & SPHINCS_TOP_N_MASK)
                || uint256(pkRoot) != (uint256(pkRoot) & SPHINCS_TOP_N_MASK)
        ) {
            revert("Invalid public key");
        }
    }
}

/// @title SphincsFastTradePlusVerifier
/// @notice SPHINCS-/+C verifier for `fast_trade_plus`.
contract SphincsFastTradePlusVerifier is ISphincsVerifier {
    string public constant PARAMETER_SET = "fast_trade_plus";
    uint256 public constant N = SPHINCS_PARAM_N;
    uint256 public constant H = SPHINCS_FAST_TRADE_PLUS_H;
    uint256 public constant D = SPHINCS_FAST_TRADE_PLUS_D;
    uint256 public constant SUBTREE_H = SPHINCS_FAST_TRADE_PLUS_SUBTREE_H;
    uint256 public constant A = SPHINCS_FAST_TRADE_PLUS_A;
    uint256 public constant K = SPHINCS_FAST_TRADE_PLUS_K;
    uint256 public constant W = SPHINCS_FAST_TRADE_PLUS_W;
    uint256 public constant L = SPHINCS_FAST_TRADE_PLUS_L;
    uint256 public constant TARGET_SUM = SPHINCS_FAST_TRADE_PLUS_TARGET_SUM;
    uint256 public constant SIG_LEN = SPHINCS_FAST_TRADE_PLUS_SIG_LEN;

    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external
        pure
        override
        returns (bool valid)
    {
        return
            SphincsVerifierCore.verifyMinus(pkSeed, pkRoot, message, sig, SIG_LEN, H, D, SUBTREE_H, A, K, L, TARGET_SUM);
    }
}

/// @title SphincsDefaultMinusVerifier
/// @notice SPHINCS-/+C verifier for `default_minus`.
contract SphincsDefaultMinusVerifier is ISphincsVerifier {
    string public constant PARAMETER_SET = "default_minus";
    uint256 public constant N = SPHINCS_PARAM_N;
    uint256 public constant H = SPHINCS_DEFAULT_MINUS_H;
    uint256 public constant D = SPHINCS_DEFAULT_MINUS_D;
    uint256 public constant SUBTREE_H = SPHINCS_DEFAULT_MINUS_SUBTREE_H;
    uint256 public constant A = SPHINCS_DEFAULT_MINUS_A;
    uint256 public constant K = SPHINCS_DEFAULT_MINUS_K;
    uint256 public constant W = SPHINCS_DEFAULT_MINUS_W;
    uint256 public constant L = SPHINCS_DEFAULT_MINUS_L;
    uint256 public constant TARGET_SUM = SPHINCS_DEFAULT_MINUS_TARGET_SUM;
    uint256 public constant SIG_LEN = SPHINCS_DEFAULT_MINUS_SIG_LEN;

    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external
        pure
        override
        returns (bool valid)
    {
        return
            SphincsVerifierCore.verifyMinus(pkSeed, pkRoot, message, sig, SIG_LEN, H, D, SUBTREE_H, A, K, L, TARGET_SUM);
    }
}

/// @title SphincsGasSaverMinusQ18AggressiveVerifier
/// @notice SPHINCS-/+C verifier for `gas_saver_minus_q18_aggressive`.
contract SphincsGasSaverMinusQ18AggressiveVerifier is ISphincsVerifier {
    string public constant PARAMETER_SET = "gas_saver_minus_q18_aggressive";
    uint256 public constant N = SPHINCS_PARAM_N;
    uint256 public constant H = SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_H;
    uint256 public constant D = SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_D;
    uint256 public constant SUBTREE_H = SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_SUBTREE_H;
    uint256 public constant A = SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_A;
    uint256 public constant K = SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_K;
    uint256 public constant W = SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_W;
    uint256 public constant L = SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_L;
    uint256 public constant TARGET_SUM = SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_TARGET_SUM;
    uint256 public constant SIG_LEN = SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_SIG_LEN;

    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external
        pure
        override
        returns (bool valid)
    {
        return
            SphincsVerifierCore.verifyMinus(pkSeed, pkRoot, message, sig, SIG_LEN, H, D, SUBTREE_H, A, K, L, TARGET_SUM);
    }
}

/// @title SphincsPlus128sVerifier
/// @notice SPHINCS+ 128s-shaped verifier using this repo's Keccak/FIPS-ADRS hash construction.
contract SphincsPlus128sVerifier is ISphincsVerifier {
    string public constant PARAMETER_SET = "sphincs_plus_128s";
    uint256 public constant N = SPHINCS_PARAM_N;
    uint256 public constant H = SPHINCS_PLUS_128S_H;
    uint256 public constant D = SPHINCS_PLUS_128S_D;
    uint256 public constant SUBTREE_H = SPHINCS_PLUS_128S_SUBTREE_H;
    uint256 public constant A = SPHINCS_PLUS_128S_A;
    uint256 public constant K = SPHINCS_PLUS_128S_K;
    uint256 public constant W = SPHINCS_PLUS_128S_W;
    uint256 public constant L = SPHINCS_PLUS_128S_L;
    uint256 public constant SIG_LEN = SPHINCS_PLUS_128S_SIG_LEN;

    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external
        pure
        override
        returns (bool valid)
    {
        return SphincsVerifierCore.verifyPlus128s(pkSeed, pkRoot, message, sig);
    }
}
