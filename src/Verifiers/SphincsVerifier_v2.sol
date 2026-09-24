// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Signature length of the SphincsVerifier_v2 blob (no prefix). MUST equal `SIG_LEN` and the
///      length check in `SphincsVerifier_v2.verify` (6176). Distinct from `SPHINCS_SIG_LEN` (3688),
///      `SPHINCS_STANDARD_SIG_LEN` (8400) and `FORS_SIG_LEN` (2448).
uint256 constant SPHINCS_V2_SIG_LEN = 6176;

/// @title SphincsVerifier_v2 — experimental sphincs-g verifier (compact H_msg revision)
/// @notice n=16 h=20 d=5 h'=4 a=9 k=19 w=16 len=35, 6,176-byte signature, public key =
///         (pkSeed, pkRoot). Standard FORS under standard WOTS+ (no +C grinding on either layer).
///         NOT standardized SLH-DSA.
///
///         Format pinned to Sphincs-G bea9447d45a4ac78bb2d8bc3d3f91a794c773881
///         (ledger_prepared_16_20). Not byte-identical to the historical Sepolia verifier; no
///         hardware slot policy is enforced here. Reference signer: scripts/sphincs_v2_reference.py.
///
///         Closer to FIPS 205 than `SphincsStandardVerifier`:
///           * H_msg input order R ‖ PK.seed ‖ PK.root ‖ M (behind a 0xFF..FF domain word),
///             packed to 112 bytes without padding the 16-byte fields.
///           * FORS signature interleaved per tree: sk ‖ A auth nodes.
///           * WOTS+ signs the 16-byte node directly, digits read MSB-first (base_2b), and the
///             3-nibble checksum likewise MSB-first.
///         Still keccak256 instead of SHAKE, 32-byte-slot tweakable hashes, and FORS indices /
///         hypertree index read LSB-first out of the digest.
///
///         Signature blob layout:
///           R(16) ‖ 19 x [ FORS sk (16) ‖ auth path (9*16) ]
///           ‖ 5 x [ 35 WOTS chains (16 each) ‖ subtree auth path (4*16) ]
///           = 16 + 19*160 + 5*624 = 6176
///
/// @dev    The assembly clobbers scratch/FMP memory and always returns directly to the caller:
///         do not mark it memory-safe or allow fall-through. Uses `mcopy` (requires Cancun).
///         UNAUDITED research prototype.
contract SphincsVerifier_v2 {
    string public constant PARAMETER_SET = "sphincs-g";
    uint256 public constant SIG_LEN = SPHINCS_V2_SIG_LEN;
    uint256 public constant HMSG_INPUT_BYTES = 112;

    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external
        pure
        returns (bool)
    {
        require(sig.length == SPHINCS_V2_SIG_LEN, "Invalid sig length");
        require((uint256(pkSeed) & type(uint128).max) == 0 && (uint256(pkRoot) & type(uint128).max) == 0, "Invalid public key");

        uint256 nMask = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000;
        uint256 dom = type(uint256).max;
        uint256 hMask = (uint256(1) << 20) - 1;
        uint256 aMask = (uint256(1) << 9) - 1;
        uint256 subtreeMask = (uint256(1) << 4) - 1;
        uint256 kA = 19 * 9;
        uint256 forsTreeBytes = (1 + 9) * 16;
        uint256 htStart = 16 + 19 * forsTreeBytes;
        uint256 wotsBytes = 35 * 16;
        uint256 xmssAuthBytes = 4 * 16;

        assembly {
            let seed := pkSeed
            let root := pkRoot
            let sigBase := sig.offset

            mstore(0x00, seed)

            // Compact H_msg: ff32 || R16 || seed16 || root16 || message32.
            // Overlapping stores pack 112 bytes, without padding the 16-byte fields.
            let R := and(calldataload(sigBase), nMask)
            mstore(0x00, dom)
            mstore(0x20, R)
            mstore(0x30, seed)
            mstore(0x40, root)
            mstore(0x50, message)
            let digest := keccak256(0x00, 0x70)
            mstore(0x00, seed)

            let htIdx := and(shr(kA, digest), hMask)
            let dVal := digest

            let idxLeaf0 := and(htIdx, subtreeMask)
            let idxTree0 := shr(4, htIdx)
            let forsBase := or(shl(128, idxTree0), or(shl(96, 3), shl(64, idxLeaf0)))

            // Standard FORS: every tree carries sk || A auth nodes.
            let forsTreePtr := add(sigBase, 16)
            let forsRootPtr := 0x80
            let forsIndices := dVal
            for { let i := 0 } lt(i, 19) { i := add(i, 1) } {
                let treeIdx := and(forsIndices, aMask)
                forsIndices := shr(9, forsIndices)
                let secretVal := and(calldataload(forsTreePtr), nMask)

                mstore(0x20, or(forsBase, or(shl(9, i), treeIdx)))
                mstore(0x40, secretVal)
                let node := and(keccak256(0x00, 0x60), nMask)

                let pathIdx := treeIdx
                let authPtr := add(forsTreePtr, 16)

                for { let hh := 0 } lt(hh, 9) { hh := add(hh, 1) } {
                    let sibling := and(calldataload(authPtr), nMask)
                    authPtr := add(authPtr, 16)
                    let parentIdx := shr(1, pathIdx)
                    mstore(
                        0x20,
                        or(
                            forsBase,
                            or(shl(32, add(hh, 1)), or(shl(sub(sub(9, 1), hh), i), parentIdx))
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
            mcopy(0x40, 0x80, mul(19, 0x20))
            let currentNode := and(keccak256(0x00, 0x2a0), nMask)

            let idxTree := htIdx
            let sigOff := htStart

            for { let layer := 0 } lt(layer, 5) { layer := add(layer, 1) } {
                let idxLeaf := and(idxTree, subtreeMask)
                idxTree := shr(4, idxTree)

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
                mcopy(0x40, 0x80, mul(35, 0x20))
                let wotsPk := and(keccak256(0x00, 0x4a0), nMask)

                let authOff := add(sigOff, wotsBytes)
                let treeAdrs := or(shl(224, layer), or(shl(128, idxTree), shl(96, 2)))
                let merkleNode := wotsPk
                let mIdx := idxLeaf
                let merklePtr := wotsPtr

                for { let hh := 0 } lt(hh, 4) { hh := add(hh, 1) } {
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
}
