// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  SphincsParamsLib
/// @notice Parameter-set plumbing for the flexible SPHINCS- verifier (`SphincsParamVerifier`):
///         the per-signer parameter struct, its single-word packing, validity constraints, and
///         signature-length math. Shared by the verifier, `SimpleAccount` registration, and tests.
/// @dev    The hash output size n is FIXED at 16 bytes (top-128-bit-aligned words / N_MASK); it is
///         deliberately NOT a parameter — generalizing n would change every memory/word layout in
///         the verifier. All other SPHINCS- parameters are per-signer:
///           h         total hypertree height (signature budget ~ 2^h FORS instances)
///           d         hypertree layers (subtree height = h/d)
///           k         FORS trees, INCLUDING the forced-zero last tree (FORS+C)
///           a         FORS tree height (2^a leaves per tree)
///           logW      log2 of the Winternitz parameter w
///           l         WOTS+C chains
///           targetSum WOTS+C target digit sum
///         An all-zero struct is the "unregistered" sentinel in `SimpleAccount.sphincsSigners`
///         (`d == 0` suffices: `validate` requires d > 0, so no registered set can have d == 0).
library SphincsParamsLib {
    /// @dev Packs into 8 bytes -> a single storage slot. The remaining 24 bytes of the slot are
    ///      spare; a future upgrade could use them for an on-chain per-signer use counter /
    ///      max-uses budget without changing the storage layout.
    struct Params {
        uint8 h;
        uint8 d;
        uint8 k;
        uint8 a;
        uint8 logW;
        uint8 l;
        uint16 targetSum;
    }

    /// @dev n = 16 bytes (128-bit hashes), fixed for every parameter set.
    uint256 internal constant N = 16;

    /// @dev WOTS+C counter field size in the signature (per hypertree layer), bytes.
    uint256 internal constant COUNTER_LEN = 4;

    /// @notice The canonical parameter set of the fixed `SphincsVerifier`
    ///         (h=22 d=2 k=7 a=19 w=8 l=43 target_sum=208, 3,688-byte blob).
    function canonical() internal pure returns (Params memory) {
        return Params({h: 22, d: 2, k: 7, a: 19, logW: 3, l: 43, targetSum: 208});
    }

    /// @notice Packs a parameter set into one word. Bit layout (little-end fields):
    ///         [0,8)=h [8,16)=d [16,24)=k [24,32)=a [32,40)=logW [40,48)=l [48,64)=targetSum,
    ///         bits [64,256) zero.
    function pack(Params memory p) internal pure returns (uint256) {
        return uint256(p.h) | (uint256(p.d) << 8) | (uint256(p.k) << 16) | (uint256(p.a) << 24)
            | (uint256(p.logW) << 32) | (uint256(p.l) << 40) | (uint256(p.targetSum) << 48);
    }

    /// @notice Inverse of `pack`. Bits [64,256) are ignored here; `SphincsParamVerifier.verify`
    ///         rejects packed words with high bits set before unpacking.
    function unpack(uint256 w) internal pure returns (Params memory p) {
        p.h = uint8(w);
        p.d = uint8(w >> 8);
        p.k = uint8(w >> 16);
        p.a = uint8(w >> 24);
        p.logW = uint8(w >> 32);
        p.l = uint8(w >> 40);
        p.targetSum = uint16(w >> 48);
    }

    /// @notice Reverts unless `p` is a well-formed parameter set the flexible verifier can execute.
    ///         Each constraint mirrors a concrete usage site in `SphincsParamVerifier`'s assembly.
    function validate(Params memory p) internal pure {
        // Degenerate schemes; d > 0 also doubles as the registration sentinel.
        require(p.h > 0 && p.d > 0 && p.k > 0 && p.a > 0 && p.l > 0, "SphincsParams: zero param");
        // WOTS digit mask is (2^logW - 1); w in [2, 256].
        require(p.logW >= 1 && p.logW <= 8, "SphincsParams: logW out of range");
        // subtreeH = h/d must be exact.
        require(p.h % p.d == 0, "SphincsParams: h not multiple of d");
        uint256 subtreeH = uint256(p.h) / p.d;
        // idxLeaf occupies ADRS word1 / merkle tree_index (uint32 fields).
        require(subtreeH <= 32, "SphincsParams: subtree too tall");
        // idxTree occupies the 96-bit ADRS tree-address field.
        require(uint256(p.h) - subtreeH <= 96, "SphincsParams: tree address overflow");
        // htIdx = (digest >> k*a) & (2^h - 1): FORS indices + hypertree index from ONE keccak word.
        require(uint256(p.k) * p.a + p.h <= 256, "SphincsParams: digest bits exceeded");
        // All l WOTS digits (logW bits each) come from ONE keccak word.
        require(uint256(p.l) * p.logW <= 256, "SphincsParams: wots digits exceeded");
        // WOTS+C digit-sum equality must be satisfiable: 0 < targetSum <= l*(w-1).
        require(
            p.targetSum > 0 && uint256(p.targetSum) <= uint256(p.l) * ((uint256(1) << p.logW) - 1),
            "SphincsParams: bad target sum"
        );
        // FORS ADRS word3 = (forsTree << a) | treeIdx, max (k << a) - 1, must fit uint32.
        // (a <= 32 first, so the shift below cannot silently drop bits.)
        require(p.a <= 32, "SphincsParams: fors tree too tall");
        require((uint256(p.k) << p.a) <= (uint256(1) << 32), "SphincsParams: fors adrs overflow");
    }

    /// @notice Raw SPHINCS- signature blob length (no envelope prefix) for this parameter set:
    ///         R(16) | k FORS secrets | (k-1) FORS auth paths (the forced-zero tree has none)
    ///         | per hypertree layer: l WOTS chains + 4-byte counter + subtree auth path.
    ///         Canonical set -> 3,688 (== the fixed verifier's SPHINCS_SIG_LEN).
    function blobLen(Params memory p) internal pure returns (uint256) {
        uint256 subtreeH = uint256(p.h) / p.d;
        return N * (1 + uint256(p.k) + (uint256(p.k) - 1) * p.a)
            + uint256(p.d) * (N * uint256(p.l) + COUNTER_LEN + N * subtreeH);
    }
}
