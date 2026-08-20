// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  ISphincsParamVerifier
/// @notice Minimal interface for the shared, stateless, PARAMETRIC SPHINCS- verifier.
/// @dev    The concrete `SphincsParamVerifier` implements `verify` as `pure`; it is declared
///         `view` here so callers can `staticcall` it through this interface. A SPHINCS- public
///         key is the pair (pkSeed, pkRoot), each a 16-byte value left-aligned in a bytes32
///         (low 128 bits zero / N_MASK). The signature blob is `SphincsParamsLib.blobLen(params)`
///         bytes with no prefix; the parameter set travels as a `SphincsParamsLib.pack`ed word.
interface ISphincsParamVerifier {
    /// @param pkSeed       SPHINCS- public seed (top-128-bit-aligned).
    /// @param pkRoot       SPHINCS- public root (top-128-bit-aligned).
    /// @param message      32-byte digest being verified (e.g. the userOpHash).
    /// @param packedParams `SphincsParamsLib.pack(params)` word; reverts if not a valid set.
    /// @param sig          The raw SPHINCS- blob (`blobLen(params)` bytes, no prefix).
    /// @return valid       True iff the signature verifies under (pkSeed, pkRoot, params).
    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, uint256 packedParams, bytes calldata sig)
        external
        view
        returns (bool valid);
}
