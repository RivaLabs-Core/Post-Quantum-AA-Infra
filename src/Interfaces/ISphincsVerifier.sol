// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  ISphincsVerifier
/// @notice Minimal interface for a shared, stateless SPHINCS verifier.
/// @dev    Concrete verifiers implement `verify` as `pure`; it is declared `view` here so callers
///         can `staticcall` through this interface. A SPHINCS
///         public key is the pair (pkSeed, pkRoot), each a 16-byte value left-aligned in a
///         bytes32 (low 128 bits zero / N_MASK). Signature length is profile-specific.
interface ISphincsVerifier {
    /// @param pkSeed  SPHINCS- public seed (top-128-bit-aligned).
    /// @param pkRoot  SPHINCS- public root (top-128-bit-aligned).
    /// @param message 32-byte digest being verified (e.g. the userOpHash).
    /// @param sig     The profile-specific SPHINCS signature blob, with no prefix.
    /// @return valid  True iff the signature verifies under (pkSeed, pkRoot).
    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external
        view
        returns (bool valid);
}
