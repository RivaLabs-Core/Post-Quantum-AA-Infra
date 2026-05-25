# NiceTry

Reference Solidity implementation of the NiceTry ephemeral-key smart wallet design.

> [!NOTE]
> This repo contains contracts only. For the protocol specification see [Ephemeral-Keys-Protocol](https://github.com/RivaLabs-Core/ephemeral-keys).

## What This Repo Contains

ERC-4337 smart account that uses FORS+C as the primary signer and rotates the
authorizing key on every UserOp.

| Scheme | Signature | Verify gas |
| --- | ---: | ---: |
| FORS+C | 2,448 B | ~35k |

FORS+C is a Forest of Random Subsets few-time signature using the SPHINCS+ FIPS
205 ADRS layout and a grinding optimization. Compared with WOTS+C, accidental
key reuse degrades more gracefully, which is why it is now the main account
implementation.

`SimpleAccountFactory` deploys FORS-backed `SimpleAccount` clones. The older
ECDSA and WOTS+C account/module work remains under `other-implementations/` for
comparison and regression tests.

Frame transactions related work is split into `FrameAccount` plus an opcode/runtime
adapter task. The account logic is present; the EIP-8141 opcode bridge is still
deliberately abstract.

## Contract Layout

```text
src/
+-- SimpleAccount.sol                    ERC-4337 FORS-backed account
+-- SimpleAccountFactory.sol             FORS-only CREATE2 factory
+-- InitialSignerCommitment.sol          CREATE2 salt and activation leaf domains
+-- FrameAccount.sol                      EIP-8141 frame account logic
+-- frame/
|   +-- FrameTransactionLib.sol           EIP-8141 constants
+-- Verifiers/
|   +-- ForsVerifier.sol                  FORS+C verifier
+-- Interfaces/
|   +-- ISignatureVerifier.sol
+-- Utility/
    +-- token.sol                         TestToken

other-implementations/
+-- LegacySimpleAccountFactory.sol        ECDSA/WOTS comparison factory
+-- ecdsa/
|   +-- SimpleAccount_ECDSA.sol
|   +-- RotatingECDSAValidator.sol
|   +-- KernelRotatingECDSAValidator.sol
+-- wots/
|   +-- SimpleAccount_WOTS.sol
|   +-- WotsCVerifier.sol
|   +-- IWotsCVerifier.sol
|   +-- KernelRotatingWOTSValidator.sol
+-- kernel/
    +-- IERC7579.sol  IKernelValidator.sol
    +-- MockKernelAccount.sol  MockNexusAccount.sol

docs/
+-- fors-parameters.md                  FORS+C parameter notes
+-- fors-two-forest-cache.md            FORS+C cache/reuse notes
+-- frame-rotation-validation.md        Frame rotation validation checks
+-- multichain-consistent-addresses.md  Root-based first activation
+-- signing-spec.md                     Signing payload layout
```

The `docs/` directory contains hand-written design notes for the active FORS
implementation: parameter choices, signer/cache behavior, signing payloads, and
the frame-account rule that ties validation to the next `rotateOwner` frame.
Generated Forge documentation remains ignored.

## Parameters

Parameters for the post-quantum schemes are still in a tuning phase. None of
the current choices are definitive, and we expect to revisit them as the design
and tooling mature.

**FORS+C** (`src/Verifiers/ForsVerifier.sol`): K=26 trees, A=5 (32 leaves
each), N=16. Signature 2,448 bytes. q-degradation: q=1 = 128 bits (NIST
Level 1), q=2 = 104, q=5 = 70. Signer hashes per signature: ~2.4k
(interactive on hardware wallets). Tree cache per keypair: ~25 KB
(K-1 = 25 trees x 63 nodes x 16 B).

To retune FORS+C, edit the primary parameters at the top of
`src/Verifiers/ForsVerifier.sol`. All derived constants (signature layout,
hash inputs, loop bounds, masks) recompute automatically.

## Build And Test

```bash
forge install
forge build
forge test
```

222 tests across 15 suites. Coverage includes:

- Round-trip cryptographic tests for the main FORS verifier.
- Main account and frame-account tests.
- Legacy WOTS/ECDSA account, module, integration, and gas tests under
  `test/other-implementations/`.

## Deploy

A deploy script lives at `script/Deploy.s.sol`. Running it deploys
`ForsVerifier`, the FORS-only `SimpleAccountFactory`, and the single
`SimpleAccount` implementation created by the factory constructor. The script
targets the canonical ERC-4337 EntryPoint v0.7, which lives at the same address
on mainnet, Sepolia, and other rollups.

## Related Repos

- [NiceTry-Spec](https://github.com/RivaLabs-Core/ephemeral-keys): protocol specification and design rationale
- [NiceTry-Wallet](https://github.com/RivaLabs-Core/NiceTry-Wallet): standalone wallet demo with local key management
- [NiceTry-Metamask](https://github.com/RivaLabs-Core/NiceTry-Metamask): MetaMask integration demo
