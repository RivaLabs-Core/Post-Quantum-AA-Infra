# NiceTry

Reference Solidity implementation of the NiceTry ephemeral-key smart wallet design.

> [!NOTE]
> This repo contains contracts only. For the protocol specification see [Ephemeral-Keys-Protocol](https://github.com/RivaLabs-Core/ephemeral-keys).

## What This Repo Contains

An ERC-4337 smart account with two hash-based, post-quantum signers:

| Role | Scheme | Signature | Verify gas |
| --- | --- | ---: | ---: |
| Primary (every UserOp) | FORS+C | 2,448 B | ~35k |
| Backup / recovery / bootstrap | SPHINCS- | 3,688 B | ~105k |

- **FORS+C** is a Forest of Random Subsets few-time signature using the
  SPHINCS+ FIPS 205 ADRS layout and a grinding optimization. The account
  rotates the authorizing FORS key on every UserOp, so a key is never reused.
  Accidental reuse degrades gracefully instead of breaking outright.
- **SPHINCS-** is a stateless, many-time SPHINCS+/SLH-DSA variant (keccak256,
  128-bit). It is a durable cold key committed into the account address. It can
  sign any op, recover an account whose rotation chain broke, and bootstrap the
  account on a chain that was not in the activation Merkle tree.

`SimpleAccountFactory` deploys `SimpleAccount` clones (EIP-1167) at CREATE2
addresses that commit to both the per-chain initial-signer Merkle root and the
SPHINCS- backup key, so the same address is reachable on every chain.

## Contract Layout

```text
src/
+-- SimpleAccount.sol                    ERC-4337 account: FORS+C primary, SPHINCS- backup
+-- SimpleAccountFactory.sol             CREATE2 clone factory
+-- InitialSignerCommitment.sol          Salt / activation-leaf / backup-leaf domains
+-- Verifiers/
|   +-- ForsVerifier.sol                 FORS+C verifier (recover -> owner address)
|   +-- SphincsVerifier.sol              SPHINCS- verifier (verify -> bool)
+-- Interfaces/
    +-- ISignatureVerifier.sol
    +-- ISphincsVerifier.sol

script/Deploy.s.sol                      Deterministic CREATE2 deploy (Foundry)
deploy-4337/                             Same deploy, gas-sponsored through ERC-4337 + Pimlico
scripts/signing_reference.py             Dependency-free FORS+C reference signer / vector generator
scripts/sphincs_reference.py             Drives the upstream SPHINCS- signer to mint a test vector
test/vectors/fors-reference-0.json       FORS+C reference vector checked by ForsReferenceVector.t.sol

docs/
+-- signing-spec.md                      Byte-level signing spec (FORS+C, account envelope)
+-- fors-parameters.md                   FORS+C parameter choice and security analysis
+-- fors-two-forest-cache.md             Signer-side tree cache / reuse notes
+-- sphincs-backup-recovery.md           SPHINCS- backup signer: dispatch, binding, recovery
+-- multichain-consistent-addresses.md   Root-based first activation across chains
```

`lib/kernel` is kept as a submodule only because it vendors `solady`, which the
account uses for Merkle proofs and clone deployment.

## Signature Dispatch

`SimpleAccount` routes a UserOp signature purely by its length:

| Length | Account state | Path |
| --- | --- | --- |
| 2,448 | activated | FORS+C: `recover()` must return an `AUTH_ACTIVE` key; that key is burned and `nextOwner` activated |
| 2,451 + 32·proofLen | not activated | Activation envelope: FORS+C signature plus Merkle proof against `initialSignerRoot` |
| 3,688 | either | SPHINCS-: verified against the committed backup key; re-seeds the FORS chain |

The three length classes are disjoint. A constructor guard and a test enforce
that they stay so. `userOp.callData` ends with the 20-byte `nextOwner`
(FORS / activation) or with `currentKey || nextOwner` (SPHINCS-). Multiple
devices are supported through per-key `authState` and `addSigner()`.

## Parameters

Parameters are still in a tuning phase and may change.

**FORS+C** (`src/Verifiers/ForsVerifier.sol`): K=26 trees, A=5 (32 leaves
each), N=16. Signature 2,448 bytes. q-degradation: q=1 = 128 bits (NIST
Level 1), q=2 = 104, q=5 = 70. Signer hashes per signature: ~2.4k. Tree cache
per keypair: ~25 KB. To retune, edit the primary parameters at the top of the
verifier; all derived constants recompute automatically.

**SPHINCS-** (`src/Verifiers/SphincsVerifier.sol`): n=16, h=22, d=2, a=19, k=7,
w=8, l=43. Signature 3,688 bytes, budget 2^22 signatures per key. The verifier
is vendored verbatim from the [SPHINCS-](https://github.com/nconsigny/SPHINCS-)
reference implementation and is unaudited research code.

## Build And Test

```bash
forge install
forge build
forge test
```

63 tests across 5 suites. Coverage includes:

- Round-trip cryptographic tests for the FORS+C verifier, including a committed
  reference vector produced by `scripts/signing_reference.py`.
- Account tests: factory address binding, activation, rotation, multi-device
  enrollment, SPHINCS- dispatch and recovery (with mock verifiers).
- SPHINCS- verifier guard tests. The vector-backed happy-path tests activate
  once `test/vectors/sphincs-reference-0.json` is generated with
  `scripts/sphincs_reference.py` (needs the external SPHINCS- signer).

## Deploy

`script/Deploy.s.sol` deploys `ForsVerifier`, `SphincsVerifier` and
`SimpleAccountFactory` (which deploys the single `SimpleAccount`
implementation in its constructor) through the standard CREATE2 deployer at
`0x4e59b44847b379578588920cA78FbF26c0B4956C`. With the same salts, bytecode and
constructor arguments the addresses are identical on every chain. The script
targets ERC-4337 EntryPoint v0.7 by default.

`deploy-4337/` performs the same deployment from a Pimlico-sponsored UserOp so
no native gas is needed. See its README.

## Legacy Code

Earlier WOTS+C and ECDSA accounts, the ZeroDev Kernel / Nexus ERC-7579 modules,
the EIP-8141 `FrameAccount` draft and the stateful `SphincsIndexedVerifier`
were removed from the main line. They are preserved in git history on the
`archive/dev-pre-cleanup` branch. The runtime-parameterised
`SphincsParamVerifier` and the multi-backup-signer account are in progress on
`multiSphincs_account`.

## Related Repos

- [NiceTry-Spec](https://github.com/RivaLabs-Core/ephemeral-keys): protocol specification and design rationale
- [NiceTry-Wallet](https://github.com/RivaLabs-Core/NiceTry-Wallet): standalone wallet demo with local key management
- [NiceTry-Metamask](https://github.com/RivaLabs-Core/NiceTry-Metamask): MetaMask integration demo
