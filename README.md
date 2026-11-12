# NiceTry

Reference Solidity implementation of the NiceTry ephemeral-key smart wallet design.

> [!NOTE]
> This repo contains contracts only. For the protocol specification see [Ephemeral-Keys-Protocol](https://github.com/RivaLabs-Core/ephemeral-keys).

## What This Repo Contains

ERC-4337 smart account families built on hash-based, post-quantum signatures:

| Account | Signer | Scheme | Signature | Verify gas |
| --- | --- | --- | ---: | ---: |
| `SimpleAccount` | Primary (every UserOp) | FORS+C | 2,448 B | ~35k |
| `SimpleAccount` | Backup / recovery / bootstrap | SPHINCS- | 3,688 B | ~105k |
| `SphincsAccount` | Only signer | SPHINCS- (standard FORS + WOTS+) | 8,400 B | ~268k |
| `SphincsAccount_v5` | Only signer | SPHINCS- (standard FORS + WOTS+C), h=26 | 7,740 B | ~81k |
| `SphincsAccount_v6` | Only signer | SPHINCS- (standard FORS + WOTS+C), h=24 | 6,524 B | ~70k |

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

`SphincsAccount` is the stateless alternative: a single SPHINCS- key signs every
UserOp, with no rotation, no activation step and no recovery path. Its factory
binds the key into the CREATE2 salt in the same way. See
[docs/sphincs-account.md](docs/sphincs-account.md).

`SphincsAccount_v5` and `SphincsAccount_v6` are the same stateless model on
the WOTS+C verifiers `SphincsVerifier_v5` / `SphincsVerifier_v6`. They share
`SphincsWotscAccount` / `SphincsWotscAccountFactory`; each version pins its
verifier's signature length and has its own factory, implementation and
address family. The standard `SphincsAccount` family is untouched.

## Contract Layout

```text
src/
+-- SimpleAccount.sol                    ERC-4337 account: FORS+C primary, SPHINCS- backup
+-- SimpleAccountFactory.sol             CREATE2 clone factory
+-- InitialSignerCommitment.sol          Salt / activation-leaf / backup-leaf domains
+-- SphincsAccount.sol                   ERC-4337 account: SPHINCS- only signer
+-- SphincsAccountFactory.sol            CREATE2 clone factory for SphincsAccount
+-- SphincsWotscAccount.sol              Shared account logic for the WOTS+C SPHINCS- accounts
+-- SphincsWotscAccountFactory.sol       Shared CREATE2 clone factory logic for them
+-- SphincsAccount_v5.sol                Account for SphincsVerifier_v5 (7,740-byte signature)
+-- SphincsAccountFactory_v5.sol         Factory for SphincsAccount_v5
+-- SphincsAccount_v6.sol                Account for SphincsVerifier_v6 (6,524-byte signature)
+-- SphincsAccountFactory_v6.sol         Factory for SphincsAccount_v6
+-- Verifiers/
|   +-- ForsVerifier.sol                 FORS+C verifier (recover -> owner address)
|   +-- SphincsVerifier.sol              SPHINCS- backup verifier (verify -> bool)
|   +-- SphincsStandardVerifier.sol      Standard SPHINCS- verifier for SphincsAccount
|   +-- SphincsVerifier_v5.sol           WOTS+C SPHINCS- verifier, h=26 (10-8-8), k=24 a=10
|   +-- SphincsVerifier_v6.sol           WOTS+C SPHINCS- verifier, h=24 (10-7-7), k=19 a=9
+-- Interfaces/
    +-- ISignatureVerifier.sol
    +-- ISphincsVerifier.sol

script/Deploy.s.sol                      Deterministic CREATE2 deploy of the SimpleAccount family
script/DeploySphincsAccount.s.sol        Deterministic CREATE2 deploy of the SphincsAccount family
script/DeploySphincsWotscAccounts.s.sol  Deterministic CREATE2 deploy of the v5 and v6 families
deploy-4337/                             Same deploy, gas-sponsored through ERC-4337 + Pimlico
scripts/signing_reference.py             Dependency-free FORS+C reference signer / vector generator
scripts/sphincs_reference.py             Drives the upstream SPHINCS- signer to mint a test vector
scripts/sphincs_wotsc_reference.py       Reference signer / vector generator for SphincsVerifier_v5 / v6
scripts/daisugi_frame_tx.py              EIP-8141 frame-transaction sender for the Daisugi testnet
deployments/daisugi.json                 Daisugi addresses of the v5 / v6 families
test/vectors/fors-reference-0.json       FORS+C reference vector checked by ForsReferenceVector.t.sol

docs/
+-- signing-spec.md                      Byte-level signing spec (FORS+C, account envelope)
+-- fors-parameters.md                   FORS+C parameter choice and security analysis
+-- fors-two-forest-cache.md             Signer-side tree cache / reuse notes
+-- sphincs-backup-recovery.md           SPHINCS- backup signer: dispatch, binding, recovery
+-- sphincs-account.md                   SPHINCS- only account: signature, binding, budget
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

`SphincsAccount` has one signer type and no dispatch: `userOp.signature` is the
raw 8,400-byte blob and `userOp.callData` is a plain call. Replay protection is
the EntryPoint nonce. `SphincsAccount_v5` and `SphincsAccount_v6` work the same
way with 7,740- and 6,524-byte blobs; any other length fails validation without
reverting.

## Parameters

Parameters are still in a tuning phase and may change.

**FORS+C** (`src/Verifiers/ForsVerifier.sol`): K=26 trees, A=5 (32 leaves
each), N=16. Signature 2,448 bytes. q-degradation: q=1 = 128 bits (NIST
Level 1), q=2 = 104, q=5 = 70. Signer hashes per signature: ~2.4k. Tree cache
per keypair: ~25 KB. To retune, edit the primary parameters at the top of the
verifier; all derived constants recompute automatically.

**SPHINCS- backup** (`src/Verifiers/SphincsVerifier.sol`): n=16, h=22, d=2,
a=19, k=7, w=8, l=43. Signature 3,688 bytes, budget 2^22 signatures per key. The
verifier is vendored verbatim from the
[SPHINCS-](https://github.com/nconsigny/SPHINCS-) reference implementation and
is unaudited research code.

**SPHINCS- standard** (`src/Verifiers/SphincsStandardVerifier.sol`, used by
`SphincsAccount`): n=16, h=20, d=4, a=7, k=29, w=4, l=68. Standard FORS and
standard WOTS+ with checksum, no grinding. Signature 8,400 bytes, budget about
10^6 signatures per key. Derived from the same reference code, unaudited, and
without a committed reference vector yet.

**SPHINCS- WOTS+C** (`src/Verifiers/SphincsVerifier_v5.sol` and
`SphincsVerifier_v6.sol`, used by `SphincsAccount_v5` / `_v6`): n=16, d=3,
w=4, standard FORS under WOTS+C (no checksum chains, digit sum fixed at 120 by
a grinding counter), compact keccak256 tweakable hash. v5: h=26 with subtrees
10-8-8 from the top, k=24 a=10, 7,740 bytes, budget about 2^30 signatures per
key. v6: h=24 with subtrees 10-7-7 from the top, k=19 a=9, 6,524 bytes, budget
about 2^24 signatures per key. The top subtree is fixed per key, so a signer can
cache it. Unaudited; checked against vectors from an off-repo signer.

## Build And Test

```bash
forge install
forge build
forge test
```

185 tests across 14 suites. Coverage includes:

- Round-trip cryptographic tests for the FORS+C verifier, including a committed
  reference vector produced by `scripts/signing_reference.py`.
- Account tests: factory address binding, activation, rotation, multi-device
  enrollment, SPHINCS- dispatch and recovery (with mock verifiers).
- SPHINCS- verifier guard tests. The vector-backed happy-path tests activate
  once `test/vectors/sphincs-reference-0.json` is generated with
  `scripts/sphincs_reference.py` (needs the external SPHINCS- signer).
- `SphincsAccount` tests: factory key binding, initialization lock, validation
  with a mock verifier, garbage rejection on the real verifier, execution.
- Standard SPHINCS- verifier layout, length-disjointness and guard tests. No
  positive verification is asserted until a reference vector exists.
- `SphincsVerifier_v5` / `_v6`: layout and guard tests, plus bench suites that
  verify two signer vectors each, reject tampering and report gas.
- `SphincsAccount_v5` / `_v6` tests: the same account checks as
  `SphincsAccount`, plus a real-vector UserOp validating end to end and every
  other family's length failing cleanly.

## Deploy

`script/Deploy.s.sol` deploys `ForsVerifier`, `SphincsVerifier` and
`SimpleAccountFactory` (which deploys the single `SimpleAccount`
implementation in its constructor) through the standard CREATE2 deployer at
`0x4e59b44847b379578588920cA78FbF26c0B4956C`. With the same salts, bytecode and
constructor arguments the addresses are identical on every chain. The script
targets ERC-4337 EntryPoint v0.7 by default.

`deploy-4337/` performs the same deployment from a Pimlico-sponsored UserOp so
no native gas is needed. See its README.

`script/DeploySphincsAccount.s.sol` deploys `SphincsStandardVerifier` and
`SphincsAccountFactory` the same way, without touching the `SimpleAccount`
family.

`script/DeploySphincsWotscAccounts.s.sol` deploys `SphincsVerifier_v5` +
`SphincsAccountFactory_v5` and `SphincsVerifier_v6` + `SphincsAccountFactory_v6`
the same way, and checks that each verifier, factory and implementation agree on
the signature length.

On the Daisugi testnet (chain 1337), whose RPC accepts only EIP-8141 frame
transactions (type 0x06), the v5 and v6 families are deployed at the same
CREATE2 salts with `scripts/daisugi_frame_tx.py deploy`, which sends one frame
transaction per contract from a plain ECDSA EOA. Addresses, transactions and
build settings are in `deployments/daisugi.json`. Daisugi's bundler rejects a
UserOp whose validation pays the prefund with a value transfer, so give an
account an EntryPoint deposit (`daisugi_frame_tx.py call` to `depositTo`) before
sending UserOps from it.

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
