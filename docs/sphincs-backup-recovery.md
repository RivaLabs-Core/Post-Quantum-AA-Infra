# SPHINCS- backup / recovery signer

NiceTry's primary signer is **FORS+C**, a *few-time* hash-based signature operated under the
Ephemeral-Keys model: the `owner` is rotated to a fresh key on every UserOp, so the q=1 FORS key is
never reused. The failure mode of that model is **bricking** — if the rotation chain breaks (a lost
ephemeral key, a UserOp that never lands and desyncs local state), only the current rotating `owner`
can sign and the account is unrecoverable.

The **SPHINCS- backup** is a durable, cold, *many-time* hash-based key — an EVM-optimized
[SPHINCS-](https://github.com/nconsigny/SPHINCS-) variant of the SPHINCS+/SLH-DSA family (see also the
[ethresear.ch writeup](https://ethresear.ch/t/sphincs-minus-efficient-stateless-post-quantum-signature-verification-on-the-evm/25165)).
It fixes this: it is a co-equal signer that can sign any op, recover a stuck account, or bootstrap the
account on a new chain — without the q=1 fragility of FORS+C, because SPHINCS- is stateless and
many-time (2²² budget).

> The verifier is **UNAUDITED research code**, derived from the reference impl with the parameter set
> retargeted (see the note in `SphincsVerifier.sol`). Gate any real-funds deployment on an
> audit of `src/Verifiers/SphincsVerifier.sol`.

## The SPHINCS- variant (keccak)

- 128-bit (n=16), keccak256 (native EVM, no precompile), FIPS 205 §11.2.2 uncompressed 32-byte ADRS.
- Parameters: `h=20 d=4 a=7 k=29 w=4 l=64 target_sum=96`. WOTS+C has NO checksum chains: all 64
  chains carry message digits (64 x logW=2 = the full 8n=128-bit digest) and `target_sum` (the mean,
  l*(w-1)/2) replaces the checksum.
- Signature: **8,048 bytes** (no prefix). Public key: `(pkSeed, pkRoot)`, two 16-byte values
  left-aligned in `bytes32` (low 128 bits zero / `N_MASK`-canonical).
- On-chain verify: **not re-measured** for this parameter set — expect roughly 2x the canonical set’s
  ≈105K (639 vs 335 keccak invocations, and larger FORS-roots / WOTS-pk compression windows).
  Signature budget 2²⁰ (≈1.05M) — sign rarely; track the count offchain.
- `H_msg` domain pad is `0xFF…FF`, **distinct** from NiceTry FORS+C's `0xFF…FD` (`ForsVerifier.sol`),
  so a FORS and a SPHINCS- signature can never collide on the same digest.

Verifier ABI (`src/Verifiers/SphincsVerifier.sol`, via `src/Interfaces/ISphincsVerifier.sol`):

```solidity
function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig) external pure returns (bool);
```

It is a shared, stateless contract deployed once and called by every account via `staticcall`.

## Dispatch: by length, no type tag

`SimpleAccount._validateSignature` routes on `userOp.signature.length`:

| Length | State | Path |
|---|---|---|
| `SPHINCS_SIG_LEN` (3,688) | either | **SPHINCS-** → `verify(backupPkSeed, backupPkRoot, userOpHash, sig)` |
| `FORS_SIG_LEN` (2,448) | `owner != 0` | primary FORS → `VERIFIER.recover == owner` |
| `2,451 + 32·proofLen` | `owner == 0` | FORS+Merkle activation envelope |

**Disjointness invariant (enforced):** the three length classes never collide —
`SPHINCS_SIG_LEN ∉ {FORS_SIG_LEN} ∪ {2,451 + 32·k : 0 ≤ k ≤ MAX_ACTIVATION_PROOF_LENGTH}`. A constructor
`require` in `SimpleAccount` asserts this once at implementation-deploy time, and a Foundry test
re-checks it, so a future change to any of the three sizes can't silently mis-route a signature.

## Semantics

A SPHINCS- signature is **fully capable (co-equal)** — it authorizes any `callData`, exactly like a
FORS op, and ends by rotating the FORS `owner` to `nextOwner` (= `callData[-20:]`). The **backup key
itself is never rotated** — it is the intentionally static parallel authority. The same path serves:

- **owner == 0 (inactive)** → *bootstrap*: set the first FORS owner. Works on a chain that is **not** in
  the activation Merkle tree (the cross-chain feature below).
- **owner != 0 (active)** → normal co-equal use, including *recovery* (re-seed a stuck account).

Replay is bound by ERC-4337: `userOpHash` commits to `sender`, `nonce`, `chainid`, and `callData`, so a
signature is valid for exactly one account / nonce / chain / action.

## Key binding (front-run safety)

The backup key is passed explicitly to `initialize(initialSignerRoot, backupPkSeed, backupPkRoot)` and
its commitment is folded into the CREATE2 salt:

```
backupSignerLeaf = keccak256(BACKUP_SIGNER_LEAF_TYPEHASH, pkSeed, pkRoot)
accountSalt      = keccak256(ACCOUNT_SALT_TYPEHASH:v2, initialSignerRoot, backupSignerLeaf, userSalt)
```

So the deterministic account address commits to the backup key. A deploy-race front-runner who supplies
a different backup key derives a *different* address — they cannot install their own recovery key at the
user's address. `initialize` also rejects zero or non-canonical (`& N_MASK != self`) keys so the
verifier can never revert on a bad stored key.

## Cross-chain activation (uncommitted chains)

The activation Merkle tree must enumerate every chain upfront; adding a chain later would change the
root and the address. The SPHINCS- key is chain-independent and already bound into the address, so it
can **activate the account on any chain**, including ones absent from the tree. Committed chains use the
cheap FORS+Merkle path; uncommitted chains use the SPHINCS- path (no Merkle proof). The tree becomes an
*optimization* for known chains, and the SPHINCS- key is the universal fallback. Per-chain replay is
prevented because `userOpHash` includes `chainid` — sign once per chain.

To onboard a new chain: deploy the factory + impl + `SphincsVerifier` there deterministically
(`script/Deploy.s.sol` / `deploy-4337/deployInfra.ts`), `createAccount(...)` the counterfactual, then
send a SPHINCS- bootstrap UserOp.

## Security notes

- 128-bit preimage security (n=16), NIST Level 1; sound for a durable backup since security reduces to
  keccak preimage resistance and does not erode with public-key exposure.
- **Blast radius:** the backup is co-equal, so a compromised standing key can drain directly and
  repeatedly. It is the user's cold key — keep it offline; consider wallet monitoring/alerts on SPHINCS-
  ops. Optional future hardening: a backup-authorized `rotateBackupKey` for post-compromise hygiene.
- Stay well below the 2²² signature budget (a handful of uses in a lifetime trivially satisfies it).

## Test vector

`scripts/sphincs_reference.py` drives the upstream [SPHINCS-](https://github.com/nconsigny/SPHINCS-)
signer to produce a real `(pkSeed, pkRoot, message, sig)` tuple and writes
`test/vectors/sphincs-reference-0.json`. `test/SphincsVerifier.t.sol` asserts `verify(...) == true` on
it (plus tamper / wrong-message negatives), alongside always-on revert-guard tests that need no vector.
Generating the vector requires running the external signer once (slow in pure Python; fast via the
repo's Rust signer binary).
