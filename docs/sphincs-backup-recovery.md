# SPHINCS- backup / recovery signers

NiceTry's primary signer is **FORS+C**, a *few-time* hash-based signature operated under the
Ephemeral-Keys model: the `owner` is rotated to a fresh key on every UserOp, so the q=1 FORS key is
never reused. The failure mode of that model is **bricking** — if the rotation chain breaks (a lost
ephemeral key, a UserOp that never lands and desyncs local state), only the current rotating `owner`
can sign and the account is unrecoverable.

A **SPHINCS- backup** is a durable, cold, *many-time* hash-based key — an EVM-optimized
[SPHINCS-](https://github.com/nconsigny/SPHINCS-) variant of the SPHINCS+/SLH-DSA family (see also the
[ethresear.ch writeup](https://ethresear.ch/t/sphincs-minus-efficient-stateless-post-quantum-signature-verification-on-the-evm/25165)).
It fixes this: it is a co-equal signer that can sign any op, recover a stuck account, or bootstrap the
account on a new chain — without the q=1 fragility of FORS+C, because SPHINCS- is stateless and
many-time.

An account can register **any number of SPHINCS- backup signers, each with its own parameter set**:
e.g. a "lightweight" key (small hypertree, cheap/short signatures, low reuse budget) next to a
"heavy" long-lived one. Verification runs through a single shared **flexible verifier**
(`src/Verifiers/SphincsParamVerifier.sol`) that takes the parameter set as a runtime input.

> The verifier logic is **vendored, UNAUDITED research code**. Gate any real-funds deployment on an
> audit of `src/Verifiers/SphincsParamVerifier.sol` (and its fixed-parameter template
> `SphincsVerifier.sol`, which is retained repo-side as the differential-test oracle and is no
> longer deployed or wired into accounts).

## The SPHINCS- variant (keccak)

- 128-bit (n=16, FIXED for every parameter set), keccak256 (native EVM, no precompile),
  FIPS 205 §11.2.2 uncompressed 32-byte ADRS.
- Per-signer parameters `(h, d, k, a, logW, l, targetSum)` — see `src/Verifiers/SphincsParamsLib.sol`
  for the struct, the single-slot packing, the validity constraints, and the blob-length formula
  `16·(1 + k + (k−1)·a) + d·(16·l + 4 + 16·h/d)`.
- The **canonical set** `h=22 d=2 a=19 k=7 w=8 l=43 target_sum=208` (3,688-byte blob, ≈105K gas,
  2²² signature budget) is auto-registered for the address-committed key at `initialize()`.
- Public key: `(pkSeed, pkRoot)`, two 16-byte values left-aligned in `bytes32` (low 128 bits zero /
  `N_MASK`-canonical).
- Sign rarely; track each signer's use count offchain against its own budget (~2^h FORS instances).
- `H_msg` domain pad is `0xFF…FF` for every parameter set, **distinct** from NiceTry FORS+C's
  `0xFF…FD` (`ForsVerifier.sol`), so a FORS and a SPHINCS- signature can never collide on the same
  digest. `H_msg` is byte-identical to the old fixed verifier, so existing signer tooling works
  unchanged with canonical params.

Verifier ABI (`src/Verifiers/SphincsParamVerifier.sol`, via `src/Interfaces/ISphincsParamVerifier.sol`):

```solidity
function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, uint256 packedParams, bytes calldata sig)
    external pure returns (bool);
```

It is a shared, stateless contract deployed once and called by every account via `staticcall`.

## Multiple SPHINCS- signers: the registry

`SimpleAccount` stores registered signers as

```solidity
mapping(address => SphincsParamsLib.Params) public sphincsSigners; // one storage slot per signer
```

- **id** = `sphincsSignerId(pkSeed, pkRoot)` = the CREATE2-commitment leaf hash
  (`InitialSignerCommitment.backupSignerLeaf`) truncated to an address.
- **All-zero params slot (`d == 0`) means the key is NOT authorized**; otherwise ops from that key
  are verified by the flexible verifier with exactly the registered parameters.
- `initialize()` registers the address-committed backup key with the canonical set.
- `addSphincsSigner(pkSeed, pkRoot, params)` enrolls further keys (EntryPoint/self-guarded, i.e.
  reachable through any validated UserOp's callData). Registration validates the params
  (`SphincsParamsLib.validate`) and enforces the length-disjointness invariant below. Post-deploy
  signers are intentionally **not** committed into the account address.
- `removeSphincsSigner(id)` zeroes the slot (same guard). Removing the last signer is allowed — the
  rotating FORS chain remains the primary authority. Re-registering later is fine.

## Dispatch: registered key head, then length

`SimpleAccount._validateSignature` routes as follows:

| Signature | State | Path |
|---|---|---|
| `[pkSeed(32)][pkRoot(32)][blob]`, head registered | either | **SPHINCS-** → `verify(pkSeed, pkRoot, userOpHash, pack(params), blob)` |
| `FORS_SIG_LEN` (2,448) | `activated` | primary FORS → `VERIFIER.recover == owner` |
| `2,451 + 32·proofLen` | `!activated` | FORS+Merkle activation envelope |

A signature longer than 64 bytes (and not exactly `FORS_SIG_LEN`) has its first 64 bytes tried as a
SPHINCS- key head. If the derived id is registered, the op is **committed** to the SPHINCS- route:
the blob must then be exactly `blobLen(params)` bytes or the signature fails — it never falls
through to another route. An unregistered head (e.g. an activation envelope's first 64 bytes) misses
the mapping and falls through cleanly.

**Disjointness invariant (enforced at registration):** a registered envelope length
(`64 + blobLen(params)`) must never equal `FORS_SIG_LEN` nor land in the activation class
`{2,451 + 32·p : 0 ≤ p ≤ 64}`. `_registerSphincsSigner` rejects violating parameter sets, so the
FORS and activation routes can never be shadowed. (The activation half is provably unreachable —
envelopes are ≡ 0 mod 4, activation lengths ≡ 3 mod 4 — and is kept belt-and-braces; the FORS half
is real: e.g. `{h=32,d=4,k=7,a=6,w=8,l=18,ts=63}` yields exactly 2,448 and is rejected. Both are
pinned by Foundry tests.) Exact-`FORS_SIG_LEN` signatures skip the registry lookup entirely, so the
FORS hot path pays no overhead.

## Semantics

A SPHINCS- signature (from ANY registered signer) is **fully capable (co-equal)** — it authorizes
any `callData`, exactly like a FORS op, and ends by rotating the FORS `owner` to `nextOwner`
(= `callData[-20:]`). A **backup key is never rotated by use** — it is the intentionally static
parallel authority (registration/removal happen only through the guarded registry calls). The same
path serves:

- **owner == 0 (inactive)** → *bootstrap*: set the first FORS owner. Works on a chain that is **not** in
  the activation Merkle tree (the cross-chain feature below).
- **owner != 0 (active)** → normal co-equal use, including *recovery* (re-seed a stuck account).

Replay is bound by ERC-4337: `userOpHash` commits to `sender`, `nonce`, `chainid`, and `callData`, so a
signature is valid for exactly one account / nonce / chain / action.

## Key binding (front-run safety)

The INITIAL backup key is passed explicitly to `initialize(initialSignerRoot, backupPkSeed,
backupPkRoot)` and its commitment is folded into the CREATE2 salt:

```
backupSignerLeaf = keccak256(BACKUP_SIGNER_LEAF_TYPEHASH, pkSeed, pkRoot)
accountSalt      = keccak256(ACCOUNT_SALT_TYPEHASH:v2, initialSignerRoot, backupSignerLeaf, userSalt)
```

So the deterministic account address commits to the initial backup key (registered with the
canonical parameter set — a racer cannot register it with weaker params either, since `initialize`
always uses `SphincsParamsLib.canonical()`). A deploy-race front-runner who supplies a different
backup key derives a *different* address — they cannot install their own recovery key at the user's
address. Registration also rejects zero or non-canonical (`& N_MASK != self`) keys so the verifier
can never revert on a bad stored key. Additional signers enrolled later via `addSphincsSigner` are
NOT address-committed — they are authorized by the account's own (already-secured) validation
paths, like `addSigner` device enrollment.

## Cross-chain activation (uncommitted chains)

The activation Merkle tree must enumerate every chain upfront; adding a chain later would change the
root and the address. The SPHINCS- key is chain-independent and already bound into the address, so it
can **activate the account on any chain**, including ones absent from the tree. Committed chains use the
cheap FORS+Merkle path; uncommitted chains use the SPHINCS- path (no Merkle proof). The tree becomes an
*optimization* for known chains, and the SPHINCS- key is the universal fallback. Per-chain replay is
prevented because `userOpHash` includes `chainid` — sign once per chain.

To onboard a new chain: deploy the factory + impl + `SphincsParamVerifier` there deterministically
(`script/Deploy.s.sol` / `deploy-4337/deployInfra.ts`), `createAccount(...)` the counterfactual, then
send a SPHINCS- bootstrap UserOp. Note that on a fresh chain only the address-committed initial key
is registered — post-deploy signers must be re-enrolled per chain.

## Security notes

- 128-bit preimage security (n=16), NIST Level 1; sound for a durable backup since security reduces to
  keccak preimage resistance and does not erode with public-key exposure.
- **Blast radius:** every registered backup is co-equal, so ANY compromised standing key can drain
  directly and repeatedly — each additional signer widens the attack surface. Keep backup keys
  offline; consider wallet monitoring/alerts on SPHINCS- ops. A compromised (or deprecated) signer
  can be revoked with `removeSphincsSigner`.
- **Choose parameter sets consciously.** Smaller trees (lower `h`, `k·a`) mean shorter/cheaper
  signatures but a lower safe-reuse budget and thinner security margin. The registry accepts any
  set passing `SphincsParamsLib.validate` — validity means "the verifier can execute it", NOT "it
  is cryptographically strong". Stay well below each signer's ~2^h budget (canonical: 2²²; a
  handful of uses in a lifetime trivially satisfies it) and track counts offchain, per signer.

## Future work

- **On-chain use counter / max-uses budget.** The per-signer params occupy 8 of the 32 slot bytes;
  the spare bytes could hold a counter incremented on every verified op for that signer (+1 warm
  SSTORE) and an optional max-uses cap — enforcing "lightweight, low-reuse" signers on-chain
  instead of by offchain bookkeeping.
- **Predetermined parameter sets.** A production deployment may restrict registration to a small
  menu of vetted sets, each served by a fixed-constant verifier like `SphincsVerifier` (cheaper,
  much smaller audit surface than the runtime-parametric Yul). That would remove the flexible
  verifier and shrink the mapping payload to a set id — the current design is the fully-general
  stepping stone.
- Optional hardening: a backup-authorized rotate flow (`removeSphincsSigner` + `addSphincsSigner`
  in one op already approximates post-compromise hygiene).

## Test vector

`scripts/sphincs_reference.py` drives the upstream [SPHINCS-](https://github.com/nconsigny/SPHINCS-)
signer to produce a real `(pkSeed, pkRoot, message, sig)` tuple and writes
`test/vectors/sphincs-reference-0.json`. `test/SphincsVerifier.t.sol` asserts `verify(...) == true` on
it (plus tamper / wrong-message negatives), alongside always-on revert-guard tests that need no vector.
Generating the vector requires running the external signer once (slow in pure Python; fast via the
repo's Rust signer binary).

`test/SphincsParamVerifier.t.sol` reuses the same vector for the flexible verifier and — vector or
not — runs a **differential suite**: with canonical packed params the flexible verifier must agree
with the fixed `SphincsVerifier` on every input (including an always-on deep-path fuzz built around
a pre-ground randomizer that passes the forced-zero check). Vectors for NON-canonical parameter
sets require an upstream signer variant with matching parameters; until one exists, non-canonical
sets are covered by the length/validation tests and the account-level mock tests only.
