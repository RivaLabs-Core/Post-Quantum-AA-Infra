# SPHINCS- indexed variant — signing spec

Signer-side spec for `src/Verifiers/SphincsIndexedVerifier.sol`. This is a **stateful** variant
of the stateless SPHINCS- backup: the hypertree leaf index `htIdx` (which FORS keypair the signer
used) is **passed explicitly in the signature and bound into H_msg**, instead of being derived
pseudo-randomly from the message digest.

> UNAUDITED research prototype. The verifier is delivered without a matching signer or reference
> vector — its happy path is currently untested. This doc is the exact contract the signer must
> honor. Gate any real-funds use on an audit + committed test vector.

## What changed vs the stateless signer (`scripts/sphincs_reference.py`)

Everything is identical to the stateless SPHINCS- signer **except** the four points below. The
FORS+C forced-zero trick, WOTS+C grinding, ADRS layout, tweakable hash, and all params
(n=16, h=22, d=2, a=19, k=7, w=8, l=43, target_sum=208) are unchanged.

1. **The signer chooses `htIdx`** (a monotonic counter / index into the 2²² FORS keypairs) —
   it is NOT taken from `digest >> 133`. It is stateful: **never reuse an index** for two
   different messages (reuse = few-time degradation of that FORS keypair, q=2 ≈ 104-bit, …).
2. **H_msg binds `htIdx`** and uses a distinct domain separator:
   ```
   digest = keccak256( pkSeed(32) ‖ pkRoot(32) ‖ R(32) ‖ htIdx(32) ‖ message(32) ‖ PAD(32) )   // 192 bytes
   ```
   - `R(32)` = the 16-byte randomizer top-aligned in a 32-byte word (low 16 bytes zero), same
     representation the stateless signer uses.
   - `htIdx(32)` = the chosen index as a plain big-endian `uint256`, canonical (value < 2²²).
   - `PAD` = `0xFF…FE` (**distinct** from stateless SPHINCS- `0xFF…FF` and FORS+C `0xFF…FD`,
     so the three schemes never collide on a digest even under a shared public key).
3. **The FORS leaf indices still come from the message digest:** `md[i] = (digest >> i·19) & (2¹⁹−1)`
   for `i ∈ [0,7)`. The forced-zero constraint is unchanged: the signer still grinds `R` until
   `md[6] == 0` (bits [114,133) of `digest`). Because `htIdx` is now bound into H_msg, grind `R`
   **after** choosing `htIdx` (the digest — and thus `md`— depends on `htIdx`).
4. **Append the index:** the signature is the stateless 3688-byte blob followed by a **32-byte
   big-endian `htIdx` word**, total **3720 bytes** (`SPHINCS_INDEXED_SIG_LEN`). `htIdx` must be
   canonical (`< 2²²`) or the verifier returns `false`.

## Signature byte layout (3720 bytes)

All elements are 16-byte (n=16) values, each stored top-aligned in the top half of a 32-byte
calldata word (the verifier masks with `N_MASK`), except `count` (uint32) and the trailing index.

| Offset | Len | Field |
| ---: | ---: | --- |
| 0 | 16 | `R` (randomizer / +C grind counter) |
| 16 | 112 | FORS: 7 revealed secrets (16 B each; secret[6] is the forced-zero tree's root) |
| 128 | 1824 | FORS: 6 auth paths × 19 nodes × 16 B |
| 1952 | 1736 | Hypertree: 2 layers × (43·16 WOTS ‖ 4-byte `count` ‖ 11·16 tree-auth) = 2×868 |
| 3688 | 32 | **`htIdx`** — explicit hypertree leaf index, big-endian `uint256`, `< 2²²` |

`htIdx` splits as the verifier does: `idxLeaf0 = htIdx & 0x7FF`, `idxTree0 = htIdx >> 11`
(SUBTREE_H = 11), and drives every FORS/hypertree ADRS position (identical to the stateless
verifier, only the *source* of `htIdx` differs).

## Signing procedure (delta)

1. Pick `htIdx` = next unused index (stateful counter). Enforce no reuse.
2. Grind `R` until `md[6] == 0`, where `digest = keccak256(pkSeed ‖ pkRoot ‖ R ‖ htIdx ‖ message ‖ 0xFF…FE)`
   and `md[i] = (digest >> i·19) & (2¹⁹−1)`.
3. Produce the FORS+C signature over `md[0..6]` at hypertree leaf `htIdx`, then the d=2 WOTS+C /
   XMSS hypertree authentication path for leaf `htIdx` — exactly as the stateless signer, using
   `htIdx` for the ADRS `tree`/`key_pair`/`tree_index` fields.
4. Concatenate `R ‖ FORS ‖ hypertree ‖ htIdx(32 B)` → 3720-byte signature.

## Security notes

- **EUF-CMA secure** with an honest, non-reusing signer: an attacker holds no FORS secret, and the
  explicit index cannot be swapped on a valid signature (bound both into H_msg *and* by the
  hypertree auth path). Passing the index does not weaken forgery resistance.
- **Statefulness is the whole tradeoff.** The stateless SphincsVerifier remains available as the
  robust, no-state recovery key; use this variant only where the signer can guarantee index
  uniqueness (the ephemeral-keys model). A state rollback / backup restore that reuses an index is
  the one real footgun.
- **Testing:** once the signer emits this format, produce a `(pkSeed, pkRoot, message, htIdx, sig)`
  vector and add positive/tamper/wrong-message tests to `test/SphincsIndexedVerifier.t.sol`
  (the current suite covers only structural guards).
