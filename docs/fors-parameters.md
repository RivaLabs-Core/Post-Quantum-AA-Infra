# FORS as Primary Signer

This document collects everything we've worked out about the FORS-based primary
signer in the NiceTry account abstraction stack: how the scheme works, what
hash operations it performs, what its security looks like, and why we landed
on the parameters we did.

It is intended to be read alongside `src/Verifiers/ForsVerifier.sol` and
`src/SimpleAccount.sol`.

---

## 1. TL;DR

**Scheme:** standalone FORS+C (Forest Of Random Subsets, with the +C grinding
optimization from Hülsing–Kudinov–Ronen–Yogev 2023). Same hash primitive and ADRS layout as our SLH-DSA-Keccak-128-24
SphincsVerifier, but no XMSS hypertree on top.

**Current parameters:** `K = 14`, `A = 10`, `n = 16` (16-byte truncated keccak256).

| Property                | Value                                      |
| ----------------------- | ------------------------------------------ |
| Signature size          | 2,336 bytes                                |
| Public key (on-chain)   | 20 bytes (Ethereum address)                |
| Tree work / signature   | ~41,000 keccak calls                       |
| Python signing time     | ~41 ms (hashlib, 1 core)                   |
| Verification gas        | ~45k                                       |
| q=1 security (classical)| 128 bits (NIST Level 1)                    |
| q=5 security (classical)| 108 bits                                   |

**Account-side convention:** owner is rotated on every signed UserOp. The
"few-time" property of FORS means accidental key reuse degrades security
gracefully rather than breaking it outright (contrast WOTS+C which is OTS).

---

## 2. FORS in plain English

Imagine **K boxes**, each containing **2^A numbered slips**. Each slip carries
a 16-byte secret.

**Signing a message:**
1. Hash the message into K small numbers, one per box.
2. From box `t` pull out the slip whose number matches the hash; that slip's
   secret becomes one component of the signature.
3. Send all K slips.

**Why is this secure?** Each box has 2^A possible slips, and the message
dictates exactly which one you reveal. A forger trying to sign a different
message would need to reveal slips at *different* indices — which they don't
have, since each unrevealed slip is a fresh random secret.

**The Merkle tree part** is just bookkeeping. Publishing all K · 2^A slip
hashes as the public key would be huge (≥1 MB). Instead, each box has a
Merkle tree built on top, and the public key is the (compressed) hash of the
K tree roots. When you reveal a slip, you also reveal the **auth path**
(A sibling hashes) so the verifier can recompute the tree root and check it
matches the public commitment.

### Few-time property

If you sign once, you reveal K out of K · 2^A slips. Sign twice — now you've
revealed up to 2K. With enough reuses, a forger can mix-and-match indices
across signatures and forge a message hashing to all-already-revealed slots.
The exact security degradation as a function of reuse count is in §6 below.

This is called **few-time** because, unlike WOTS+C (one-time, breaks
immediately on reuse), FORS degrades gracefully. We exploit this as defense
in depth: the wallet's intended discipline is "one signature per key," but if
that ever slips, the failure mode is "weakened" rather than "broken."

---

## 3. The +C variant

Plain FORS sends K leaf-secrets plus K auth paths. FORS+C drops the K-th tree
entirely — its auth path, its computation, and its presence in the public-key
compression — and replaces it with a **grinding step**:

1. The signer iterates a 16-byte counter, recomputing the message digest each
   time, until the digest's last A bits are zero. (Equivalently: the K-th
   tree's would-be index is forced to 0 by grinding.)
2. The K-th tree never gets opened, and the signer doesn't need to compute it.
3. The signature carries the counter (16 B) instead of the K-th tree's
   `sk + auth_path` (16 + A·16 B). Net savings:
   `A · 16 = 160 B` for `A = 10`.

**Cost of grinding:** expected `2^A` Hmsg attempts (one keccak each). For
`A = 10`, ~1,024 hashes — small relative to tree work.

**Security:** preserved at q=1 (paper claim, see §13 and §9.2 of the Bitcoin
hash-based signatures paper). The forger now has K-1 random indices to predict
*plus* the grinding cost on the K-th index, and the bookkeeping works out to
match the K-tree FORS bound.

### Note on the "approximately the same" claim

The paper writes that grinding (≈2^A hashes) "offsets" the saved last-tree
generation (≈2^A hashes), keeping signer time roughly unchanged. Under our
careful accounting, where every signature re-derives all leaves from `skSeed`,
one tree costs `3·2^A − 1` hashes (PRF + F + H per leaf, see §5), so dropping
it saves ~3× more than grinding adds. So FORS+C is actually a small **net**
improvement in signer cost (~5%), not a wash. The paper's accounting drops
the PRF count because in many SPHINCS+ implementations leaf-secrets are
cached or amortized — fair enough as an approximation, but doesn't match our
fresh-keypair-per-UserOp setting.

---

## 4. Hash functions in FORS

Five **roles** appear in the algorithm. All five are implemented as truncated
keccak256 in our code; the names distinguish their roles, not different
primitives. Domain separation is provided by the **ADRS** structure (a 32-byte
typed address that is part of every hash input).

| Name      | Role                            | Input shape                                        |
| --------- | ------------------------------- | -------------------------------------------------- |
| **PRF**   | secret expansion                | `skSeed ‖ ADRS`                                    |
| **F**     | leaf hash                       | `pkSeed ‖ ADRS ‖ sk`                               |
| **H**     | internal node                   | `pkSeed ‖ ADRS ‖ left ‖ right`                     |
| **T**    | roots compression               | `pkSeed ‖ ADRS_roots ‖ root_0 ‖ … ‖ root_{K-2}`    |
| **Hmsg**  | message digest (with grinding)  | `pkSeed ‖ R ‖ digest ‖ DOM ‖ counter`              |

### PRF and key derivation

`PRF(skSeed, ADRS) = keccak256(pad32(skSeed) ‖ ADRS)` truncated to 16 bytes.

This is the function that expands the master secret into all the per-leaf
secrets:

```
sk_{t,l} = PRF(skSeed, ADRS_{t,l})
```

A single 16-byte `skSeed` deterministically produces all K · 2^A leaf-secrets
(for K=12, A=10: 12,288 secrets) without the signer ever storing them
explicitly. This is what makes BIP44-style HD derivation work: one HD-derived
seed expands into the entire FORS keypair, and one seed-rotation produces an
entirely fresh keypair.

The cryptographic requirement is that PRF be indistinguishable from a random
function to anyone who doesn't know `skSeed`. Truncated keccak256 satisfies
this under standard assumptions.

### Per-signature randomizer R

`R = PRF(skSeed, digest)` (16 B) is mixed into the message hash to prevent
generic collision attacks across signatures. R is included in the signature
so the verifier can reproduce the digest exactly.

### Domain separator DOM

A 32-byte fixed constant (`0xFF…FD` in our scheme) ending in the type byte
`0xFD`. This keeps our standalone-FORS scheme cryptographically separate from
SPHINCS+ proper (`0xFF…FF`) and from our SLH-DSA-Keccak-128-24 family
(`0xFF…FE`), so a digest from one scheme can't be replayed in another.

---

## 5. Hash-count analysis

### Per FORS tree (2^A leaves)

| Step                     | Calls         |
| ------------------------ | ------------- |
| Leaf secrets (PRF)       | 2^A = 1,024   |
| Leaf hashes (F)          | 2^A = 1,024   |
| Internal nodes (H)       | 2^A − 1 = 1,023 |
| **Per tree**             | **3·2^A − 1 = 3,071** |

### Why every leaf is needed (for one signature)

It's tempting to think you only need to compute the K leaves you're revealing
plus their auth paths. **But the auth path siblings together with the path
itself partition every leaf in the tree.** The auth-path sibling at level `h`
is the root of a subtree containing 2^h leaves; summing across levels:

```
1 (path leaf) + sum_{h=0..A-1} 2^h  =  1 + (2^A − 1)  =  2^A
```

So all 2^A leaves are needed — there's no "lazy" shortcut for a single
signature. The same holds for internal nodes (`2^A − 1` total).

What you *can* save on is **multiple signatures with the same key**: cache
the trees after the first signature, and subsequent signatures cost ~K
hashes for index lookup only. But for our rotation-per-UserOp model
(fresh keypair every signature), every signature pays the full cost.

### Total per signature (K=14, A=10, FORS+C)

| Step                              | Calls         |
| --------------------------------- | ------------- |
| (K−1) trees                       | 13 · 3,071 = 39,923 |
| Hmsg grinding (~2^A attempts)     | ~1,024        |
| K-roots compression (T)           | 1             |
| R derivation (PRF)                | 1             |
| Address derivation                | 1             |
| **Total**                         | **~40,950**   |

The grinding cost is the only non-tree term that's large enough to matter;
the other three are rounding noise.

### Internal node count clarification

For a complete binary tree with 2^A leaves, the number of **internal nodes**
is `2^A − 1`, not `2^(A−1)`. The level-1 count is `2^(A−1)` (parents of the
leaves), but you also need 2^(A−2) at level 2, and so on up to the root:

```
2^(A−1) + 2^(A−2) + … + 2 + 1  =  2^A − 1
```

Sanity check (A=2): 4 leaves → 2 nodes at level 1 → 1 root. Total 3 = 2² − 1. ✓

---

## 6. Security analysis

### q-signature security bound

After q signatures, each tree has up to q revealed leaves out of 2^A.
A forger needs to find a message whose K hash-derived indices all land on
revealed leaves. Per-attempt success probability is `(q/2^A)^K`, so forging
takes roughly `(2^A/q)^K = 2^(K·(A−log₂q))` work.

```
security(q) ≈ min(n,  K · (A − log₂ q))     bits, classical
```

Capped at `n = 128` (the hash output truncation) because beyond that you can
just attack the hash directly.

### Numbers for K=14, A=10

| q   | log₂ q | K·(A − log₂ q)  | security |
| --- | ------ | --------------- | -------- |
| 1   | 0      | 14 · 10 = 140   | **128** (capped) |
| 2   | 1      | 14 · 9 = 126    | **126**  |
| 3   | 1.585  | 14 · 8.42 ≈ 118 | **118**  |
| 4   | 2      | 14 · 8 = 112    | **112**  |
| 5   | 2.322  | 14 · 7.68 ≈ 108 | **108**  |
| 10  | 3.322  | 14 · 6.68 ≈ 94  | **94**   |
| 100 | 6.644  | 14 · 3.36 ≈ 47  | **47**   |

q=1 is **128 bits** — at the NIST Level 1 ceiling, capped by `n = 128`.
The "headroom" `K·A = 140` over the cap is what limits how fast q-reuse
degrades; with 12 bits of headroom, q=2..5 stay above 108 bits.

For comparison, plain ECDSA on secp256k1 is 128-bit classical against
discrete log but **0-bit against a CRQC** running Shor — it's that
post-quantum gap that motivates this whole exercise.

---

## 7. Parameter sweep

All rows assume FORS+C (counter included, last tree dropped). Sig size
formula: `48 + 16·(K−1)·(A+1)` bytes. Tree work: `(K−1)·(3·2^A − 1) + 2^A`
hashes (signer side). Python time: tree work / 1M hash/s.

| K  | A  | K·A | q=1 | q=2 | q=3 | q=4 | q=5 | sig (B) | tree work | python    |
| -- | -- | --- | --- | --- | --- | --- | --- | ------- | --------- | --------- |
| 14 | 13 | 182 | 128 | 128 | 128 | 128 | 128 | 2,960   | 328k      | ~330 ms   |
| 14 | 12 | 168 | 128 | 128 | 128 | 128 | 128 | 2,752   | 164k      | ~165 ms   |
| 12 | 13 | 156 | 128 | 128 | 128 | 128 | 128 | 2,512   | 279k      | ~280 ms   |
| 14 | 11 | 154 | 128 | 128 | 128 | 126 | 122 | 2,544   |  82k      | ~82 ms    |
| 12 | 12 | 144 | 128 | 128 | 125 | 120 | 116 | 2,336   | 139k      | ~140 ms   |
| **14** | **10** | **140** | **128** | **126** | **118** | **112** | **108** | **2,336** | **41k** | **~41 ms** |
| 10 | 13 | 130 | 128 | 120 | 114 | 110 | 107 | 2,064   | 229k      | ~230 ms   |
| 12 | 11 | 132 | 128 | 120 | 113 | 108 | 104 | 2,160   |  70k      | ~70 ms    |
| 10 | 12 | 120 | 120 | 110 | 104 | 100 |  97 | 1,920   | 115k      | ~115 ms   |
| 12 | 10 | 120 | 120 | 108 | 101 |  96 |  92 | 1,984   |  35k      | ~35 ms    |
| 10 | 11 | 110 | 110 | 100 |  94 |  90 |  87 | 1,776   |  57k      | ~57 ms    |
| 8  | 13 | 104 | 104 |  96 |  91 |  88 |  85 | 1,616   | 180k      | ~180 ms   |
| 10 | 10 | 100 | 100 |  90 |  84 |  80 |  77 | 1,632   |  29k      | ~29 ms    |

Bold = current selection.

### Why K=14, A=10

Among rows that retain q=1 = 128 bits (NIST Level 1), the selection trades
off:

- **Size** (~600 B smaller than K=14, A=13): 2,336 B fits comfortably on-chain
  even with full UserOp overhead.
- **Signing time** (~8× faster than K=14, A=13): 41 ms in Python is
  essentially instantaneous; sub-second on practically any CPU.
- **Security at q=1**: 128 bits — at the Level 1 ceiling. The headroom over
  the cap (K·A = 140 vs n = 128) is only 12 bits, so reuse degrades faster
  than the K=14, A=13 baseline (q=10: 94 bits vs 128). For the
  rotation-per-UserOp model this is fine; for protocols with potential
  long-term reuse, prefer K=14, A=13 (table top row).

### When to revisit

Move to **K=14, A=13** (or another row with K·A ≥ 180) if any of:
- The threat model expands to "many signatures per key" (some Layer-2
  protocol where rotation discipline is hard to enforce). At K=14, A=13,
  q=10 still sits at 128 bits; here it drops to 94.
- A rigorous q=64 or higher bound is required.

Move to a smaller row (e.g. K=12, A=10 at 1,984 B / 35 ms) if signature size
becomes the binding constraint and you can accept q=1 = 120 bits (below
Level 1).

To revisit, change `FORS_K` and `FORS_A` at the top of
`src/Verifiers/ForsVerifier.sol`. All other parameter-derived values (loop bounds,
bit masks, shift counts, signature length, roots-hash length) are
computed from those two constants and hoisted into stack locals at the
top of `recover()`, so no assembly literal needs to be touched in
lockstep. Update the parameter-summary block at the top of the file and
the relevant numbers in this doc to keep documentation in sync, and run
the account tests (`test/SimpleAccount.t.sol`) — the new
`FORS_SIG_LEN` flows through automatically and the mock-based suite
exercises the length check.

---

## 8. Signer workflow

For one UserOp signature with rotation (fresh keypair per UserOp):

1. **Derive `skSeed` from BIP44**: take the relevant 32-byte HD-derived
   seed, truncate / KDF down to 16 bytes. Same trick as WOTS+C.
2. **Derive `pkSeed`**: e.g., `pkSeed = keccak(skSeed ‖ "pub")[0..16]`. Public,
   travels with the signature.
3. **Build the K−1 = 13 FORS trees**: for each tree `t`, for each leaf
   `l ∈ [0, 2^A)`, compute `sk_{t,l} = PRF(skSeed, ADRS_{t,l})` and
   `leaf_{t,l} = F(pkSeed, ADRS_{t,l}, sk_{t,l})`, then climb to a root via H.
4. **Compute `pkRoot = T(pkSeed, ADRS_roots, root_0, …, root_{K-2})`**.
5. **Compute address = `keccak(pkSeed ‖ pkRoot)[12:32]`**. This is the
   `nextOwner` we'll embed in the *current* UserOp's calldata.
6. **Compute `R = PRF(skSeed, userOpHash)`**.
7. **Grind**: for `counter = 0, 1, …`, compute
   `dVal = keccak(pkSeed ‖ R ‖ userOpHash ‖ DOM ‖ counter)` until the bottom
   A bits of dVal are zero. ~2^A attempts on average.
8. **Open trees**: for `t = 0, …, K−2`, extract `mdT = (dVal >> A·t) & MASK`,
   look up the leaf and its auth path in the cached tree, append to signature.
9. **Pack the signature**: `R ‖ pkSeed ‖ tree_0 ‖ … ‖ tree_{K-2} ‖ counter`.

The verifier (on-chain) does the inverse: read R, pkSeed, counter; recompute
dVal; verify the zero-bit constraint; for each tree, recompute the leaf hash
from the revealed `sk` then climb the auth path to a root; compress all K−1
roots into pkRoot; recompute the address and compare to the stored `owner`.

---

## 9. Hardware-wallet feasibility

For a Ledger-class secure element (ST33, ARM SC000, ~30 MHz):

- **Keccak in software** (no HW accel): ~3 ms per call → 41,000 × 3 ms ≈
  **~2 minutes per signature**. Painful but not impossible. For comparison,
  the K=14, A=13 baseline would have been ~17 minutes — clearly infeasible.
- **SHA-256 with HW accel** (~2 μs per call): would be **~80 ms** if we ever
  forked the verifier to a SHA-256 variant. Comfortable for interactive UX.

A modern phone or desktop signs in **~41 ms** regardless. Practical paths:

| Signing platform                  | Per-sig time | Verdict          |
| --------------------------------- | ------------ | ---------------- |
| Phone / desktop (any modern CPU)  | ~10–50 ms    | trivial          |
| Ledger-SE, Keccak (current scheme)| ~2 min       | borderline       |
| Ledger-SE, SHA-256 (future fork)  | ~80 ms       | comfortable      |
| Pure Python `hashlib` (laptop)    | ~41 ms       | trivial          |

If interactive Ledger signing becomes a priority, the path is: instantiate a
SHA-256 variant of this verifier (separate contract, new domain byte). The
verifier change is mostly mechanical; the harder bit is producing test
vectors that match the spec. Tracked as a separate followup if/when needed.

---

## 10. Related schemes (briefly)

### HORS

Original few-time scheme (Reyzin–Reyzin 2002). Same "K boxes" idea but with
the public key being the *full set of leaf-hashes* (no Merkle compression).
Public key size = T · 16 B per tree → tens of KB. Not on-chain feasible
unless you hash-commit the pubkey, in which case the signature has to ship
the full pubkey to reconstruct. So HORS is dominated by HORST/FORS in our
setting.

### PORS+FP (Forced Pruning)

Aumasson–Endignoux PORS (2018) + Abri–Katz forced-pruning grinding
(ePrint 2025/2069). One big Merkle tree of `K · t` leaves instead of K
small ones; K *distinct* indices selected via PRNG; auth paths combined
into one **Octopus** authentication set; signer grinds until the Octopus
size fits a constant cap. Saves ~5–10% on signature size vs FORS+C.

Cost: significantly more complex verifier (variable-shape Octopus
reconstruction in EVM, not the tight fixed-size loop FORS+C uses), and a
larger Merkle tree to compute at signing time. Not worth it at our current
size budget. Tracked as a possible future optimization if signature size
ever becomes the binding constraint.

### WOTS+C (parallel signer in this codebase)

One-time signature (OTS), not few-time: any reuse breaks immediately.
Smaller signature than FORS at comparable security (~750 B vs 1,984 B for
FORS+C). WOTS+C is no longer part of this repo; the legacy contracts live in
git history (branch `archive/dev-pre-cleanup`, directory
`other-implementations/`). The main `SimpleAccountFactory` deploys the FORS-backed
`SimpleAccount`; FORS is the safer-on-reuse alternative to WOTS+C, paying
~3x the bytes for graceful degradation.

---

## 11. References

- D.J. Bernstein et al., *The SPHINCS+ Signature Framework*, ACM CCS 2019.
  [DOI](https://doi.org/10.1145/3319535.3363229)
- A. Hülsing, M.A. Kudinov, E. Ronen, E. Yogev. *SPHINCS+C: Compressing
  SPHINCS+ with (almost) no cost*. IEEE S&P 2023.
  [DOI](https://doi.org/10.1109/SP46215.2023.10179381)
- A. Hülsing, M.A. Kudinov. *Recovering the Tight Security Proof of
  SPHINCS+*. ASIACRYPT 2022.
- M. Kudinov, J. Nick. *Hash-based Signature Schemes for Bitcoin*.
  Blockstream Research, 2025-12-05. (Sections 9, 9.2, 13.2, 14.)
  Comprehensive treatment including FORS+C and PORS+FP parameter analysis.
- L. Reyzin, N. Reyzin. *Better than BiBa: Short One-Time Signatures with
  Fast Signing and Verifying*. ACISP 2002. (Original HORS paper.)
- J.-P. Aumasson, G. Endignoux. *Improving Stateless Hash-Based Signatures*.
  CT-RSA 2018. (Original PORS paper.)
- M. Abri, J. Katz. *Shorter Hash-Based Signatures Using Forced Pruning*.
  ePrint 2025/2069. (PORS+FP.)
- NIST FIPS 205, *Stateless Hash-Based Digital Signature Standard (SLH-DSA)*.
  [DOI](https://doi.org/10.6028/NIST.FIPS.205)
