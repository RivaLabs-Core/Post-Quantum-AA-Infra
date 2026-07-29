# NiceTry Signing Spec

This document is the byte-level signing specification for off-chain signers
that target the current Solidity contracts in this repo.

It intentionally describes the contract-visible transcript, not a hardware
wallet UX. If two implementations follow this document, they should produce
signatures that recover the same owner address in:

- `src/Verifiers/ForsVerifier.sol`
- `src/SimpleAccount.sol`
- `other-implementations/wots/WotsCVerifier.sol`
- `other-implementations/wots/SimpleAccount_WOTS.sol`
- `other-implementations/wots/KernelRotatingWOTSValidator.sol`

ECDSA is included only for account-level binding rules. The post-quantum
signature formats are WOTS+C and FORS+C.

## 1. Shared Conventions

### 1.1 Hash

All hashes use Ethereum `keccak256`, not NIST SHA3-256.

```text
keccak256(bytes) -> 32 bytes
```

### 1.2 Truncation

`N = 16` for both WOTS+C and FORS+C.

When a hash is truncated to `N`, take the first 16 bytes of the 32-byte
Keccak output:

```text
left16(h) = h[0:16]
```

This matches Solidity `bytes16(keccak256(...))` and the verifier's top-half
word masking.

Ethereum-style owner addresses use the last 20 bytes of a 32-byte Keccak
output:

```text
last20(h) = h[12:32]
```

### 1.3 Integers

All fixed-width integer byte encodings are big-endian:

```text
uint32_be(x)  = 4-byte big-endian encoding of x
uint64_be(x)  = 8-byte big-endian encoding of x
uint128_be(x) = 16-byte big-endian encoding of x
uint256_be(x) = 32-byte big-endian encoding of x
```

When the Solidity verifier hashes a padded 16-byte value, the value occupies
the first 16 bytes of a 32-byte slot:

```text
pad32(x16) = x16 || 16 zero bytes
```

There are no ABI dynamic-length prefixes inside the WOTS/FORS hash transcripts.
Every input below is raw byte concatenation.

### 1.4 UserOp Digest Binding

For WOTS+C and FORS+C accounts, the signed digest is the raw ERC-4337
`userOpHash`. The first FORS+C activation uses a larger signature envelope, but
the FORS blob inside that envelope still signs `userOpHash`.

The signer must build the UserOp so that `userOp.callData` ends with the next
owner address:

```text
userOp.callData = account_specific_callData || bytes20(nextOwner)
digest          = EntryPoint.getUserOpHash(userOp)
signature       = sign(currentSigner, digest)
```

The `nextOwner` must be the address of the next already-derived signer.

The account verifies the signature against the current owner and, if valid,
rotates:

```text
owner = nextOwner
```

Do not put `nextOwner` in the signature only. It must be in `callData`, because
`userOpHash` commits to `callData`.

For the root-based FORS account, deployment starts with `owner == address(0)`.
The first UserOp must use the activation signature envelope described in
[Account-Level Signing Procedure](#5-account-level-signing-procedure). After
activation, normal FORS signatures are exactly `FORS_SIG_LEN` bytes again.

ECDSA mode differs only in the signing primitive: it signs
`toEthSignedMessageHash(userOpHash)`, matching OpenZeppelin `ECDSA.recover`.
WOTS+C and FORS+C sign `userOpHash` directly.

## 2. Recommended Local Key Derivation

The verifier does not know how keys are derived. It only sees public seeds and
signature bytes. Still, for interoperability and reproducible test vectors, use
this deterministic derivation unless you intentionally define another version.

If starting from a BIP44/ECDSA private key, treat the 32-byte scalar as:

```text
masterSecret = uint256_be(ecdsaPrivateScalar)
```

Do not use ECDSA signing in the derivation. Use the scalar bytes only as KDF
input.

Recommended v1 derivation:

```text
FORS skSeed(index) = left16(keccak256("NiceTry/FORS/skSeed/v1" || masterSecret || uint64_be(index)))
FORS pkSeed(index) = left16(keccak256("NiceTry/FORS/pkSeed/v1" || masterSecret || uint64_be(index)))

WOTS sk(index, i)  = left16(keccak256("NiceTry/WOTS/sk/v1" || masterSecret || uint64_be(index) || uint32_be(i)))
WOTS pkSeed(index) = left16(keccak256("NiceTry/WOTS/pkSeed/v1" || masterSecret || uint64_be(index)))
```

The `index` is the local signer sequence number:

```text
S_0 = first owner
S_1 = next owner after first UserOp
S_2 = next owner after second UserOp
...
```

The Solidity tests currently use simpler toy derivations. Those are test-only
and should not be copied into production signer code.

## 3. WOTS+C

### 3.1 Parameters

```text
N             = 16
L             = 26
W_BITS        = 5
W             = 32
W_MAX         = 31
TARGET_SUM    = 403
WOTS_BLOB_LEN = 468
```

### 3.2 Signature Layout

```text
offset   length   field
0        416      sigChains: 26 entries * 16 bytes
416      32       R
448      4        ctr
452      16       pkSeed
```

So:

```text
sig[0 + i*16 : 16 + i*16] = chain value for i, for i in 0..25
sig[416 : 448]            = R
sig[448 : 452]            = uint32_be(ctr)
sig[452 : 468]            = pkSeed
```

### 3.3 WOTS ADRS

ADRS is a 32-byte big-endian integer word.

The chain hash address is:

```text
ADRS_HASH(i, s) = uint256_be((i << 32) | s)
```

The public-key compression address is:

```text
ADRS_PK = uint256_be(1 << 96)
```

### 3.4 WOTS Chain Step

```text
chainStep(pkSeed, i, s, cur) =
    left16(keccak256(pkSeed || ADRS_HASH(i, s) || cur))
```

Input length is:

```text
16 + 32 + 16 = 64 bytes
```

No zero padding is inserted between these fields.

### 3.5 WOTS Public Key And Address

Given private chain starts:

```text
sk[0], sk[1], ..., sk[25]
```

derive public chain endpoints:

```text
pk[i] = sk[i]
for s in 0..30:
    pk[i] = chainStep(pkSeed, i, s, pk[i])
```

Then compress:

```text
pkRoot = left16(keccak256(pkSeed || ADRS_PK || pk[0] || pk[1] || ... || pk[25]))
```

Input length is:

```text
16 + 32 + 26*16 = 464 bytes
```

The WOTS owner address is:

```text
wotsAddress = last20(keccak256(pkSeed || pkRoot))
```

Input length is exactly 32 bytes.

### 3.6 WOTS Message Digest Digits

For signing, first find a 4-byte counter whose checksum matches
`TARGET_SUM`.

The signer chooses a 32-byte randomizer `R`. For deterministic signing vectors,
use:

```text
R = keccak256("NiceTry/WOTS/R/v1" || masterSecret || uint64_be(index) || digest)
```

Then search:

```text
for ctr in 0..2^32-1:
    h = keccak256(R || uint32_be(ctr) || digest)
    digits[i] = (uint256(h) >> (251 - 5*i)) & 31, for i in 0..25
    if sum(digits) == 403:
        use this ctr
        break
```

This extraction is MSB-first over the 32-byte `h`. Digit 0 uses bits 251..255
in Solidity shift notation, matching:

```text
WOTS_DIGIT_SHIFT_0 = 256 - W_BITS = 251
```

### 3.7 WOTS Signing

For each chain:

```text
cur = sk[i]
for s in 0..digits[i]-1:
    cur = chainStep(pkSeed, i, s, cur)
sigChains[i] = cur
```

Assemble:

```text
signature =
    sigChains[0] || ... || sigChains[25] ||
    R ||
    uint32_be(ctr) ||
    pkSeed
```

The verifier recovers by walking each chain from `digits[i]` up to `W_MAX - 1`
and then recompressing the endpoint public key.

## 4. FORS+C

### 4.1 Parameters

```text
N             = 16
K             = 26
A             = 5
REAL_TREES    = K - 1 = 25
LEAVES        = 2^A = 32
FORS_SIG_LEN  = 2448
TREE_LEN      = 16 + A*16 = 96
SECTION_LEN   = 25 * 96 = 2400
```

FORS+C drops the K-th tree and replaces it with a counter-grinding condition.
Only trees `t = 0..24` are included in the signature and public-root
compression.

### 4.2 Signature Layout

```text
offset   length   field
0        16       R
16       16       pkSeed
32       2400     tree openings for t = 0..24
2432     16       counter
```

Each tree opening is 96 bytes:

```text
treeOffset(t) = 32 + 96*t

offset within tree   length   field
0                    16       sk for selected leaf
16                   16       auth[0], leaf-level sibling
32                   16       auth[1]
48                   16       auth[2]
64                   16       auth[3]
80                   16       auth[4], root-level sibling
```

Final signature:

```text
signature =
    R ||
    pkSeed ||
    openTree(0) || ... || openTree(24) ||
    uint128_be(counter)
```

### 4.3 FORS ADRS

ADRS is a 32-byte big-endian integer word following the FIPS 205 §4.2 field
layout: layer address at bytes 0..4, tree address at bytes 4..16, type at
bytes 16..20, then three type-dependent words. Layer, tree and the keypair
word are all zero for standalone FORS+C, since there is no hypertree above
and no enclosing WOTS+ leaf.

Implement the integer formulas below exactly; they are the current contract
encoding.

Constants:

```text
FORS_TYPE_FORS_TREE  = 3
FORS_TYPE_FORS_ROOTS = 4
```

Leaf ADRS:

```text
ADRS_LEAF(t, leafIdx) =
    uint256_be((3 << 96) | ((t << A) | leafIdx))
```

Internal node ADRS at tree height `cp`, where `cp = 1..5`:

```text
ADRS_NODE(t, cp, parentIdx) =
    uint256_be((3 << 96) | (cp << 32) | ((t << (A - cp)) | parentIdx))
```

Roots-compression ADRS:

```text
ADRS_ROOTS = uint256_be(4 << 96)
```

### 4.4 FORS Hash Primitives

All 16-byte fields are padded with trailing zero bytes to 32-byte slots inside
FORS hash transcripts.

Secret expansion:

```text
PRF(skSeed, adrs) =
    left16(keccak256(pad32(skSeed) || adrs))
```

Input length: 64 bytes.

Leaf hash:

```text
F(pkSeed, adrs, sk) =
    left16(keccak256(pad32(pkSeed) || adrs || pad32(sk)))
```

Input length: 96 bytes.

Internal node hash:

```text
H(pkSeed, adrs, left, right) =
    left16(keccak256(pad32(pkSeed) || adrs || pad32(left) || pad32(right)))
```

Input length: 128 bytes.

Message hash:

```text
FORS_DOM = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd

Hmsg(pkSeed, R, digest, counter) =
    keccak256(
        pad32(pkSeed) ||
        pad32(R) ||
        digest ||
        uint256_be(FORS_DOM) ||
        pad32(uint128_be(counter))
    )
```

Input length: 160 bytes. `Hmsg` is not truncated before digit extraction.

Roots compression:

```text
T_roots(pkSeed, roots[0..24]) =
    left16(keccak256(
        pad32(pkSeed) ||
        ADRS_ROOTS ||
        pad32(roots[0]) ||
        ... ||
        pad32(roots[24])
    ))
```

Input length:

```text
(K + 1) * 32 = 864 bytes
```

FORS address:

```text
forsAddress = last20(keccak256(pad32(pkSeed) || pad32(pkRoot)))
```

Input length is 64 bytes. This is intentionally different from the WOTS
address input, which is tightly packed to 32 bytes.

### 4.5 FORS Tree Construction

For each real tree `t = 0..24`, build 32 leaves:

```text
for leafIdx in 0..31:
    adrs = ADRS_LEAF(t, leafIdx)
    sk_leaf[leafIdx] = PRF(skSeed, adrs)
    level[0][leafIdx] = F(pkSeed, adrs, sk_leaf[leafIdx])
```

Then build parent levels:

```text
for cp in 1..5:
    for parentIdx in 0..(2^(A-cp)-1):
        left  = level[cp-1][2*parentIdx]
        right = level[cp-1][2*parentIdx + 1]
        adrs  = ADRS_NODE(t, cp, parentIdx)
        level[cp][parentIdx] = H(pkSeed, adrs, left, right)
```

The root of tree `t` is:

```text
root[t] = level[5][0]
```

### 4.6 FORS Public Key And Address

Build the 25 real tree roots:

```text
for t in 0..24:
    root[t] = buildTree(t).root
```

Then:

```text
pkRoot = T_roots(pkSeed, root[0..24])
addr   = forsAddress(pkSeed, pkRoot)
```

This `addr` is the on-chain owner address for this FORS signer.

### 4.7 FORS Message Indices And Grinding

The signer chooses a 16-byte randomizer `R`. For deterministic signing vectors,
use:

```text
R = left16(keccak256("NiceTry/FORS/R/v1" || skSeed || digest))
```

Then search a 16-byte counter:

```text
for counter in 0..2^128-1:
    dVal = Hmsg(pkSeed, R, digest, counter)

    md[t] = (uint256(dVal) >> (5*t)) & 31, for t in 0..25

    if md[25] == 0:
        use this counter
        break
```

Important: FORS index extraction is LSB-first. Tree `t = 0` uses the lowest
5 bits of `dVal`, tree `t = 1` uses the next 5 bits, and so on. The omitted
K-th tree is represented only by the grinding check:

```text
((uint256(dVal) >> 125) & 31) == 0
```

### 4.8 FORS Signing

After finding `counter` and `md[0..24]`, emit one opening per real tree.

For tree `t`:

```text
leafIdx = md[t]
sk      = PRF(skSeed, ADRS_LEAF(t, leafIdx))
auth    = []

idx = leafIdx
for cp in 0..4:
    siblingIdx = idx ^ 1
    auth[cp] = level[cp][siblingIdx]
    idx = idx >> 1
```

The auth path is bottom-up:

```text
auth[0] = sibling leaf
auth[1] = sibling at height 1
auth[2] = sibling at height 2
auth[3] = sibling at height 3
auth[4] = sibling at height 4
```

Then:

```text
openTree(t) = sk || auth[0] || auth[1] || auth[2] || auth[3] || auth[4]
```

Final signature:

```text
signature =
    R ||
    pkSeed ||
    openTree(0) ||
    openTree(1) ||
    ... ||
    openTree(24) ||
    uint128_be(counter)
```

### 4.9 FORS Verification Shape

The Solidity verifier:

1. Checks `signature.length == 2448`.
2. Recomputes `dVal`.
3. Checks the omitted tree's `md[25] == 0`.
4. Recomputes 25 roots from the provided leaf secrets and auth paths.
5. Compresses those roots into `pkRoot`.
6. Returns `last20(keccak256(pad32(pkSeed) || pad32(pkRoot)))`.

Malformed FORS signatures usually recover a different nonzero address. They
only return `address(0)` on bad length or failed grinding check.

## 5. Account-Level Signing Procedure

### 5.1 Initial Activation

The root-based FORS account is deployed inactive:

```text
owner             = address(0)
initialSignerRoot = Merkle root over supported-chain initial signers
```

The first UserOp proves that the chain-local first signer is in that root. The
activation signature layout is:

```text
offset  length  field
0       1       activationVersion = 1
1       2       proofLen = uint16_be(number of proof siblings)
3       32*N    Merkle proof siblings
3+32N   2448    FORS signature over EntryPoint.getUserOpHash(userOp)
```

The activation Merkle leaf is:

```text
leaf = keccak256(abi.encode(
    keccak256("NiceTryInitialSignerLeaf:v1(uint256 chainId,address signer)"),
    chainId,
    initialSignerAddress
))
```

The tree uses sorted-pair Keccak hashing, verified onchain with Solady
`MerkleProofLib.verify`.

Activation procedure:

```text
initial = chain-local first signer S_0
next    = already-derived signer S_1

callData = account_call || bytes20(address(S_1))
userOp   = PackedUserOperation(..., callData=callData, signature="")
digest   = EntryPoint.getUserOpHash(userOp)

forsSig = FORS_sign(S_0, digest)
userOp.signature =
    activationVersion ||
    proofLen ||
    merkleProof ||
    forsSig

submit userOp
```

If the UserOp includes `initCode` and the account is predeployed before the
UserOp lands, the retry with `initCode = ""` has a different `userOpHash` and
therefore needs a second activation signature. This is intentional in the
current ERC-4337 implementation and relies on the FORS+C bounded-reuse policy
for that deployment race.

### 5.2 Normal Rotation

For each transaction:

```text
current = cached signer S_i
next    = cached signer S_{i+1}

assert onchain owner == address(S_i)

callData = account_call || bytes20(address(S_{i+1}))
userOp   = PackedUserOperation(..., callData=callData, signature="")
digest   = EntryPoint.getUserOpHash(userOp)

signature = WOTS_sign(S_i, digest)
         or FORS_sign(S_i, digest)

userOp.signature = signature
submit userOp
```

The signer should burn or mark `S_i` as used before releasing signature bytes.
After signing, it should start preparing `S_{i+2}` so the next transaction can
use:

```text
current = S_{i+1}
next    = S_{i+2}
```

For replacement or dropped transactions, the local policy may allow bounded
reuse for FORS+C. WOTS+C should be treated as strictly one-time.

## 6. Test Vector Requirements

An off-chain signer should be able to emit JSON vectors containing at least:

```json
{
  "scheme": "FORS+C",
  "params": { "n": 16, "k": 26, "a": 5 },
  "index": 0,
  "digest": "0x...",
  "skSeed": "0x...",
  "pkSeed": "0x...",
  "R": "0x...",
  "counter": "0x...",
  "dVal": "0x...",
  "md": [0, 1, 2],
  "pkRoot": "0x...",
  "address": "0x...",
  "signature": "0x..."
}
```

For WOTS+C:

```json
{
  "scheme": "WOTS+C",
  "params": { "n": 16, "l": 26, "wBits": 5, "targetSum": 403 },
  "index": 0,
  "digest": "0x...",
  "pkSeed": "0x...",
  "R": "0x...",
  "ctr": 0,
  "h": "0x...",
  "digits": [0, 1, 2],
  "pkRoot": "0x...",
  "address": "0x...",
  "signature": "0x..."
}
```

Foundry tests should assert:

```solidity
assertEq(verifier.recover(signature, digest), expectedAddress);
assertEq(verifier.wrecover(signature, digest), expectedAddress);
```

and should include mutation tests across every field and boundary.
