# SPHINCS- account

`src/SphincsAccount.sol` is an ERC-4337 account authenticated solely by a SPHINCS- signature.
It is a parallel account family to `SimpleAccount` (FORS+C primary, SPHINCS- backup), deployed by
its own factory and never sharing an address, an implementation or a salt domain with it.

> The verifier is UNAUDITED research code and no reference vector is committed yet, so its
> positive path is not covered by the test suite. Gate any real-funds use on an audit and on
> end-to-end vectors produced by a real signer.

## Why it is simpler than SimpleAccount

Everything in `SimpleAccount` that tracks keys (`authState`, `activated`, `initialSignerRoot`,
the Merkle activation envelope, the `[currentKey][nextOwner]` callData tail) exists because
FORS+C is a few-time scheme whose key must be burned and replaced on every use. SPHINCS- is
stateless and many-time: one `(pkSeed, pkRoot)` signs indefinitely. So this account has:

- no rotation and no per-signer state,
- no activation step and no Merkle tree,
- no trailing key material in `callData`,
- exactly one signer type, hence no length dispatch.

Replay protection comes entirely from the EntryPoint nonce. `userOpHash` binds sender, nonce,
chain id and callData, so a signature is valid for exactly one UserOp on exactly one chain.

## Contracts

| Contract | Role |
| --- | --- |
| `SphincsAccount` | The account. `initialize(pkSeed, pkRoot)` once; `_validateSignature` checks length then calls the verifier. |
| `SphincsAccountFactory` | EIP-1167 clone factory. `createAccount(pkSeed, pkRoot, salt)` and `getAddress(...)`. |
| `SphincsStandardVerifier` | Stateless verifier, standard FORS under standard WOTS+, `verify(pkSeed, pkRoot, message, sig) -> bool`. |

## Signature

- `userOp.signature` is the raw 8,400-byte blob (`SPHINCS_STANDARD_SIG_LEN`). No envelope, no
  type tag. A wrong length returns `SIG_VALIDATION_FAILED` without reverting.
- Parameters: n=16, h=20, d=4, a=7, k=29, w=4, l=68 (64 message chains + 4 checksum chains).
  keccak256 tweakable hash, FIPS 205 uncompressed 32-byte ADRS.
- Blob layout: `R(16) || 29 FORS secrets (16 each) || 29 FORS auth paths (7 x 16 each)
  || 4 x [68 WOTS chains (16 each) || subtree auth path (5 x 16)]` = 16 + 464 + 3248 + 4 x 1168.
- Unlike the backup `SphincsVerifier` there is no forced-zero FORS tree and no WOTS+C grinding
  counter, so a standard SLH-DSA-style signer can be used with only the hash function swapped.
- Length classes stay disjoint from the FORS+C (2,448), activation envelope and backup SPHINCS-
  (3,688) blobs. `test/SphincsStandardVerifier.t.sol` asserts this.

## Key binding

The public key is passed to `initialize` and folded into the CREATE2 salt:

```
salt = keccak256(abi.encode(SPHINCS_ACCOUNT_SALT_TYPEHASH, pkSeed, pkRoot, userSalt))
```

so the account address commits to the key and a deploy race cannot install a different key at
the same address. Both the factory and `initialize` reject zero or non-canonical keys (low 128
bits must be zero), because the verifier reverts on a non-canonical key and a stored one would
brick the account permanently. The key is chain-independent, so the same `(pkSeed, pkRoot, salt)`
yields the same address on every chain where the factory is deployed at the same address.

## Budget, cost and recovery

- Signature budget: h=20 gives 2^20 FORS instances selected per message. Security degrades as
  instances are reused; treat about 10^6 signatures per key as the budget and track the count
  off-chain. This is not enforced on-chain.
- Cost: roughly 268k gas to verify plus about 134k gas of calldata for the 8,400-byte
  signature. Budget around 400k gas per UserOp before the call itself and confirm the bundler
  accepts a signature field this large.
- Recovery: there is none. Exactly one key, fixed at `initialize`, no second signer, no rotation.
  Loss of the key is terminal for the account.

## Deploy

`script/DeploySphincsAccount.s.sol` deploys `SphincsStandardVerifier` and
`SphincsAccountFactory` through the canonical CREATE2 deployer, skipping anything already
deployed, and asserts the wiring. It does not touch the `SimpleAccount` family.
