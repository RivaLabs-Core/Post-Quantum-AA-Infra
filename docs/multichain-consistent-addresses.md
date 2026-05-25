# Multi-Chain Consistent Addresses

This note documents the account-address mechanism implemented by
`SimpleAccountFactory` and `SimpleAccount`.

## Goal

The same user account should resolve to the same counterfactual address on every
supported chain, while each chain can use a different first signer derived from
a different wallet path.

The account address therefore cannot depend on the chain-local first signer.
Instead, it depends on one commitment: a Merkle root over the supported chains'
initial signers.

## CREATE2 Preimage

The account is an EIP-1167 clone deployed by `SimpleAccountFactory` with
Solady's `cloneDeterministic`.

The final address is:

```text
address = last20(keccak256(
    0xff ||
    factory ||
    fullSalt ||
    keccak256(cloneInitCode(accountImplementation))
))
```

`fullSalt` is:

```text
ACCOUNT_SALT_TYPEHASH =
  keccak256("NiceTryAccountSalt:v1(bytes32 initialSignerRoot,uint256 salt)")

fullSalt = keccak256(abi.encode(
    ACCOUNT_SALT_TYPEHASH,
    initialSignerRoot,
    salt
))
```

The first signer is deliberately absent from the salt. Two chains with the same
factory address, account implementation address, root, and user salt predict the
same account address.

This also means uniform deployment is required:

```text
same factory address
same account implementation address
same factory bytecode
same implementation bytecode
same EntryPoint and verifier assumptions
same root and user salt
```

If any of those drift, the address can drift.

## Initial Signer Root

The root commits to the first signer for each supported chain.

Each leaf is:

```text
INITIAL_SIGNER_LEAF_TYPEHASH =
  keccak256(
    "NiceTryInitialSignerLeaf:v1(uint256 chainId,address signer,bytes32 derivationPathHash,uint8 schemeId,uint64 signerIndex)"
  )

leaf = keccak256(abi.encode(
    INITIAL_SIGNER_LEAF_TYPEHASH,
    chainId,
    signer,
    derivationPathHash,
    schemeId,
    signerIndex
))
```

Current constants:

```text
schemeId    = 1   // FORS+C
signerIndex = 0   // initial signer only
```

The Merkle tree uses sorted-pair Keccak hashing, matching OpenZeppelin
`MerkleProof`:

```text
parent = keccak256(min(a, b) || max(a, b))
```

The `chainId` is part of the leaf. During activation the contract reconstructs
the leaf with `block.chainid`, so a proof for one chain cannot activate the same
root on another chain.

## Account Lifecycle

Deployment does not set an owner:

```text
factory.createAccount(initialSignerRoot, salt)
  deploys clone at CREATE2 address
  calls account.initialize(initialSignerRoot)

account.owner             = address(0)
account.initialSignerRoot = initialSignerRoot
```

`owner == address(0)` is the inactive state. Inactive accounts accept only the
activation signature format.

After activation:

```text
account.owner = nextOwner
```

From that point onward, validation uses the existing normal FORS path:

```text
userOp.signature = 2448-byte FORS signature
recovered = VERIFIER.recover(userOp.signature, userOpHash)
require recovered == owner
owner = nextOwner from the calldata tail
```

## Activation Signature

When `owner == address(0)`, `userOp.signature` is a fixed header, a Merkle proof,
and the normal FORS signature:

```text
offset  length  field
0       1       activationVersion = 1
1       1       schemeId = 1 for FORS+C
2       8       signerIndex, uint64 big-endian, currently 0
10      32      derivationPathHash
42      2       proofLen, uint16 big-endian
44      32*N    Merkle proof siblings
44+32N  2448    FORS signature blob
```

Validation flow:

```text
1. Read nextOwner from the last 20 bytes of userOp.callData.
2. Parse activation header.
3. Require version == 1.
4. Require schemeId == FORS+C.
5. Require signerIndex == 0.
6. Recover initial signer from the FORS blob over userOpHash.
7. Rebuild leaf using block.chainid, recovered signer, derivationPathHash,
   schemeId, signerIndex.
8. Verify Merkle proof against initialSignerRoot.
9. Rotate owner to nextOwner.
```

Malformed activation signatures return `SIG_VALIDATION_FAILED`. A zero
`nextOwner` reverts through the same rotation guard used by the normal path.

## First UserOp Deployment Race

The first UserOp may still use standard ERC-4337 deployment:

```text
sender   = factory.getAddress(root, salt)
initCode = factory || createAccount(root, salt)
signature = activation signature
```

If someone predeploys the same root-only account before this UserOp lands, the
UserOp can fail on EntryPoint versions that reject nonempty `initCode` for an
already-deployed sender. That is not a takeover: the deployed account is still
inactive and still has the expected root.

The retry flow is:

```text
1. Check sender.code.length > 0.
2. Check account.initialSignerRoot() == expected root.
3. Check account.owner() == address(0).
4. Check account.ENTRY_POINT() and account.VERIFIER().
5. Resubmit activation with initCode = "".
6. Produce a fresh activation signature over the new userOpHash.
```

For FORS+C this is acceptable if the local reuse policy allows `q = 2` for this
failure mode. A stricter wallet can avoid the second signature by predeploying
the inactive account before asking the device for the activation signature.

## Future Chain Support

Adding a new chain changes the root unless that chain's first signer was already
included. A changed root means a different account address. Chains that must
share the same address later need to be committed in the root up front.
