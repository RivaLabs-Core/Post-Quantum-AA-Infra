# Multi-Chain Consistent Addresses

This document explains the commitment mechanism used to give the same user the
same smart account address on multiple chains, while still allowing each chain
to use a different first signer.

It is intentionally explanatory. The exact byte encodings and signature layout
are documented separately in [signing-spec.md](signing-spec.md) and the
implementation.

## The Problem

The account is deployed with CREATE2, so its address is determined before the
account exists onchain.

That is useful because the wallet can know the user's account address in
advance. It is also dangerous if the CREATE2 inputs contain anything that is
different from chain to chain.

The first signer cannot be part of the CREATE2 salt, because the wallet derives
a different first signer on every chain. If the salt included the chain-local
first signer, the user would get a different account address on every chain.

The goal is therefore:

```text
same user
same account address
different first signer per chain
```

## The Core Idea

Instead of putting the first signer directly into the CREATE2 salt, the salt
contains a commitment to all supported first signers.

That commitment is a Merkle root.

Each supported chain contributes one leaf:

```text
chain id + first signer for that chain
```

The root is the same on every chain because it is built from the same full list
of supported chains. The account address can therefore depend on the root
without depending on any one chain's local signer.

At activation time, the account verifies that the signer used on the current
chain is one of the signers committed in the root.

## What The Root Means

The root means:

```text
"This account may be activated by these chain-specific first signers,
and only on their corresponding chains."
```

It does not mean:

```text
"Every chain uses the same first signer."
```

The leaf includes the chain id, so a signer committed for one chain cannot be
used to activate the account on another chain.

For example:

```text
Ethereum Sepolia    -> signer A
Base Sepolia        -> signer B
Arbitrum Sepolia    -> signer C
OP Sepolia          -> signer D
```

All four leaves produce one root. That same root is used everywhere. But on
each chain, only the leaf for that chain can pass activation.

## Why This Keeps The Address Stable

The account address depends on:

```text
factory address
account implementation address
initial signer root
user salt
```

The address does not depend on the individual first signer.

So if the deployment is uniform across chains, these inputs can be identical:

```text
same factory
same account implementation
same root
same user salt
```

Then the predicted account address is identical on every supported chain.

## Why Deployment Uniformity Matters

The root is only one part of the address calculation.

The factory and account implementation must also be the same across chains. If
the factory address changes, the account address changes. If the implementation
address changes, the account address changes.

For this reason, the factory deployment itself must be deterministic across
chains. The deploy script deploys the verifier and factory through CREATE2 so
that the same bytecode, salts, and constructor arguments produce the same
addresses on every target chain.

The important invariant is:

```text
same verifier address
same factory address
same account implementation address
same root
same user salt
```

If any of those values drift, the account address can drift.

## Account Lifecycle

The account starts inactive.

When the factory deploys the account, it stores the root but does not set an
owner:

```text
owner = address(0)
initialSignerRoot = root
```

`owner = address(0)` is not a normal usable state. It means the account is
waiting for its first valid activation.

During activation, the user provides:

```text
the first signature
the Merkle proof for this chain's first signer
the next owner to rotate into
```

If the proof is valid and the signature recovers the expected chain-local first
signer, the account rotates from:

```text
owner = address(0)
```

to:

```text
owner = next signer
```

After that, the Merkle root is no longer used for normal transactions. Normal
validation checks the current owner and rotates to the next owner after each
successful operation.

## Activation In Plain Terms

The first UserOp says:

```text
"I am the first signer for this chain.
Here is a proof that this signer was committed in the root.
Here is the next signer the account should use after activation."
```

The account checks:

1. The account is still inactive.
2. The signature recovers a nonzero signer.
3. The current chain id plus the recovered signer form a leaf.
4. The provided Merkle proof connects that leaf to the stored root.
5. The requested next owner is valid.

If all checks pass, the account activates and immediately rotates to the next
owner.

This is important because the first signer is consumed during activation. It is
not kept as the long-term owner.

## Why The Chain ID Is In The Leaf

The chain id prevents cross-chain proof reuse.

Without the chain id, the same signer proof could be replayed on another chain
that shares the same root. With the chain id included, the account rebuilds the
leaf using `block.chainid`, so the proof is only valid on the intended chain.

This lets the wallet safely use different derivation paths on different chains.

## Adding Or Removing Chains

The root commits to the full supported-chain set.

If a chain is added after the root is created, the root changes. If the root
changes, the account address changes.

Therefore, every chain that should share the same address must be included in
the root before the account address is derived.

This is the main planning constraint:

```text
future shared-address chains must be committed up front
```

If a chain was not committed up front, it can still be supported later, but it
will belong to a different root and therefore a different account address.

## Deployment Race During The First UserOp

The first UserOp may include account deployment data. That is the standard
ERC-4337 flow.

There is a minor race: someone else may deploy the account before the user's
first UserOp lands.

That does not give them control. The deployed account is still inactive and
still contains the expected root.

The practical consequence is that the original UserOp may fail if the EntryPoint
rejects nonempty deployment data for an account that already exists. The wallet
can recover by checking the already-deployed account and resubmitting activation
without deployment data.

Because the resubmitted UserOp has a different hash, it needs a fresh
activation signature. The current design accepts this under the bounded FORS+C
reuse policy for this specific deployment race.

## What Must Be Checked Offchain

Before relying on a predicted account address, the wallet or deployment tooling
must verify:

```text
factory address matches on every chain
account implementation address matches on every chain
verifier address matches on every chain
EntryPoint address is the expected one
initialSignerRoot is identical on every chain
user salt is identical on every chain
```

Before retrying activation after a predeployment race, the wallet must verify:

```text
account code exists
account root equals the expected root
owner is still address(0)
EntryPoint is the expected EntryPoint
verifier is the expected verifier
```

If those checks pass, the wallet can treat the predeployed account as the
correct inactive account and continue activation.

## Summary

The commitment mechanism separates account address identity from chain-local
first signers.

The account address depends on one shared root, not on any individual first
signer. The root commits to the authorized first signer for each supported
chain. During activation, the current chain's signer proves membership in that
root and immediately rotates the account to the next owner.

This gives the wallet a stable multi-chain account address while preserving
chain-specific derivation paths and avoiding first-signer reuse across chains.
