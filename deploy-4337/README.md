# deploy-4337 — gasless infra deploy via ERC-4337 + Pimlico

The account-abstraction sibling of [`script/Deploy.s.sol`](../script/Deploy.s.sol).
It deploys the same two infra contracts — `ForsVerifier` and
`SimpleAccountFactory` — to the **same deterministic addresses**, but pays for gas
through a Pimlico paymaster instead of native token on the deployer EOA.

## Why the addresses match the Foundry script

Both paths deploy through the canonical CREATE2 deployer `0x4e59…4956C`. The
resulting address is `keccak(0xff ++ 0x4e59… ++ salt ++ keccak(initcode))[12:]`,
which does **not** depend on who sent the transaction. So whether an EOA broadcast
(`Deploy.s.sol`) or a smart account inside a sponsored UserOperation (this script)
triggers the CREATE2, the contracts land at the same addresses — as long as the
**salts, EntryPoint, and compiled bytecode are identical**. This script reads
bytecode straight from the forge `out/` artifacts to guarantee that.

## What this does and does not buy you

- The **one-time infra deploy** (verifier + factory) becomes gasless — that's this script.
- **Per-user account creation** is already gasless via standard 4337: the wallet's
  first UserOp carries the factory `initCode` and Pimlico sponsors it. That path
  does not need this script.

## Prerequisites

- Node ≥ 20.12 (uses the native `.env` loader). Tested on Node 22.
- `forge build` has been run at the repo root (this script reads `out/…`).
- A Pimlico account: API key, a funded **Pimlico balance**, and (recommended) a
  **sponsorship policy**. One balance covers every Pimlico-supported chain.
- Each target chain must have: Pimlico support, EntryPoint v0.7, the SimpleAccount
  factory (Pimlico's, used by the deployer account), and `0x4e59…4956C`. The
  script preflights the last two and fails clearly if missing.

## Usage

```bash
cd deploy-4337
npm install
cp .env.example .env        # then edit .env

# 1) Dry run — prints predicted addresses, sends nothing:
npm run deploy:dry

# 2) Cross-check parity with the Foundry path (must print the same two addresses):
#    from the repo root, against any RPC for a chain that has 0x4e59…:
#    forge script script/Deploy.s.sol --rpc-url <RPC> --sig "run()"

# 3) Deploy for real (gas sponsored by Pimlico):
npm run deploy
```

Re-run per chain by changing `CHAIN_ID` + `RPC_URL` (+ the matching Pimlico
endpoint). The script is **idempotent**: contracts that already exist are skipped,
so re-running a partially-completed chain is safe.

## Config

See [`.env.example`](.env.example). Required: `CHAIN_ID`, `RPC_URL`, `PRIVATE_KEY`,
and `PIMLICO_API_KEY` (or `PIMLICO_URL`). The `PRIVATE_KEY` owner signs UserOps and
needs **no native balance**.

## A note on `npm install` / `.npmrc`

`viem` and `permissionless` versions are pinned to a known-good pair
(`viem@2.52.2`, `permissionless@0.2.57`). permissionless declares an *optional*
peer on `ox@^0.8.0` while viem pulls `ox@0.14.x`; those work together at runtime,
but npm ≥ 7 otherwise aborts a fresh install with `ERESOLVE`. The committed
[`.npmrc`](.npmrc) sets `legacy-peer-deps=true` to relax that optional-peer check,
so a plain `npm install` works. If you ever bump these deps, re-run
`npm run typecheck` and `npm run deploy:dry` to confirm the pair still resolves and
the predicted addresses are unchanged.

## Caveats (the things that silently break determinism)

1. **Byte-identical bytecode.** Deploy from the same `out/` artifacts / same
   [`foundry.toml`](../foundry.toml) compiler settings everywhere. A different
   solc/optimizer config changes the initcode hash and therefore the address. The
   script aborts if an artifact carries unlinked-library placeholders.
2. **Keep `ENTRYPOINT` and the salts identical across chains.** The EntryPoint is a
   factory constructor arg baked into the initcode; overriding it on one chain
   drifts every downstream address. The default salts are self-tested against the
   Solidity constants on each run.
3. **`0x4e59…4956C` must exist on the chain.** A few chains need it pre-seeded via
   Nick's keyless method before anything here will reproduce.

## How it stays in lockstep with `Deploy.s.sol`

Same constants (CREATE2 deployer, EntryPoint v0.7, salt strings), same initcode
construction (factory args = `abi.encode(entryPoint, predictedVerifier)`), and the
same post-deploy assertions (`VERIFIER()`, `ENTRY_POINT()`, address drift). If you
change a salt or the EntryPoint in one file, change it in the other.
