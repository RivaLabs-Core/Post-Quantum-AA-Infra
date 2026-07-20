/**
 * Gasless multi-chain infra deploy via ERC-4337 + Pimlico.
 *
 * This is the account-abstraction sibling of `script/Deploy.s.sol`. It deploys
 * the same three contracts — ForsVerifier, SphincsParamVerifier and SimpleAccountFactory — to the same
 * deterministic addresses, but instead of an EOA `forge` broadcast it has a
 * smart account CALL the canonical CREATE2 deployer (0x4e59…4956C) inside a
 * Pimlico-sponsored UserOperation. No native token is needed on the deployer.
 *
 * Why the addresses still match `Deploy.s.sol`:
 *   The contracts are created by 0x4e59… (not by the smart account), so the
 *   address is keccak(0xff ++ 0x4e59… ++ salt ++ keccak(initcode))[12:] —
 *   independent of who sent the UserOp. Same salts + same EntryPoint + same
 *   compiled bytecode (from `out/`) => identical addresses on every chain.
 *
 * The two scripts MUST stay in lockstep. Run with `--dry-run` first and diff the
 * predicted addresses against `forge script script/Deploy.s.sol` before
 * broadcasting for real.
 */

import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  type Address,
  type Chain,
  type Hex,
  concatHex,
  createPublicClient,
  defineChain,
  encodeAbiParameters,
  getAddress,
  getCreate2Address,
  http,
  keccak256,
  toBytes,
} from 'viem'
import { entryPoint07Address } from 'viem/account-abstraction'
import { privateKeyToAccount } from 'viem/accounts'
import * as allChains from 'viem/chains'
import { createSmartAccountClient } from 'permissionless'
import { toSimpleSmartAccount } from 'permissionless/accounts'
import { createPimlicoClient } from 'permissionless/clients/pimlico'

// ---------------------------------------------------------------------------
// Constants — MUST match script/Deploy.s.sol
// ---------------------------------------------------------------------------
const CREATE2_DEPLOYER: Address = '0x4e59b44847b379578588920cA78FbF26c0B4956C'
const DEFAULT_ENTRYPOINT: Address = '0x0000000071727De22E5E9d8BAf0edAc6f37da032' // EntryPoint v0.7

// keccak256 of the verifier/factory salt strings. Pinned from `cast keccak` so a TS keccak/encoding
// mismatch fails loudly here instead of silently deploying to the wrong addresses.
const EXPECTED_FORS_SALT: Hex = '0x1891551135aa6aebbd0237cb36dd6bfc9cb284420e866248f2a7592bc01895e7'
const EXPECTED_SPHINCS_SALT: Hex = '0x04011f525b81fa97e4cb35c8b52d5b6a8ab40508250c543260581465dd47453d'
const EXPECTED_FACTORY_SALT: Hex = '0x86c6c38223aead0d46ad82406622f80d6eb574af29de7f40040b6e5e96765f49'

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = resolve(SCRIPT_DIR, '..')

// Minimal read ABI for the post-deploy wiring checks (mirrors Deploy.s.sol asserts).
const FACTORY_READ_ABI = [
  { type: 'function', name: 'VERIFIER', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'SPHINCS_PARAM_VERIFIER', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'ENTRY_POINT', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'ACCOUNT_IMPL', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
] as const

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
function env(name: string): string | undefined {
  const v = process.env[name]
  return v === undefined || v === '' ? undefined : v
}

function requireEnv(name: string): string {
  const v = env(name)
  if (v === undefined) throw new Error(`Missing required env var: ${name} (set it in deploy-4337/.env)`)
  return v
}

function asHex(s: string): Hex {
  return (s.startsWith('0x') ? s : `0x${s}`) as Hex
}

/** Read a contract's creation bytecode from a forge `out/` artifact. */
function loadCreationCode(artifactPath: string): Hex {
  let raw: string
  try {
    raw = readFileSync(artifactPath, 'utf8')
  } catch {
    throw new Error(`Artifact not found: ${artifactPath}\nRun \`forge build\` at the repo root first.`)
  }
  const obj = String(JSON.parse(raw).bytecode?.object ?? '')
  if (!obj || obj === '0x') throw new Error(`No creation bytecode in ${artifactPath}`)
  if (obj.includes('__$')) {
    throw new Error(`${artifactPath} contains unlinked library placeholders; CREATE2 of unlinked bytecode is unsupported.`)
  }
  return asHex(obj)
}

/** Resolve a viem Chain by id, falling back to a minimal custom chain over RPC_URL. */
function getChain(id: number, rpcUrl: string): Chain {
  const known = (Object.values(allChains) as Chain[]).find((c) => c && typeof c === 'object' && c.id === id)
  if (known) return known
  return defineChain({
    id,
    name: `chain-${id}`,
    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  })
}

type Call = { to: Address; value: bigint; data: Hex }

async function main() {
  // Load deploy-4337/.env if present (Node >= 20.12 native loader).
  try {
    ;(process as { loadEnvFile?: (p: string) => void }).loadEnvFile?.(resolve(SCRIPT_DIR, '.env'))
  } catch {
    /* no .env file — rely on the ambient environment */
  }

  const dryRun = env('DRY_RUN') === '1' || process.argv.includes('--dry-run')

  // ----- config -----
  const chainId = Number(requireEnv('CHAIN_ID'))
  if (!Number.isInteger(chainId) || chainId <= 0) throw new Error(`Invalid CHAIN_ID: ${process.env.CHAIN_ID}`)
  const rpcUrl = requireEnv('RPC_URL')
  const entryPoint: Address = env('ENTRYPOINT') ? getAddress(asHex(requireEnv('ENTRYPOINT'))) : DEFAULT_ENTRYPOINT

  const forsSalt: Hex = env('FORS_VERIFIER_SALT')
    ? asHex(requireEnv('FORS_VERIFIER_SALT'))
    : keccak256(toBytes('NiceTry.ForsVerifier.v1'))
  const sphincsSalt: Hex = env('SPHINCS_VERIFIER_SALT')
    ? asHex(requireEnv('SPHINCS_VERIFIER_SALT'))
    : keccak256(toBytes('NiceTry.SphincsParamVerifier.v1'))
  const factorySalt: Hex = env('FACTORY_SALT')
    ? asHex(requireEnv('FACTORY_SALT'))
    : keccak256(toBytes('NiceTry.SimpleAccountFactory.v1'))

  // Self-test: the default salts must equal the Solidity constants.
  if (!env('FORS_VERIFIER_SALT') && forsSalt.toLowerCase() !== EXPECTED_FORS_SALT) {
    throw new Error(`FORS salt derivation drift: got ${forsSalt}, expected ${EXPECTED_FORS_SALT}`)
  }
  if (!env('SPHINCS_VERIFIER_SALT') && sphincsSalt.toLowerCase() !== EXPECTED_SPHINCS_SALT) {
    throw new Error(`SPHINCS salt derivation drift: got ${sphincsSalt}, expected ${EXPECTED_SPHINCS_SALT}`)
  }
  if (!env('FACTORY_SALT') && factorySalt.toLowerCase() !== EXPECTED_FACTORY_SALT) {
    throw new Error(`Factory salt derivation drift: got ${factorySalt}, expected ${EXPECTED_FACTORY_SALT}`)
  }

  // ----- build initcode + predicted addresses (mirrors Deploy.s.sol exactly) -----
  const forsInitCode = loadCreationCode(resolve(REPO_ROOT, 'out/ForsVerifier.sol/ForsVerifier.json'))
  const predictedVerifier = getCreate2Address({ from: CREATE2_DEPLOYER, salt: forsSalt, bytecode: forsInitCode })

  const sphincsInitCode = loadCreationCode(resolve(REPO_ROOT, 'out/SphincsParamVerifier.sol/SphincsParamVerifier.json'))
  const predictedSphincsVerifier = getCreate2Address({ from: CREATE2_DEPLOYER, salt: sphincsSalt, bytecode: sphincsInitCode })

  const factoryCreationCode = loadCreationCode(resolve(REPO_ROOT, 'out/SimpleAccountFactory.sol/SimpleAccountFactory.json'))
  const factoryArgs = encodeAbiParameters(
    [{ type: 'address' }, { type: 'address' }, { type: 'address' }],
    [entryPoint, predictedVerifier, predictedSphincsVerifier],
  )
  const factoryInitCode = concatHex([factoryCreationCode, factoryArgs])
  const predictedFactory = getCreate2Address({ from: CREATE2_DEPLOYER, salt: factorySalt, bytecode: factoryInitCode })

  console.log('— Deterministic deploy plan —')
  console.log('chainId            :', chainId)
  console.log('EntryPoint         :', entryPoint)
  console.log('CREATE2 deployer   :', CREATE2_DEPLOYER)
  console.log('ForsVerifier salt  :', forsSalt)
  console.log('SphincsParamVerifier salt:', sphincsSalt)
  console.log('Factory salt       :', factorySalt)
  console.log('Predicted verifier :', predictedVerifier)
  console.log('Predicted sphincs  :', predictedSphincsVerifier)
  console.log('Predicted factory  :', predictedFactory)

  // Dry run is offline by design: it only needs the artifacts, so it works without
  // a live RPC and is the parity check against `forge script script/Deploy.s.sol`.
  if (dryRun) {
    console.log('\nDRY_RUN: predictions only, nothing sent.')
    console.log('Cross-check: `forge script script/Deploy.s.sol` must print these same three addresses.')
    return
  }

  // ----- public client + chain sanity -----
  const chain = getChain(chainId, rpcUrl)
  const publicClient = createPublicClient({ chain, transport: http(rpcUrl) })

  const liveChainId = await publicClient.getChainId()
  if (liveChainId !== chainId) throw new Error(`RPC reports chainId ${liveChainId} but CHAIN_ID=${chainId}`)

  const hasCode = async (address: Address): Promise<boolean> => {
    const code = await publicClient.getCode({ address })
    return !!code && code !== '0x'
  }

  // ----- preflight: required singletons must exist on this chain -----
  if (!(await hasCode(CREATE2_DEPLOYER))) {
    throw new Error(
      `CREATE2 deployer ${CREATE2_DEPLOYER} is not present on chain ${chainId}. ` +
        `Deploy it first (Nick's keyless method) — without it addresses cannot be reproduced.`,
    )
  }
  if (!(await hasCode(entryPoint))) {
    throw new Error(`EntryPoint ${entryPoint} is not present on chain ${chainId}.`)
  }

  // ----- idempotency: skip whatever already exists.
  // The Arachnid proxy reverts if CREATE2 hits an address that already has code,
  // so re-deploying must be filtered out here (same as Deploy.s.sol _deployDeterministic). -----
  const calls: Call[] = []
  if (await hasCode(predictedVerifier)) console.log('• ForsVerifier already deployed — skipping')
  else calls.push({ to: CREATE2_DEPLOYER, value: 0n, data: concatHex([forsSalt, forsInitCode]) })

  if (await hasCode(predictedSphincsVerifier)) console.log('• SphincsParamVerifier already deployed — skipping')
  else calls.push({ to: CREATE2_DEPLOYER, value: 0n, data: concatHex([sphincsSalt, sphincsInitCode]) })

  if (await hasCode(predictedFactory)) console.log('• SimpleAccountFactory already deployed — skipping')
  else calls.push({ to: CREATE2_DEPLOYER, value: 0n, data: concatHex([factorySalt, factoryInitCode]) })

  if (calls.length > 0) {
    const owner = privateKeyToAccount(asHex(requireEnv('PRIVATE_KEY')))
    const pimlicoUrl =
      env('PIMLICO_URL') ?? `https://api.pimlico.io/v2/${chainId}/rpc?apikey=${requireEnv('PIMLICO_API_KEY')}`

    // Deployer smart account. SimpleAccount keeps dependencies minimal; swap in
    // toSafeSmartAccount / toEcdsaKernelSmartAccount here if you prefer that stack.
    const account = await toSimpleSmartAccount({
      client: publicClient,
      owner,
      entryPoint: { address: entryPoint07Address, version: '0.7' },
    })
    console.log('Deployer smart account:', account.address, '(gas sponsored — no balance required)')

    const pimlicoClient = createPimlicoClient({
      transport: http(pimlicoUrl),
      entryPoint: { address: entryPoint07Address, version: '0.7' },
    })

    const policyId = env('PIMLICO_SPONSORSHIP_POLICY_ID')
    const smartAccountClient = createSmartAccountClient({
      account,
      chain,
      bundlerTransport: http(pimlicoUrl),
      paymaster: pimlicoClient,
      paymasterContext: policyId ? { sponsorshipPolicyId: policyId } : undefined,
      userOperation: {
        estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast,
      },
    })

    // Both CREATE2 calls fit in one batched UserOp. Set ONE_PER_OP=1 to send them
    // separately if a chain's bundler rejects the combined op as too large.
    const batches: Call[][] = env('ONE_PER_OP') === '1' ? calls.map((c) => [c]) : [calls]
    for (const [i, batch] of batches.entries()) {
      console.log(`\nSending sponsored UserOperation ${i + 1}/${batches.length} (${batch.length} call(s))…`)
      const userOpHash = await smartAccountClient.sendUserOperation({ calls: batch })
      console.log('  userOpHash:', userOpHash)
      const receipt = await smartAccountClient.waitForUserOperationReceipt({ hash: userOpHash })
      console.log('  mined in tx:', receipt.receipt.transactionHash, '| success:', receipt.success)
      if (!receipt.success) throw new Error('UserOperation reverted on-chain')
    }
  }

  // ----- post-deploy verification (mirrors Deploy.s.sol require()s) -----
  if (!(await hasCode(predictedVerifier))) throw new Error('ForsVerifier missing after deploy')
  if (!(await hasCode(predictedSphincsVerifier))) throw new Error('SphincsParamVerifier missing after deploy')
  if (!(await hasCode(predictedFactory))) throw new Error('SimpleAccountFactory missing after deploy')

  const [wiredVerifier, wiredSphincs, wiredEntryPoint, accountImpl] = await Promise.all([
    publicClient.readContract({ address: predictedFactory, abi: FACTORY_READ_ABI, functionName: 'VERIFIER' }),
    publicClient.readContract({ address: predictedFactory, abi: FACTORY_READ_ABI, functionName: 'SPHINCS_PARAM_VERIFIER' }),
    publicClient.readContract({ address: predictedFactory, abi: FACTORY_READ_ABI, functionName: 'ENTRY_POINT' }),
    publicClient.readContract({ address: predictedFactory, abi: FACTORY_READ_ABI, functionName: 'ACCOUNT_IMPL' }),
  ])

  if (getAddress(wiredVerifier) !== getAddress(predictedVerifier)) {
    throw new Error(`Verifier wiring mismatch: factory.VERIFIER()=${wiredVerifier} != ${predictedVerifier}`)
  }
  if (getAddress(wiredSphincs) !== getAddress(predictedSphincsVerifier)) {
    throw new Error(`SPHINCS verifier wiring mismatch: factory.SPHINCS_PARAM_VERIFIER()=${wiredSphincs} != ${predictedSphincsVerifier}`)
  }
  if (getAddress(wiredEntryPoint) !== getAddress(entryPoint)) {
    throw new Error(`EntryPoint wiring mismatch: factory.ENTRY_POINT()=${wiredEntryPoint} != ${entryPoint}`)
  }

  console.log('\n✓ Deployed & verified on chain', chainId)
  console.log('ForsVerifier         :', predictedVerifier)
  console.log('SphincsParamVerifier :', predictedSphincsVerifier)
  console.log('SimpleAccountFactory :', predictedFactory)
  console.log('Account implementation:', accountImpl)
}

main().catch((e) => {
  console.error('\n✗', e instanceof Error ? e.message : e)
  process.exit(1)
})
