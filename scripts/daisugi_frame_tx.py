#!/usr/bin/env python3
"""Send EIP-8141 frame transactions (type 0x06) on the Daisugi testnet from a plain ECDSA EOA.

Daisugi's public RPC accepts only frame transactions. An EOA sends one with two frames: a VERIFY
frame on its own address, whose protocol default code checks a SECP256K1 entry in the
transaction's `signatures` list and approves execution and payment, then a SENDER frame that makes
the actual call.

Encoding accepted by Daisugi (it differs from the current EIP-8141 text in the fee field and the
signing hash):

    0x06 || rlp([chain_id, nonce, sender, frames, signatures, fees, blob_versioned_hashes])
    frame     = [mode, flags, target, [execution_gas, state_gas], value, data]
    signature = [scheme = 1 (SECP256K1), signer = b"" (tx.sender), msg = b"", v(0/1) || r || s]
    fees      = [max_priority_fee_per_gas, max_fee_per_gas, max_fee_per_blob_gas = 0]
    signing hash = keccak256(0x06 || rlp(tx with every signature's bytes replaced by b""))

Contract creation and code deposit are charged to a frame's state-gas budget.

Commands:
    deploy  Deploy the SphincsVerifier_v5/_v6 + SphincsAccountFactory_v5/_v6 families through the
            canonical CREATE2 deployer, using `forge build` artifacts from out/. Already-deployed
            contracts are skipped; prints a JSON record of what it deployed.
    call    One SENDER-frame call, e.g. funding an account's EntryPoint deposit:
                call --to <EntryPoint> --value-wei 100000000000000000 \\
                     --data $(cast calldata "depositTo(address)" <account>)

The signing key comes from a Foundry keystore (`cast wallet new <dir>`), via `cast wallet sign`.
Testnet only: use a disposable key.

Usage:
    python3 scripts/daisugi_frame_tx.py --keystore <file> [--password-file <file>] deploy [v5|v6 ...]
    python3 scripts/daisugi_frame_tx.py --keystore <file> call --to 0x.. [--data 0x..] [--value-wei N]
Requires Foundry's `cast` on PATH.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

RPC = "https://daisugi.fyi/rpc"
CHAIN_ID = 1337
ENTRY_POINT = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"
CREATE2_DEPLOYER = "0x4e59b44847b379578588920cA78FbF26c0B4956C"
REPO_ROOT = Path(__file__).resolve().parents[1]

MODE_VERIFY, MODE_SENDER = 1, 2
APPROVE_EXECUTION_AND_PAYMENT = 3
SCHEME_SECP256K1 = 1

# (verifier, verifier salt preimage, factory, factory salt preimage) — as in
# script/DeploySphincsWotscAccounts.s.sol.
FAMILIES = {
    "v6": ("SphincsVerifier_v6", "NiceTry.SphincsVerifier_v6.h24-7.7.10-w4-k19a9.v1",
           "SphincsAccountFactory_v6", "NiceTry.SphincsAccountFactory_v6.v1"),
    "v5": ("SphincsVerifier_v5", "NiceTry.SphincsVerifier_v5.h26-8.8.10-w4-k24a10.v1",
           "SphincsAccountFactory_v5", "NiceTry.SphincsAccountFactory_v5.v1"),
}


# --- RLP --------------------------------------------------------------------------------------

def rlp(x) -> bytes:
    if isinstance(x, int):
        x = b"" if x == 0 else x.to_bytes((x.bit_length() + 7) // 8, "big")
    if isinstance(x, (bytes, bytearray)):
        if len(x) == 1 and x[0] < 0x80:
            return bytes(x)
        return _rlp_len(len(x), 0x80) + bytes(x)
    body = b"".join(rlp(i) for i in x)
    return _rlp_len(len(body), 0xC0) + body


def _rlp_len(n: int, offset: int) -> bytes:
    if n < 56:
        return bytes([offset + n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(b)]) + b


# --- plumbing ---------------------------------------------------------------------------------

def h2b(h: str) -> bytes:
    return bytes.fromhex(h[2:] if h.startswith("0x") else h)


def cast(*args: str) -> str:
    r = subprocess.run(["cast", *args], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f"cast {args[0]}: {r.stderr.strip()}")
    return r.stdout.strip()


def rpc(method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC, body, {"content-type": "application/json", "user-agent": "daisugi-frame-tx"})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            out = json.load(resp)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{method}: HTTP {e.code}: {e.read().decode()[:2000]}")
    if "error" in out:
        raise RuntimeError(f"{method}: {out['error']}")
    return out["result"]


class Wallet:
    def __init__(self, keystore: str, password_file: str | None):
        self.auth = ["--keystore", keystore] + (["--password-file", password_file] if password_file else ["--password", ""])
        self.address = cast("wallet", "address", *self.auth)

    def sign_hash(self, digest: str) -> bytes:
        """65-byte v(0/1) || r || s over a raw 32-byte digest (no EIP-191 prefix)."""
        s = h2b(cast("wallet", "sign", "--no-hash", digest, *self.auth))
        v = s[64] - 27 if s[64] >= 27 else s[64]
        return bytes([v]) + s[:64]


def send_frame_tx(wallet: Wallet, target: str, data: str, exec_gas: int, state_gas: int, value: int = 0,
                  verify_gas: int = 60_000, max_fee: int = 2 * 10**9, priority_fee: int = 10**9) -> tuple[str, dict]:
    sender = h2b(wallet.address)
    nonce = int(rpc("eth_getTransactionCount", [wallet.address, "pending"]), 16)
    frames = [
        [MODE_VERIFY, APPROVE_EXECUTION_AND_PAYMENT, sender, [verify_gas, 0], 0, b""],
        [MODE_SENDER, 0, h2b(target), [exec_gas, state_gas], value, h2b(data)],
    ]
    fees = [priority_fee, max_fee, 0]

    def tx(sig: bytes) -> list:
        return [CHAIN_ID, nonce, sender, frames, [[SCHEME_SECP256K1, b"", b"", sig]], fees, []]

    sig = wallet.sign_hash(cast("keccak", "0x06" + rlp(tx(b"")).hex()))
    tx_hash = rpc("eth_sendRawTransaction", ["0x06" + rlp(tx(sig)).hex()])
    print(f"sent {tx_hash} (nonce {nonce})", file=sys.stderr)
    for _ in range(90):
        receipt = rpc("eth_getTransactionReceipt", [tx_hash])
        if receipt:
            return tx_hash, receipt
        time.sleep(2)
    raise RuntimeError(f"no receipt for {tx_hash}")


def frame_statuses(receipt: dict) -> list:
    return [f.get("status") for f in receipt.get("frameReceipts", [])]


# --- commands ---------------------------------------------------------------------------------

def creation_code(name: str) -> str:
    art = REPO_ROOT / "out" / f"{name}.sol" / f"{name}.json"
    return json.loads(art.read_text())["bytecode"]["object"]


def has_code(address: str) -> bool:
    return cast("code", address, "--rpc-url", RPC) not in ("0x", "")


def deploy_one(wallet: Wallet, name: str, salt_preimage: str, init_code: str) -> dict:
    salt = cast("keccak", salt_preimage)
    address = cast("create2", "--deployer", CREATE2_DEPLOYER, "--salt", salt, "--init-code", init_code).split()[0]
    record = {"contract": name, "address": address, "salt": salt, "saltPreimage": salt_preimage,
              "initCodeHash": cast("keccak", init_code)}
    if has_code(address):
        print(f"[{name}] already deployed at {address}", file=sys.stderr)
        return record
    data = salt + init_code[2:]
    estimate = int(cast("estimate", CREATE2_DEPLOYER, data, "--from", wallet.address, "--rpc-url", RPC))
    exec_gas = min(estimate * 3 // 2 + 100_000, 15_000_000)
    state_gas = estimate * 2 + 1_000_000
    print(f"[{name}] -> {address}", file=sys.stderr)
    tx_hash, receipt = send_frame_tx(wallet, CREATE2_DEPLOYER, data, exec_gas, state_gas)
    if not has_code(address):
        raise RuntimeError(f"[{name}] no code at {address} (frames {frame_statuses(receipt)})")
    record.update({"transactionHash": tx_hash, "blockNumber": int(receipt["blockNumber"], 16),
                   "gasUsed": int(receipt["gasUsed"], 16)})
    return record


def cmd_deploy(wallet: Wallet, tags: list[str]) -> None:
    records = []
    for tag in tags or list(FAMILIES):
        vname, vsalt, fname, fsalt = FAMILIES[tag]
        v = deploy_one(wallet, vname, vsalt, creation_code(vname))
        records.append(v)
        factory_init = creation_code(fname) + cast("abi-encode", "f(address,address)", ENTRY_POINT, v["address"])[2:]
        records.append(deploy_one(wallet, fname, fsalt, factory_init))
    print(json.dumps(records, indent=2))


def cmd_call(wallet: Wallet, to: str, data: str, value: int, exec_gas: int, state_gas: int) -> None:
    tx_hash, receipt = send_frame_tx(wallet, to, data, exec_gas, state_gas, value)
    print(json.dumps({"transactionHash": tx_hash, "blockNumber": int(receipt["blockNumber"], 16),
                      "status": receipt["status"], "frames": frame_statuses(receipt)}, indent=2))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keystore", required=True, help="Foundry keystore file of the sending EOA")
    ap.add_argument("--password-file", help="keystore password file (default: empty password)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("deploy")
    d.add_argument("families", nargs="*", help=f"subset of {sorted(FAMILIES)} (default: all)")
    c = sub.add_parser("call")
    c.add_argument("--to", required=True)
    c.add_argument("--data", default="0x")
    c.add_argument("--value-wei", type=int, default=0)
    c.add_argument("--exec-gas", type=int, default=200_000)
    c.add_argument("--state-gas", type=int, default=200_000)
    args = ap.parse_args()
    if args.cmd == "deploy" and not set(args.families) <= set(FAMILIES):
        ap.error(f"unknown family; choose from {sorted(FAMILIES)}")

    wallet = Wallet(args.keystore, args.password_file)
    print(f"sender {wallet.address}", file=sys.stderr)
    if args.cmd == "deploy":
        cmd_deploy(wallet, args.families)
    else:
        cmd_call(wallet, args.to, args.data, args.value_wei, args.exec_gas, args.state_gas)


if __name__ == "__main__":
    main()
