#!/usr/bin/env python3
"""Reference signer + test-vector generator for src/Verifiers/SphincsVerifier_v2.sol.

Parameter set: n=16 h=20 d=5 h'=4 a=9 k=19 w=16 (log_w=4), l = 32 + 3 = 35, standard FORS under
standard WOTS+ (no +C grinding on either layer). Signature = 6176 bytes.

Mirrors the verifier exactly: keccak256 tweakable hashes over 32-byte slots (seed ‖ ADRS ‖ payload),
16-byte nodes kept in the top half of each slot, FIPS 205 uncompressed ADRS, the 0xFF..FF H_msg pad,
and LSB-first digit / FORS-index extraction. Secret-key derivation is signer-private (the verifier
never sees it); here it is keccak(skSeed ‖ ADRS) so the output is fully deterministic.

This is a TEST signer: it uses fixed seeds and must never be used to hold real funds.

Usage:
    python scripts/sphincs_v2_reference.py [--message 0x..32bytes]
Requires: pip install pycryptodome
"""

import argparse
import json
from pathlib import Path

from Crypto.Hash import keccak

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_PATH = REPO_ROOT / "test" / "vectors" / "sphincs-v2-reference-0.json"
DEFAULT_MESSAGE = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

N = 16
H = 20
D = 5
HP = H // D  # subtree height h' = 4
K = 19
A = 9
LOG_W = 4
W = 1 << LOG_W
LEN1 = 128 // LOG_W  # 32
LEN2 = 3
L = LEN1 + LEN2  # 35
SIG_LEN = N * (1 + K + K * A) + D * (N * L + N * HP)
assert SIG_LEN == 6176

# ADRS types (FIPS 205 §4.2)
WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS = 0, 1, 2, 3, 4
WOTS_PRF, FORS_PRF = 5, 6  # signer-private, never reach the verifier

# Fixed test seeds (top-aligned 16-byte values).
SK_SEED = bytes.fromhex("11" * 16)
PK_SEED = bytes.fromhex("5eed" * 8)
SK_PRF = bytes.fromhex("22" * 16)


def keccak256(data: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=data).digest()


def slot(node: bytes) -> bytes:
    """16-byte node -> 32-byte word, value in the top half (matches N_MASK)."""
    return node + b"\x00" * 16


def adrs(layer=0, tree=0, typ=0, w1=0, w2=0, w3=0) -> bytes:
    v = (layer << 224) | (tree << 128) | (typ << 96) | (w1 << 64) | (w2 << 32) | w3
    return v.to_bytes(32, "big")


def thash(a: bytes, *nodes: bytes) -> bytes:
    return keccak256(slot(PK_SEED) + a + b"".join(slot(x) for x in nodes))[:N]


def prf(a: bytes) -> bytes:
    return keccak256(slot(SK_SEED) + a)[:N]


# ---------------------------------------------------------------- WOTS+ / XMSS subtree

def chain(x: bytes, start: int, steps: int, layer: int, tree: int, kp: int, ci: int) -> bytes:
    for j in range(start, start + steps):
        x = thash(adrs(layer, tree, WOTS_HASH, kp, ci, j), x)
    return x


def wots_sk(layer: int, tree: int, kp: int, ci: int) -> bytes:
    return prf(adrs(layer, tree, WOTS_PRF, kp, ci, 0))


def wots_pk(layer: int, tree: int, kp: int) -> bytes:
    pks = [chain(wots_sk(layer, tree, kp, i), 0, W - 1, layer, tree, kp, i) for i in range(L)]
    return thash(adrs(layer, tree, WOTS_PK, kp), *pks)


def wots_digits(msg_node: bytes, layer: int, tree: int, kp: int) -> list[int]:
    dw = int.from_bytes(keccak256(slot(PK_SEED) + adrs(layer, tree, WOTS_HASH, kp) + slot(msg_node)), "big")
    msg = [(dw >> (LOG_W * i)) & (W - 1) for i in range(LEN1)]
    csum = sum(W - 1 - x for x in msg)
    return msg + [(csum >> (LOG_W * j)) & (W - 1) for j in range(LEN2)]


def wots_sign(msg_node: bytes, layer: int, tree: int, kp: int) -> list[bytes]:
    digits = wots_digits(msg_node, layer, tree, kp)
    return [chain(wots_sk(layer, tree, kp, i), 0, digits[i], layer, tree, kp, i) for i in range(L)]


def subtree(layer: int, tree: int) -> list[list[bytes]]:
    """All levels of the XMSS subtree: levels[0] = leaves, levels[HP] = [root]."""
    levels = [[wots_pk(layer, tree, kp) for kp in range(1 << HP)]]
    for z in range(1, HP + 1):
        prev = levels[-1]
        levels.append([
            thash(adrs(layer, tree, TREE, 0, z, p), prev[2 * p], prev[2 * p + 1])
            for p in range(len(prev) // 2)
        ])
    return levels


def auth_path(levels: list[list[bytes]], idx: int) -> list[bytes]:
    path = []
    for z in range(len(levels) - 1):
        path.append(levels[z][idx ^ 1])
        idx >>= 1
    return path


# ---------------------------------------------------------------- FORS

def fors_tree(i: int, tree: int, kp: int) -> tuple[list[bytes], list[list[bytes]]]:
    sks = [prf(adrs(0, tree, FORS_PRF, kp, 0, (i << A) | j)) for j in range(1 << A)]
    levels = [[thash(adrs(0, tree, FORS_TREE, kp, 0, (i << A) | j), sks[j]) for j in range(1 << A)]]
    for z in range(1, A + 1):
        prev = levels[-1]
        levels.append([
            thash(adrs(0, tree, FORS_TREE, kp, z, (i << (A - z)) | p), prev[2 * p], prev[2 * p + 1])
            for p in range(len(prev) // 2)
        ])
    return sks, levels


# ---------------------------------------------------------------- keygen / sign

def keygen() -> tuple[bytes, bytes]:
    return PK_SEED, subtree(D - 1, 0)[HP][0]


def sign(message: bytes, pk_root: bytes) -> bytes:
    R = keccak256(slot(SK_PRF) + message)[:N]
    digest = int.from_bytes(keccak256(slot(PK_SEED) + slot(pk_root) + slot(R) + message + b"\xff" * 32), "big")
    ht_idx = (digest >> (K * A)) & ((1 << H) - 1)

    idx_leaf, idx_tree = ht_idx & ((1 << HP) - 1), ht_idx >> HP
    secrets, auths, roots = [], [], []
    for i in range(K):
        t = (digest >> (i * A)) & ((1 << A) - 1)
        sks, levels = fors_tree(i, idx_tree, idx_leaf)
        secrets.append(sks[t])
        auths.extend(auth_path(levels, t))
        roots.append(levels[A][0])
    node = thash(adrs(0, idx_tree, FORS_ROOTS, idx_leaf), *roots)

    ht = []
    idx = ht_idx
    for layer in range(D):
        idx_leaf, idx = idx & ((1 << HP) - 1), idx >> HP
        levels = subtree(layer, idx)
        ht.extend(wots_sign(node, layer, idx, idx_leaf))
        ht.extend(auth_path(levels, idx_leaf))
        node = levels[HP][0]
    assert node == pk_root, "hypertree did not reach pkRoot"

    sig = R + b"".join(secrets) + b"".join(auths) + b"".join(ht)
    assert len(sig) == SIG_LEN
    return sig


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--message", default=DEFAULT_MESSAGE, help="32-byte hex message digest")
    args = ap.parse_args()

    message = bytes.fromhex(args.message.removeprefix("0x"))
    assert len(message) == 32, "message must be 32 bytes"

    pk_seed, pk_root = keygen()
    sig = sign(message, pk_root)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps({
        "params": {"n": N, "h": H, "d": D, "hPrime": HP, "a": A, "k": K, "w": W, "l": L,
                   "signatureLength": SIG_LEN},
        "pkSeed": "0x" + slot(pk_seed).hex(),
        "pkRoot": "0x" + slot(pk_root).hex(),
        "message": "0x" + message.hex(),
        "signature": "0x" + sig.hex(),
    }, indent=2) + "\n")
    print(f"wrote {OUT_PATH.relative_to(REPO_ROOT)} ({SIG_LEN} B signature)")


if __name__ == "__main__":
    main()
