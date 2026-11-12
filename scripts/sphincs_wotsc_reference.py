#!/usr/bin/env python3
"""Reference signer + test-vector generator for SphincsVerifier_v5 and SphincsVerifier_v6.

Both sets are SPHINCS- with standard FORS under WOTS+C, n=16, d=3, w=4 (len = 64, no checksum
chains, digit sum fixed at TARGET_SUM = 120 by a grinding counter):

    v5: h=26, subtree heights 8, 8, 10 from the bottom (10 on top), a=10 k=24, 7740-byte signature
    v6: h=24, subtree heights 7, 7, 10 from the bottom (10 on top), a=9  k=19, 6524-byte signature

Mirrors the verifiers exactly (see docs/signing-spec.md, "SPHINCS- WOTS+C (v5 / v6)"):
    T(seed, ADRS, v1..vm) = keccak256(seed16 ‖ ADRS16 ‖ v1_16 ‖ ... ‖ vm_16)[:16]
    ADRS16 = layer(1) ‖ tree(8) ‖ type(1) ‖ kp(2) ‖ word2(1) ‖ word3(3)
    digest = keccak256(0xff*32 ‖ R16 ‖ seed16 ‖ root16 ‖ M32); FORS index i = (digest >> a*i) & (2^a-1)
    htIdx  = v5: keccak256(digest) & (2^26 - 1)      v6: (digest >> 171) & (2^24 - 1)
    WOTS+C digest = keccak256(seed16 ‖ WOTS_HASH ADRS16 ‖ node16 ‖ count4); digits = top 128 bits,
             base 4, MSB-first; valid iff the digit sum is 120.
Secret values (PRF outputs, R) are signer-private; here they are keccak(skSeed ‖ ADRS) and
keccak(skSeed ‖ M)[:16] so the output is fully deterministic.

This is a TEST signer: it uses fixed seeds and must never be used to hold real funds.

Usage:
    python3 scripts/sphincs_wotsc_reference.py v6 [--message 0x..32bytes] [--out vector.json]
    python3 scripts/sphincs_wotsc_reference.py v5 --check test/vectors/sphincs-v5-bench-0.json

Uses pycryptodome's keccak when installed; otherwise the pure-Python keccak in
scripts/signing_reference.py (no dependencies, a few minutes per signature).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import List, Sequence, Tuple

try:
    from Crypto.Hash import keccak as _keccak

    def keccak256(data: bytes) -> bytes:
        return _keccak.new(digest_bits=256, data=data).digest()

except ImportError:
    _spec = importlib.util.spec_from_file_location(
        "signing_reference", Path(__file__).resolve().parent / "signing_reference.py"
    )
    _ref = importlib.util.module_from_spec(_spec)
    sys.modules["signing_reference"] = _ref
    _spec.loader.exec_module(_ref)
    keccak256 = _ref.keccak256

DEFAULT_MESSAGE = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

N = 16
W = 4
LEN = 64
TARGET_SUM = 120

# ADRS types
WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS = 0, 1, 2, 3, 4

PARAMS = {
    "v5": {"heights": [8, 8, 10], "k": 24, "a": 10, "sig_len": 7740, "ht_idx": "keccak256(digest) & (2^26-1)"},
    "v6": {"heights": [7, 7, 10], "k": 19, "a": 9, "sig_len": 6524, "ht_idx": "digest bits [171, 195)"},
}


class Signer:
    def __init__(self, name: str) -> None:
        p = PARAMS[name]
        self.name = name
        self.heights: List[int] = p["heights"]  # bottom-up
        self.k: int = p["k"]
        self.a: int = p["a"]
        self.sig_len: int = p["sig_len"]
        self.d = len(self.heights)
        self.h = sum(self.heights)
        assert self.sig_len == N * (1 + self.k * (1 + self.a)) + self.d * (N * LEN + 4) + N * self.h
        # Fixed test seeds.
        self.sk_seed = keccak256(f"{name}-sk-seed".encode())[:N]
        self.pk_seed = keccak256(f"{name}-pk-seed".encode())[:N]
        self._top = None

    # --- primitives -------------------------------------------------------------------------

    @staticmethod
    def adrs(layer=0, tree=0, typ=0, kp=0, w2=0, w3=0) -> bytes:
        assert layer < 1 << 8 and tree < 1 << 64 and kp < 1 << 16 and w2 < 1 << 8 and w3 < 1 << 24
        return (
            bytes([layer]) + tree.to_bytes(8, "big") + bytes([typ]) + kp.to_bytes(2, "big")
            + bytes([w2]) + w3.to_bytes(3, "big")
        )

    def thash(self, a: bytes, *vals: bytes) -> bytes:
        return keccak256(self.pk_seed + a + b"".join(vals))[:N]

    def prf(self, a: bytes) -> bytes:
        return keccak256(self.sk_seed + a)[:N]

    # --- WOTS+C -----------------------------------------------------------------------------

    def chain(self, layer: int, tree: int, kp: int, ci: int, upto: int) -> List[bytes]:
        """Chain values 0..upto, starting from the chain's secret."""
        v = self.prf(self.adrs(layer, tree, WOTS_HASH, kp, ci, 0))
        out = [v]
        for ha in range(upto):
            v = self.thash(self.adrs(layer, tree, WOTS_HASH, kp, ci, ha), v)
            out.append(v)
        return out

    def wots_pk(self, layer: int, tree: int, kp: int) -> bytes:
        ends = [self.chain(layer, tree, kp, i, W - 1)[W - 1] for i in range(LEN)]
        return self.thash(self.adrs(layer, tree, WOTS_PK, kp), *ends)

    def wots_sign(self, layer: int, tree: int, kp: int, node: bytes) -> Tuple[List[bytes], int]:
        a = self.adrs(layer, tree, WOTS_HASH, kp)
        count = 0
        while True:
            d = int.from_bytes(keccak256(self.pk_seed + a + node + count.to_bytes(4, "big")), "big")
            digits = [(d >> (254 - 2 * j)) & 3 for j in range(LEN)]
            if sum(digits) == TARGET_SUM:
                break
            count += 1
        return [self.chain(layer, tree, kp, i, digits[i])[digits[i]] for i in range(LEN)], count

    # --- Merkle -----------------------------------------------------------------------------

    def subtree(self, layer: int, tree: int) -> List[List[bytes]]:
        hp = self.heights[layer]
        level = [self.wots_pk(layer, tree, leaf) for leaf in range(1 << hp)]
        levels = [level]
        for z in range(1, hp + 1):
            level = [
                self.thash(self.adrs(layer, tree, TREE, 0, z, y), level[2 * y], level[2 * y + 1])
                for y in range(len(level) // 2)
            ]
            levels.append(level)
        return levels

    @staticmethod
    def auth_path(levels: Sequence[Sequence[bytes]], idx: int) -> List[bytes]:
        out = []
        for z in range(len(levels) - 1):
            out.append(levels[z][idx ^ 1])
            idx >>= 1
        return out

    def top(self) -> List[List[bytes]]:
        """The top subtree is fixed per key; built once and cached."""
        if self._top is None:
            self._top = self.subtree(self.d - 1, 0)
        return self._top

    def pk_root(self) -> bytes:
        return self.top()[self.heights[-1]][0]

    # --- signing ----------------------------------------------------------------------------

    def ht_idx(self, digest: bytes) -> int:
        if self.name == "v5":
            return int.from_bytes(keccak256(digest), "big") & ((1 << self.h) - 1)
        return (int.from_bytes(digest, "big") >> (self.k * self.a)) & ((1 << self.h) - 1)

    def sign(self, message: bytes) -> Tuple[bytes, int]:
        root = self.pk_root()
        r = keccak256(self.sk_seed + message)[:N]
        digest_b = keccak256(b"\xff" * 32 + r + self.pk_seed + root + message)
        digest = int.from_bytes(digest_b, "big")
        ht = self.ht_idx(digest_b)

        # FORS under the bottom layer's (tree, leaf).
        leaf0, tree0 = ht & ((1 << self.heights[0]) - 1), ht >> self.heights[0]
        sig = r
        roots = []
        a = self.a
        for i in range(self.k):
            idx = (digest >> (a * i)) & ((1 << a) - 1)

            def fors_adrs(z: int, j: int) -> bytes:
                return self.adrs(0, tree0, FORS_TREE, leaf0, z, j)

            level = [self.thash(fors_adrs(0, (i << a) | j), self.prf(fors_adrs(0, (i << a) | j))) for j in range(1 << a)]
            sig += self.prf(fors_adrs(0, (i << a) | idx))
            x = idx
            for z in range(1, a + 1):
                sig += level[x ^ 1]
                x >>= 1
                level = [
                    self.thash(fors_adrs(z, (i << (a - z)) | y), level[2 * y], level[2 * y + 1])
                    for y in range(len(level) // 2)
                ]
            roots.append(level[0])
        node = self.thash(self.adrs(0, tree0, FORS_ROOTS, leaf0), *roots)

        # Hypertree, bottom layer first.
        tree, tries = ht, 0
        for layer in range(self.d):
            leaf, tree = tree & ((1 << self.heights[layer]) - 1), tree >> self.heights[layer]
            levels = self.top() if layer == self.d - 1 else self.subtree(layer, tree)
            chains, count = self.wots_sign(layer, tree, leaf, node)
            tries += count + 1
            sig += b"".join(chains) + count.to_bytes(4, "big") + b"".join(self.auth_path(levels, leaf))
            node = levels[self.heights[layer]][0]

        assert node == root and len(sig) == self.sig_len, len(sig)
        return sig, tries

    def vector(self, message: bytes) -> dict:
        sig, tries = self.sign(message)
        print(f"{self.name}: grinding tries over {self.d} layers: {tries}", file=sys.stderr)
        pad = lambda b: "0x" + b.hex() + "00" * 16  # noqa: E731 — top-128-bit-aligned bytes32
        return {
            "params": {
                "n": N, "h": self.h, "d": self.d, "hPrime": self.heights, "a": self.a, "k": self.k, "w": W,
                "l": LEN, "targetSum": TARGET_SUM, "tweakableHash": "keccak256(seed16 || adrs16 || payload16*)",
                "htIdx": PARAMS[self.name]["ht_idx"], "signatureLength": self.sig_len,
            },
            "pkSeed": pad(self.pk_seed),
            "pkRoot": pad(self.pk_root()),
            "message": "0x" + message.hex(),
            "signature": "0x" + sig.hex(),
        }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("params", choices=sorted(PARAMS))
    ap.add_argument("--message", default=None, help="32-byte hex message (default: the one in --check, else 0xdeadbeef..)")
    ap.add_argument("--out", type=Path, help="write the vector JSON here (default: stdout)")
    ap.add_argument("--check", type=Path, help="regenerate this vector and fail unless it matches byte for byte")
    args = ap.parse_args()

    expected = None
    message_hex = args.message
    if args.check:
        expected = args.check.read_text()
        message_hex = message_hex or json.loads(expected)["message"]
    message_hex = message_hex or DEFAULT_MESSAGE
    message = bytes.fromhex(message_hex[2:] if message_hex.startswith("0x") else message_hex)
    if len(message) != 32:
        sys.exit("message must be 32 bytes")

    text = json.dumps(Signer(args.params).vector(message), indent=2)
    if expected is not None:
        if text != expected:
            sys.exit(f"MISMATCH: regenerated vector differs from {args.check}")
        print(f"OK: {args.check} reproduced byte for byte", file=sys.stderr)
    if args.out:
        args.out.write_text(text)
    elif expected is None:
        print(text)


if __name__ == "__main__":
    main()
