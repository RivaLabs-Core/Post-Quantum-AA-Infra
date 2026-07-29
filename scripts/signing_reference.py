#!/usr/bin/env python3
"""
Dependency-free reference signer for NiceTry WOTS+C and FORS+C.

This file is intentionally boring and explicit. It is meant to be used as a
test oracle and vector generator, not as a production signer. It follows
docs/signing-spec.md and mirrors the current Solidity verifiers' byte
transcripts.

Examples:

    python scripts/signing_reference.py --self-test

    python scripts/signing_reference.py \\
      --scheme fors \\
      --master-secret 0x00000000000000000000000000000000000000000000000000000000000000aa \\
      --index 0 \\
      --digest 0x1111111111111111111111111111111111111111111111111111111111111111
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple


# =============================================================================
# Keccak-256
# =============================================================================

MASK64 = (1 << 64) - 1

KECCAKF_ROUNDS = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
]

KECCAKF_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rotl64(x: int, n: int) -> int:
    n %= 64
    if n == 0:
        return x & MASK64
    return ((x << n) | (x >> (64 - n))) & MASK64


def _keccak_f1600(state: List[int]) -> None:
    """In-place Keccak-f[1600] permutation."""

    for rc in KECCAKF_ROUNDS:
        # Theta
        c = [0] * 5
        for x in range(5):
            c[x] = (
                state[x]
                ^ state[x + 5]
                ^ state[x + 10]
                ^ state[x + 15]
                ^ state[x + 20]
            )
        d = [0] * 5
        for x in range(5):
            d[x] = c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1)
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
                state[x + 5 * y] &= MASK64

        # Rho + Pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                dst_x = y
                dst_y = (2 * x + 3 * y) % 5
                b[dst_x + 5 * dst_y] = _rotl64(
                    state[x + 5 * y],
                    KECCAKF_ROT[x][y],
                )

        # Chi
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = (
                    b[x + 5 * y]
                    ^ ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y])
                ) & MASK64

        # Iota
        state[0] ^= rc
        state[0] &= MASK64


def keccak256(data: bytes) -> bytes:
    """Ethereum Keccak-256, not NIST SHA3-256."""

    rate = 136  # 1088-bit rate for Keccak-256.
    state = [0] * 25

    offset = 0
    while offset + rate <= len(data):
        block = data[offset : offset + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[8 * i : 8 * i + 8], "little")
            state[i] &= MASK64
        _keccak_f1600(state)
        offset += rate

    block = bytearray(rate)
    tail = data[offset:]
    block[: len(tail)] = tail
    block[len(tail)] ^= 0x01  # Keccak pad10*1 domain suffix.
    block[-1] ^= 0x80
    for i in range(rate // 8):
        state[i] ^= int.from_bytes(block[8 * i : 8 * i + 8], "little")
        state[i] &= MASK64
    _keccak_f1600(state)

    out = bytearray()
    while len(out) < 32:
        for i in range(rate // 8):
            out.extend(state[i].to_bytes(8, "little"))
            if len(out) >= 32:
                break
        if len(out) < 32:
            _keccak_f1600(state)
    return bytes(out[:32])


# =============================================================================
# Shared helpers
# =============================================================================


def left16(x: bytes) -> bytes:
    if len(x) < 16:
        raise ValueError("left16 input shorter than 16 bytes")
    return x[:16]


def last20(x: bytes) -> bytes:
    if len(x) < 20:
        raise ValueError("last20 input shorter than 20 bytes")
    return x[-20:]


def pad32(x16: bytes) -> bytes:
    _require_len("x16", x16, 16)
    return x16 + b"\x00" * 16


def u32(x: int) -> bytes:
    return x.to_bytes(4, "big")


def u64(x: int) -> bytes:
    return x.to_bytes(8, "big")


def u128(x: int) -> bytes:
    return x.to_bytes(16, "big")


def u256(x: int) -> bytes:
    return x.to_bytes(32, "big")


def int_be(x: bytes) -> int:
    return int.from_bytes(x, "big")


def hx(x: bytes) -> str:
    return "0x" + x.hex()


def parse_hex(value: str, *, length: Optional[int] = None, left_pad: bool = False) -> bytes:
    s = value[2:] if value.startswith(("0x", "0X")) else value
    if len(s) % 2:
        s = "0" + s
    raw = bytes.fromhex(s)
    if length is not None:
        if left_pad and len(raw) <= length:
            raw = raw.rjust(length, b"\x00")
        if len(raw) != length:
            raise ValueError(f"expected {length} bytes, got {len(raw)}")
    return raw


def _require_len(name: str, value: bytes, expected: int) -> None:
    if len(value) != expected:
        raise ValueError(f"{name} must be {expected} bytes, got {len(value)}")


# =============================================================================
# WOTS+C
# =============================================================================


WOTS_N = 16
WOTS_L = 26
WOTS_W_BITS = 5
WOTS_W = 1 << WOTS_W_BITS
WOTS_W_MAX = WOTS_W - 1
WOTS_W_MASK = WOTS_W - 1
WOTS_TARGET_SUM = (WOTS_L * WOTS_W_MAX) // 2
WOTS_SIG_DATA = WOTS_L * WOTS_N
WOTS_R_LEN = 32
WOTS_CTR_LEN = 4
WOTS_SEED_LEN = WOTS_N
WOTS_R_OFFSET = WOTS_SIG_DATA
WOTS_CTR_OFFSET = WOTS_SIG_DATA + WOTS_R_LEN
WOTS_SEED_OFFSET = WOTS_SIG_DATA + WOTS_R_LEN + WOTS_CTR_LEN
WOTS_BLOB_LEN = WOTS_SIG_DATA + WOTS_R_LEN + WOTS_CTR_LEN + WOTS_SEED_LEN
WOTS_DIGIT_SHIFT_0 = 256 - WOTS_W_BITS


@dataclass(frozen=True)
class WotsKey:
    sk: Tuple[bytes, ...]
    pk_seed: bytes
    pk_root: bytes
    address: bytes
    index: Optional[int] = None
    master_secret: Optional[bytes] = None


def wots_adrs_hash(i: int, s: int) -> bytes:
    return u256((i << 32) | s)


def wots_adrs_pk() -> bytes:
    return u256(1 << 96)


def wots_chain_step(pk_seed: bytes, i: int, s: int, cur: bytes) -> bytes:
    _require_len("pk_seed", pk_seed, 16)
    _require_len("cur", cur, 16)
    return left16(keccak256(pk_seed + wots_adrs_hash(i, s) + cur))


def wots_compress_pk(pk_seed: bytes, pk: Sequence[bytes]) -> bytes:
    _require_len("pk_seed", pk_seed, 16)
    if len(pk) != WOTS_L:
        raise ValueError(f"pk must have {WOTS_L} entries")
    for i, entry in enumerate(pk):
        _require_len(f"pk[{i}]", entry, 16)
    return left16(keccak256(pk_seed + wots_adrs_pk() + b"".join(pk)))


def wots_address(pk_seed: bytes, pk_root: bytes) -> bytes:
    _require_len("pk_seed", pk_seed, 16)
    _require_len("pk_root", pk_root, 16)
    return last20(keccak256(pk_seed + pk_root))


def build_wots_key(
    sk: Sequence[bytes],
    pk_seed: bytes,
    *,
    index: Optional[int] = None,
    master_secret: Optional[bytes] = None,
) -> WotsKey:
    """Build a WOTS key from explicit private chain starts and pkSeed."""

    _require_len("pk_seed", pk_seed, 16)
    if len(sk) != WOTS_L:
        raise ValueError(f"sk must have {WOTS_L} entries")
    for i, entry in enumerate(sk):
        _require_len(f"sk[{i}]", entry, 16)

    pk: List[bytes] = []
    for i in range(WOTS_L):
        cur = sk[i]
        for s in range(WOTS_W_MAX):
            cur = wots_chain_step(pk_seed, i, s, cur)
        pk.append(cur)

    pk_root = wots_compress_pk(pk_seed, pk)
    return WotsKey(
        sk=tuple(sk),
        pk_seed=pk_seed,
        pk_root=pk_root,
        address=wots_address(pk_seed, pk_root),
        index=index,
        master_secret=master_secret,
    )


def derive_wots_key(master_secret: bytes, index: int) -> WotsKey:
    _require_len("master_secret", master_secret, 32)

    sk = tuple(
        left16(
            keccak256(
                b"NiceTry/WOTS/sk/v1"
                + master_secret
                + u64(index)
                + u32(i)
            )
        )
        for i in range(WOTS_L)
    )
    pk_seed = left16(
        keccak256(b"NiceTry/WOTS/pkSeed/v1" + master_secret + u64(index))
    )
    return build_wots_key(
        sk,
        pk_seed,
        index=index,
        master_secret=master_secret,
    )


def wots_digits(h: bytes) -> List[int]:
    _require_len("h", h, 32)
    h_int = int_be(h)
    return [
        (h_int >> (WOTS_DIGIT_SHIFT_0 - i * WOTS_W_BITS)) & WOTS_W_MASK
        for i in range(WOTS_L)
    ]


def wots_find_counter(r: bytes, digest: bytes, max_ctr: int = 1_000_000) -> Tuple[int, bytes, List[int]]:
    _require_len("r", r, 32)
    _require_len("digest", digest, 32)

    for ctr in range(max_ctr):
        h = keccak256(r + u32(ctr) + digest)
        digits = wots_digits(h)
        if sum(digits) == WOTS_TARGET_SUM:
            return ctr, h, digits
    raise RuntimeError("WOTS counter search failed")


def wots_sign(
    key: WotsKey,
    digest: bytes,
    *,
    r: Optional[bytes] = None,
    max_ctr: int = 1_000_000,
) -> Tuple[bytes, Dict[str, object]]:
    _require_len("digest", digest, 32)

    if r is None:
        if key.master_secret is None or key.index is None:
            raise ValueError("r is required when key lacks master_secret/index")
        r = keccak256(
            b"NiceTry/WOTS/R/v1"
            + key.master_secret
            + u64(key.index)
            + digest
        )
    _require_len("r", r, 32)

    ctr, h, digits = wots_find_counter(r, digest, max_ctr=max_ctr)

    sig_chains: List[bytes] = []
    for i, digit in enumerate(digits):
        cur = key.sk[i]
        for s in range(digit):
            cur = wots_chain_step(key.pk_seed, i, s, cur)
        sig_chains.append(cur)

    sig = b"".join(sig_chains) + r + u32(ctr) + key.pk_seed
    _require_len("wots signature", sig, WOTS_BLOB_LEN)

    meta: Dict[str, object] = {
        "ctr": ctr,
        "h": h,
        "digits": digits,
    }
    return sig, meta


def wots_recover_address(signature: bytes, digest: bytes) -> Optional[bytes]:
    _require_len("digest", digest, 32)
    if len(signature) != WOTS_BLOB_LEN:
        return None

    sig_chains = [
        signature[i * WOTS_N : (i + 1) * WOTS_N]
        for i in range(WOTS_L)
    ]
    r = signature[WOTS_R_OFFSET : WOTS_R_OFFSET + WOTS_R_LEN]
    ctr = signature[WOTS_CTR_OFFSET : WOTS_CTR_OFFSET + WOTS_CTR_LEN]
    pk_seed = signature[WOTS_SEED_OFFSET : WOTS_SEED_OFFSET + WOTS_SEED_LEN]

    h = keccak256(r + ctr + digest)
    digits = wots_digits(h)
    if sum(digits) != WOTS_TARGET_SUM:
        return None

    pk: List[bytes] = []
    for i, digit in enumerate(digits):
        cur = sig_chains[i]
        for s in range(digit, WOTS_W_MAX):
            cur = wots_chain_step(pk_seed, i, s, cur)
        pk.append(cur)

    pk_root = wots_compress_pk(pk_seed, pk)
    return wots_address(pk_seed, pk_root)


def make_wots_vector(master_secret: bytes, index: int, digest: bytes) -> Dict[str, object]:
    key = derive_wots_key(master_secret, index)
    sig, meta = wots_sign(key, digest)
    recovered = wots_recover_address(sig, digest)
    if recovered != key.address:
        raise AssertionError("WOTS self-recover mismatch")

    return {
        "scheme": "WOTS+C",
        "params": {
            "n": WOTS_N,
            "l": WOTS_L,
            "wBits": WOTS_W_BITS,
            "targetSum": WOTS_TARGET_SUM,
            "signatureLength": WOTS_BLOB_LEN,
        },
        "index": index,
        "digest": hx(digest),
        "sk": [hx(x) for x in key.sk],
        "pkSeed": hx(key.pk_seed),
        "R": hx(sig[WOTS_R_OFFSET : WOTS_R_OFFSET + WOTS_R_LEN]),
        "ctr": meta["ctr"],
        "h": hx(meta["h"]),  # type: ignore[arg-type]
        "digits": meta["digits"],
        "pkRoot": hx(key.pk_root),
        "address": hx(key.address),
        "signature": hx(sig),
    }


# =============================================================================
# FORS+C
# =============================================================================


FORS_N = 16
FORS_K = 26
FORS_A = 5
FORS_REAL_TREES = FORS_K - 1
FORS_LEAVES = 1 << FORS_A
FORS_R_LEN = 16
FORS_PKSEED_LEN = 16
FORS_TREE_LEN = 16 + FORS_A * 16
FORS_SECTION_LEN = FORS_REAL_TREES * FORS_TREE_LEN
FORS_COUNTER_LEN = 16
FORS_SIG_LEN = FORS_R_LEN + FORS_PKSEED_LEN + FORS_SECTION_LEN + FORS_COUNTER_LEN
FORS_R_OFFSET = 0
FORS_PKSEED_OFFSET = FORS_R_OFFSET + FORS_R_LEN
FORS_SECTION_OFFSET = FORS_PKSEED_OFFSET + FORS_PKSEED_LEN
FORS_COUNTER_OFFSET = FORS_SECTION_OFFSET + FORS_SECTION_LEN
FORS_DOM = (1 << 256) - 3
FORS_TYPE_FORS_TREE = 3
FORS_TYPE_FORS_ROOTS = 4


@dataclass(frozen=True)
class ForsKey:
    sk_seed: bytes
    pk_seed: bytes
    pk_root: bytes
    address: bytes
    index: Optional[int] = None
    master_secret: Optional[bytes] = None


def fors_adrs_leaf(t: int, leaf_idx: int) -> bytes:
    return u256((FORS_TYPE_FORS_TREE << 96) | ((t << FORS_A) | leaf_idx))


def fors_adrs_node(t: int, cp: int, parent_idx: int) -> bytes:
    return u256(
        (FORS_TYPE_FORS_TREE << 96)
        | (cp << 32)
        | ((t << (FORS_A - cp)) | parent_idx)
    )


def fors_adrs_roots() -> bytes:
    return u256(FORS_TYPE_FORS_ROOTS << 96)


def fors_prf(sk_seed: bytes, adrs: bytes) -> bytes:
    _require_len("sk_seed", sk_seed, 16)
    _require_len("adrs", adrs, 32)
    return left16(keccak256(pad32(sk_seed) + adrs))


def fors_f(pk_seed: bytes, adrs: bytes, sk: bytes) -> bytes:
    _require_len("pk_seed", pk_seed, 16)
    _require_len("adrs", adrs, 32)
    _require_len("sk", sk, 16)
    return left16(keccak256(pad32(pk_seed) + adrs + pad32(sk)))


def fors_h(pk_seed: bytes, adrs: bytes, left: bytes, right: bytes) -> bytes:
    _require_len("pk_seed", pk_seed, 16)
    _require_len("adrs", adrs, 32)
    _require_len("left", left, 16)
    _require_len("right", right, 16)
    return left16(keccak256(pad32(pk_seed) + adrs + pad32(left) + pad32(right)))


def fors_hmsg(pk_seed: bytes, r: bytes, digest: bytes, counter: bytes) -> bytes:
    _require_len("pk_seed", pk_seed, 16)
    _require_len("r", r, 16)
    _require_len("digest", digest, 32)
    _require_len("counter", counter, 16)
    return keccak256(
        pad32(pk_seed)
        + pad32(r)
        + digest
        + u256(FORS_DOM)
        + pad32(counter)
    )


def fors_compress_roots(pk_seed: bytes, roots: Sequence[bytes]) -> bytes:
    _require_len("pk_seed", pk_seed, 16)
    if len(roots) != FORS_REAL_TREES:
        raise ValueError(f"roots must have {FORS_REAL_TREES} entries")
    for i, root in enumerate(roots):
        _require_len(f"roots[{i}]", root, 16)
    return left16(
        keccak256(
            pad32(pk_seed)
            + fors_adrs_roots()
            + b"".join(pad32(root) for root in roots)
        )
    )


def fors_address(pk_seed: bytes, pk_root: bytes) -> bytes:
    _require_len("pk_seed", pk_seed, 16)
    _require_len("pk_root", pk_root, 16)
    return last20(keccak256(pad32(pk_seed) + pad32(pk_root)))


def fors_build_tree(sk_seed: bytes, pk_seed: bytes, t: int) -> List[List[bytes]]:
    """Return levels[0..A], with levels[0] leaves and levels[A][0] root."""

    leaves: List[bytes] = []
    for leaf_idx in range(FORS_LEAVES):
        adrs = fors_adrs_leaf(t, leaf_idx)
        sk = fors_prf(sk_seed, adrs)
        leaves.append(fors_f(pk_seed, adrs, sk))

    levels: List[List[bytes]] = [leaves]
    for cp in range(1, FORS_A + 1):
        prev = levels[cp - 1]
        level: List[bytes] = []
        for parent_idx in range(1 << (FORS_A - cp)):
            left = prev[2 * parent_idx]
            right = prev[2 * parent_idx + 1]
            level.append(
                fors_h(
                    pk_seed,
                    fors_adrs_node(t, cp, parent_idx),
                    left,
                    right,
                )
            )
        levels.append(level)

    return levels


def build_fors_key(
    sk_seed: bytes,
    pk_seed: bytes,
    *,
    index: Optional[int] = None,
    master_secret: Optional[bytes] = None,
) -> ForsKey:
    """Build a FORS key from explicit skSeed and pkSeed."""

    _require_len("sk_seed", sk_seed, 16)
    _require_len("pk_seed", pk_seed, 16)
    roots = [
        fors_build_tree(sk_seed, pk_seed, t)[FORS_A][0]
        for t in range(FORS_REAL_TREES)
    ]
    pk_root = fors_compress_roots(pk_seed, roots)
    return ForsKey(
        sk_seed=sk_seed,
        pk_seed=pk_seed,
        pk_root=pk_root,
        address=fors_address(pk_seed, pk_root),
        index=index,
        master_secret=master_secret,
    )


def derive_fors_key(master_secret: bytes, index: int) -> ForsKey:
    _require_len("master_secret", master_secret, 32)

    sk_seed = left16(
        keccak256(b"NiceTry/FORS/skSeed/v1" + master_secret + u64(index))
    )
    pk_seed = left16(
        keccak256(b"NiceTry/FORS/pkSeed/v1" + master_secret + u64(index))
    )
    return build_fors_key(
        sk_seed,
        pk_seed,
        index=index,
        master_secret=master_secret,
    )


def fors_md(dval: bytes) -> List[int]:
    _require_len("dval", dval, 32)
    d = int_be(dval)
    return [(d >> (FORS_A * t)) & (FORS_LEAVES - 1) for t in range(FORS_K)]


def fors_find_counter(pk_seed: bytes, r: bytes, digest: bytes) -> Tuple[bytes, bytes, List[int], int]:
    _require_len("pk_seed", pk_seed, 16)
    _require_len("r", r, 16)
    _require_len("digest", digest, 32)

    counter_int = 0
    while True:
        counter = u128(counter_int)
        dval = fors_hmsg(pk_seed, r, digest, counter)
        md = fors_md(dval)
        if md[FORS_REAL_TREES] == 0:
            return counter, dval, md, counter_int
        counter_int += 1


def fors_sign(
    key: ForsKey,
    digest: bytes,
    *,
    r: Optional[bytes] = None,
) -> Tuple[bytes, Dict[str, object]]:
    _require_len("digest", digest, 32)

    if r is None:
        r = left16(keccak256(b"NiceTry/FORS/R/v1" + key.sk_seed + digest))
    _require_len("r", r, 16)

    counter, dval, md, counter_int = fors_find_counter(key.pk_seed, r, digest)

    openings: List[bytes] = []
    roots: List[bytes] = []
    for t in range(FORS_REAL_TREES):
        leaf_idx = md[t]
        levels = fors_build_tree(key.sk_seed, key.pk_seed, t)
        roots.append(levels[FORS_A][0])

        sk = fors_prf(key.sk_seed, fors_adrs_leaf(t, leaf_idx))
        auth: List[bytes] = []
        idx = leaf_idx
        for cp in range(FORS_A):
            auth.append(levels[cp][idx ^ 1])
            idx >>= 1
        openings.append(sk + b"".join(auth))

    pk_root = fors_compress_roots(key.pk_seed, roots)
    if pk_root != key.pk_root:
        raise AssertionError("FORS pkRoot mismatch during signing")

    sig = r + key.pk_seed + b"".join(openings) + counter
    _require_len("fors signature", sig, FORS_SIG_LEN)

    meta: Dict[str, object] = {
        "counter": counter,
        "counterInt": counter_int,
        "dVal": dval,
        "md": md,
    }
    return sig, meta


def fors_recover_address(signature: bytes, digest: bytes) -> Optional[bytes]:
    _require_len("digest", digest, 32)
    if len(signature) != FORS_SIG_LEN:
        return None

    r = signature[FORS_R_OFFSET : FORS_R_OFFSET + FORS_R_LEN]
    pk_seed = signature[
        FORS_PKSEED_OFFSET : FORS_PKSEED_OFFSET + FORS_PKSEED_LEN
    ]
    counter = signature[
        FORS_COUNTER_OFFSET : FORS_COUNTER_OFFSET + FORS_COUNTER_LEN
    ]

    dval = fors_hmsg(pk_seed, r, digest, counter)
    md = fors_md(dval)
    if md[FORS_REAL_TREES] != 0:
        return None

    roots: List[bytes] = []
    for t in range(FORS_REAL_TREES):
        off = FORS_SECTION_OFFSET + t * FORS_TREE_LEN
        sk = signature[off : off + 16]
        auth = [
            signature[off + 16 + cp * 16 : off + 32 + cp * 16]
            for cp in range(FORS_A)
        ]

        leaf_idx = md[t]
        node = fors_f(pk_seed, fors_adrs_leaf(t, leaf_idx), sk)

        path_idx = leaf_idx
        for cp in range(1, FORS_A + 1):
            sibling = auth[cp - 1]
            parent_idx = path_idx >> 1
            if path_idx & 1:
                left, right = sibling, node
            else:
                left, right = node, sibling
            node = fors_h(
                pk_seed,
                fors_adrs_node(t, cp, parent_idx),
                left,
                right,
            )
            path_idx = parent_idx

        roots.append(node)

    pk_root = fors_compress_roots(pk_seed, roots)
    return fors_address(pk_seed, pk_root)


def make_fors_vector(master_secret: bytes, index: int, digest: bytes) -> Dict[str, object]:
    key = derive_fors_key(master_secret, index)
    sig, meta = fors_sign(key, digest)
    recovered = fors_recover_address(sig, digest)
    if recovered != key.address:
        raise AssertionError("FORS self-recover mismatch")

    return {
        "scheme": "FORS+C",
        "params": {
            "n": FORS_N,
            "k": FORS_K,
            "a": FORS_A,
            "realTrees": FORS_REAL_TREES,
            "signatureLength": FORS_SIG_LEN,
        },
        "index": index,
        "digest": hx(digest),
        "skSeed": hx(key.sk_seed),
        "pkSeed": hx(key.pk_seed),
        "R": hx(sig[FORS_R_OFFSET : FORS_R_OFFSET + FORS_R_LEN]),
        "counter": hx(meta["counter"]),  # type: ignore[arg-type]
        "counterInt": meta["counterInt"],
        "dVal": hx(meta["dVal"]),  # type: ignore[arg-type]
        "md": meta["md"],
        "pkRoot": hx(key.pk_root),
        "address": hx(key.address),
        "signature": hx(sig),
    }


# =============================================================================
# CLI / self-test
# =============================================================================


def self_test() -> None:
    # Ethereum Keccak-256 known vectors.
    assert (
        keccak256(b"").hex()
        == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )
    assert (
        keccak256(b"hello").hex()
        == "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
    )

    master = bytes.fromhex(
        "00000000000000000000000000000000000000000000000000000000000000aa"
    )
    digest = keccak256(b"NiceTry reference self-test")

    wots = make_wots_vector(master, 0, digest)
    fors = make_fors_vector(master, 0, digest)

    assert len(parse_hex(wots["signature"])) == WOTS_BLOB_LEN  # type: ignore[arg-type]
    assert len(parse_hex(fors["signature"])) == FORS_SIG_LEN  # type: ignore[arg-type]
    print("self-test ok")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run internal self-tests")
    parser.add_argument(
        "--scheme",
        choices=("wots", "fors", "both"),
        default="both",
        help="vector scheme to emit",
    )
    parser.add_argument(
        "--master-secret",
        help="32-byte BIP44/ECDSA scalar bytes as hex; shorter values are left-padded",
    )
    parser.add_argument("--index", type=int, default=0, help="signer derivation index")
    parser.add_argument("--digest", help="32-byte digest/userOpHash as hex")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON")

    args = parser.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    if args.master_secret is None or args.digest is None:
        parser.error("--master-secret and --digest are required unless --self-test is used")

    master_secret = parse_hex(args.master_secret, length=32, left_pad=True)
    digest = parse_hex(args.digest, length=32)

    if args.scheme == "wots":
        result: object = make_wots_vector(master_secret, args.index, digest)
    elif args.scheme == "fors":
        result = make_fors_vector(master_secret, args.index, digest)
    else:
        result = {
            "wots": make_wots_vector(master_secret, args.index, digest),
            "fors": make_fors_vector(master_secret, args.index, digest),
        }

    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
