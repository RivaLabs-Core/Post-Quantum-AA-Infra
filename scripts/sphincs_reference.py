#!/usr/bin/env python3
"""Generate the SPHINCS- reference test vector.

This drives the upstream SPHINCS- signer (the verifier in src/Verifiers/SphincsVerifier.sol is
vendored verbatim from the SPHINCS- reference implementation,
https://github.com/nconsigny/SPHINCS-) to mint a real (pkSeed, pkRoot, signature) tuple for a fixed
message, then writes it to test/vectors/sphincs-reference-0.json. test/SphincsVerifier.t.sol picks the
file up automatically and asserts verify(...) == true (plus tamper / wrong-message negatives).

The signer is EXTERNAL research code and is intentionally NOT committed here. Point this script at a
checkout of the SPHINCS- reference repo via --upstream (or $SPHINCS_UPSTREAM), and pass the signer's
parameter-set token via --variant (or $SPHINCS_VARIANT). Two signer backends, both emitting identical
ABI output `(bytes32,bytes32,bytes)`:

  * Rust (fast, ~seconds after a one-time build):
        (cd <upstream>/signer-wasm && cargo build --release --bin signer-<variant>)
    then this script auto-uses <upstream>/signer-wasm/target/release/signer-<variant>
  * Python (no build, slow — minutes of FORS/R grinding):
        <upstream>/script/signer.py    (requires: pip install eth-account eth-abi pycryptodome)

Usage:
    python3 scripts/sphincs_reference.py --upstream DIR --variant TOKEN [--message 0x..32bytes] [--python]
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from eth_abi import decode as abi_decode  # pip install eth-abi

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_PATH = REPO_ROOT / "test" / "vectors" / "sphincs-reference-0.json"
DEFAULT_MESSAGE = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
SIG_LEN = 3688

# SPHINCS- parameters (informational; the verifier hardcodes them).
PARAMS = {"n": 16, "h": 22, "d": 2, "a": 19, "k": 7, "w": 8, "l": 43, "target_sum": 208}


def _signer_argv(upstream: Path, variant: str, force_python: bool) -> list[str]:
    rust = upstream / "signer-wasm" / "target" / "release" / f"signer-{variant}"
    rust_exe = rust.with_suffix(".exe") if os.name == "nt" else rust
    if not force_python and (rust.exists() or rust_exe.exists()):
        return [str(rust_exe if rust_exe.exists() else rust)]
    py = upstream / "script" / "signer.py"
    if not py.exists():
        sys.exit(f"No signer found under {upstream} (looked for the Rust bin and script/signer.py)")
    return [sys.executable, str(py)]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--upstream", default=os.environ.get("SPHINCS_UPSTREAM"),
                    help="path to a SPHINCS- reference checkout (or set $SPHINCS_UPSTREAM)")
    ap.add_argument("--variant", default=os.environ.get("SPHINCS_VARIANT"),
                    help="the upstream signer's parameter-set token (passed through verbatim)")
    ap.add_argument("--message", default=DEFAULT_MESSAGE, help="32-byte hex message digest")
    ap.add_argument("--python", action="store_true", help="force the slow pure-Python signer")
    args = ap.parse_args()

    if not args.upstream:
        sys.exit("Set --upstream <dir> or $SPHINCS_UPSTREAM to a SPHINCS- reference checkout.")
    if not args.variant:
        sys.exit("Set --variant <token> or $SPHINCS_VARIANT to the upstream signer's parameter-set token.")
    upstream = Path(args.upstream).resolve()

    argv = _signer_argv(upstream, args.variant, args.python) + [args.variant, args.message]
    print(f"running: {' '.join(argv)}  (cwd={upstream})", file=sys.stderr)
    # cwd=upstream so script/signer.py resolves its relative imports/fixtures.
    out = subprocess.run(argv, cwd=upstream, capture_output=True, text=True, check=True).stdout.strip()

    raw = bytes.fromhex(out[2:] if out.startswith("0x") else out)
    pk_seed, pk_root, sig = abi_decode(["bytes32", "bytes32", "bytes"], raw)
    if len(sig) != SIG_LEN:
        sys.exit(f"unexpected SPHINCS- signature length {len(sig)} (expected {SIG_LEN})")

    vector = {
        "scheme": "SPHINCS-",
        "params": PARAMS,
        "message": args.message,
        "pkSeed": "0x" + pk_seed.hex(),
        "pkRoot": "0x" + pk_root.hex(),
        "signature": "0x" + sig.hex(),
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(vector, indent=2) + "\n")
    print(f"wrote {OUT_PATH.relative_to(REPO_ROOT)}  (sig {len(sig)} B)", file=sys.stderr)


if __name__ == "__main__":
    main()
