from __future__ import annotations
import argparse, os, getpass

from .engine import Context, run_pipeline
from .report import write_report
from .transforms import StripDocstrings, RenameIdentifiers, EncodeConstants, GetattrAttributes, InsertDummyComments
from .layers import ZlibB64Split, IPTable, XORBruteforceLab
from .crypto import bundle_encrypt, bundle_decrypt, BundleAlg, KdfKind

def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def _write_text(path: str, s: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(s)

def cmd_obfuscate(args) -> None:
    code = _read_text(args.input)

    ctx = Context(
        seed=args.seed,
        include_imports=args.include_imports,
        recursion=max(1, args.recursion),
    )

    transforms = [
        StripDocstrings(),
        RenameIdentifiers(),
        EncodeConstants(),
        GetattrAttributes(),
        InsertDummyComments(),
    ]

    layers = []
    if not args.no_pack:
        layers = [ZlibB64Split(), IPTable()]
        if args.lab_xor:
            layers.append(XORBruteforceLab())

    out = run_pipeline(code, ctx, transforms, layers)

    out_path = args.output or os.path.join(
        os.path.dirname(args.input),
        "Obfuscated_" + os.path.basename(args.input)
    )
    _write_text(out_path, out)
    print(f"Saved: {out_path}")

    if args.report:
        write_report(args.report, ctx)
        print(f"Report: {args.report}")

def _parse_algs(s: str) -> list[BundleAlg]:
    items = [x.strip().lower() for x in s.split(",") if x.strip()]
    return [BundleAlg(x) for x in items]

def cmd_bundle_encrypt(args) -> None:
    password = args.password or getpass.getpass("Password: ")
    kdf = KdfKind(args.kdf)

    # Multi-layer: --algs chacha20,aesgcm,aessiv
    if args.algs:
        algs = _parse_algs(args.algs)
        bundle_encrypt(args.in_dir, args.out_file, password=password, algs=algs, kdf=kdf)
        print(f"Bundle written (layers={','.join([a.value for a in algs])}): {args.out_file}")
        return

    # Legacy single-layer: --alg chacha20
    alg = BundleAlg(args.alg)
    bundle_encrypt(args.in_dir, args.out_file, password=password, alg=alg, kdf=kdf)
    print(f"Bundle written (alg={alg.value}): {args.out_file}")

def cmd_bundle_decrypt(args) -> None:
    password = args.password or getpass.getpass("Password: ")
    bundle_decrypt(args.in_file, args.out_dir, password=password)
    print(f"Bundle extracted to: {args.out_dir}")

def main():
    p = argparse.ArgumentParser(prog="blankobf", description="BlankOBF EDU Toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)

    o = sub.add_parser("obfuscate", help="Obfuscate Python source (educational)")
    o.add_argument("-i", "--input", required=True)
    o.add_argument("-o", "--output")
    o.add_argument("--seed", type=int, default=None)
    o.add_argument("--report", default=None, help="Write JSON report (explain mode artifact)")
    o.add_argument("--recursion", type=int, default=1)
    o.add_argument("--include-imports", action="store_true")
    o.add_argument("--no-pack", action="store_true", help="Skip runtime layers; AST transforms only (recommended)")
    o.add_argument("--lab-xor", action="store_true", help="Enable XOR brute-force lab layer (slow)")
    o.set_defaults(func=cmd_obfuscate)

    be = sub.add_parser("bundle-encrypt", help="Encrypt a folder into an AEAD bundle (legit encryption)")
    be.add_argument("--in-dir", required=True)
    be.add_argument("--out-file", required=True)
    be.add_argument("--alg", choices=[a.value for a in BundleAlg], default="chacha20",
                    help="Single algorithm (legacy). Prefer --algs for multi-layer.")
    be.add_argument("--algs", default=None,
                    help="Comma-separated list of algorithms to apply in order (e.g. chacha20,aesgcm).")
    be.add_argument("--kdf", choices=[k.value for k in KdfKind], default="scrypt")
    be.add_argument("--password", default=None, help="Provide password via CLI (not recommended); else prompt")
    be.set_defaults(func=cmd_bundle_encrypt)

    bd = sub.add_parser("bundle-decrypt", help="Decrypt an AEAD bundle to a folder")
    bd.add_argument("--in-file", required=True)
    bd.add_argument("--out-dir", required=True)
    bd.add_argument("--password", default=None, help="Provide password via CLI (not recommended); else prompt")
    bd.set_defaults(func=cmd_bundle_decrypt)

    args = p.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
