from __future__ import annotations
import os, json, struct, base64
from typing import Any
from .bundle import BundleAlg, KdfKind, _derive_master_key, _encrypt_layers, _decrypt_layers

MAGIC_FILE = b"BOFF2"  # BlankOBF File Format v2 (layered AEAD)

def read_encrypted_file_header(in_file: str) -> dict[str, Any]:
    with open(in_file, "rb") as f:
        blob = f.read()

    if not blob.startswith(MAGIC_FILE):
        raise ValueError("Not a BlankOBF encrypted file (.boff2 container).")

    idx = len(MAGIC_FILE)
    header_len = struct.unpack(">I", blob[idx:idx+4])[0]
    idx += 4
    header = json.loads(blob[idx:idx+header_len].decode("utf-8"))
    return header

def encrypt_file(
    in_file: str,
    out_file: str,
    password: str,
    algs: list[BundleAlg],
    kdf: KdfKind = KdfKind.scrypt,
) -> None:
    if not algs:
        raise ValueError("Choose at least one algorithm")

    with open(in_file, "rb") as f:
        plaintext = f.read()

    salt = os.urandom(16)
    master_key = _derive_master_key(password, salt, kdf)

    ciphertext, layers_meta = _encrypt_layers(plaintext, master_key, algs, kdf)

    header = {
        "version": 2,
        "kdf": kdf.value,
        "salt": base64.b64encode(salt).decode("ascii"),
        "layers": layers_meta,
        "orig_name": os.path.basename(in_file),
    }
    header_bytes = json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    blob = MAGIC_FILE + struct.pack(">I", len(header_bytes)) + header_bytes + ciphertext

    with open(out_file, "wb") as f:
        f.write(blob)

def decrypt_file(
    in_file: str,
    out_file: str,
    password: str,
) -> None:
    out_dir = os.path.dirname(os.path.abspath(out_file)) or "."
    os.makedirs(out_dir, exist_ok=True)
    _, data = _decrypt_to_bytes(in_file, password)
    with open(out_file, "wb") as f:
        f.write(data)

def decrypt_file_to_dir(
    in_file: str,
    out_dir: str,
    password: str,
) -> str:
    """Decrypt and write into out_dir using the original filename from the header.
    Returns the written file path.
    """
    header, data = _decrypt_to_bytes(in_file, password)
    os.makedirs(out_dir, exist_ok=True)
    name = header.get("orig_name") or "decrypted.bin"
    out_path = os.path.join(out_dir, name)
    with open(out_path, "wb") as f:
        f.write(data)
    return out_path

def _decrypt_to_bytes(in_file: str, password: str):
    with open(in_file, "rb") as f:
        blob = f.read()

    if not blob.startswith(MAGIC_FILE):
        raise ValueError("Not a BlankOBF encrypted file (.boff2 container).")

    idx = len(MAGIC_FILE)
    header_len = struct.unpack(">I", blob[idx:idx+4])[0]
    idx += 4
    header = json.loads(blob[idx:idx+header_len].decode("utf-8"))
    idx += header_len
    ciphertext = blob[idx:]

    kdf = KdfKind(header["kdf"])
    salt = base64.b64decode(header["salt"])
    layers = header["layers"]

    master_key = _derive_master_key(password, salt, kdf)
    plaintext = _decrypt_layers(ciphertext, master_key, layers, kdf)
    return header, plaintext
