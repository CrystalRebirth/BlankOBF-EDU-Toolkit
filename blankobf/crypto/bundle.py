from __future__ import annotations
import os, json, struct, base64, hashlib
from enum import Enum
from typing import List, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
try:
    # cryptography supports AESSIV in many versions
    from cryptography.hazmat.primitives.ciphers.aead import AESSIV
except Exception:  # pragma: no cover
    AESSIV = None  # type: ignore

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

MAGIC_V1 = b"BOBF1"  # single-layer (legacy)
MAGIC_V2 = b"BOBF2"  # multi-layer (current)

class BundleAlg(str, Enum):
    aesgcm = "aesgcm"
    chacha20 = "chacha20"
    aessiv = "aessiv"  # nonce-misuse resistant (no nonce); requires cryptography support

class KdfKind(str, Enum):
    scrypt = "scrypt"

def _derive_master_key(password: str, salt: bytes, kdf: KdfKind) -> bytes:
    if kdf != KdfKind.scrypt:
        raise ValueError("Unsupported KDF")
    k = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)  # reasonable defaults
    return k.derive(password.encode("utf-8"))

def _hkdf_expand(master_key: bytes, info: bytes, length: int) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(master_key)

def _walk_files(in_dir: str) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    in_dir = os.path.abspath(in_dir)
    for root, _dirs, files in os.walk(in_dir):
        for fn in files:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, in_dir).replace(os.sep, "/")
            items.append((full, rel))
    items.sort(key=lambda x: x[1])
    return items

def _build_plaintext(in_dir: str) -> bytes:
    files = _walk_files(in_dir)
    manifest = {"version": 2, "files": []}
    payload_parts: list[bytes] = []

    for full, rel in files:
        with open(full, "rb") as f:
            data = f.read()
        sha = hashlib.sha256(data).hexdigest()
        manifest["files"].append({"path": rel, "size": len(data), "sha256": sha})
        payload_parts.append(struct.pack(">I", len(rel.encode("utf-8"))))
        payload_parts.append(rel.encode("utf-8"))
        payload_parts.append(struct.pack(">Q", len(data)))
        payload_parts.append(data)

    manifest_bytes = json.dumps(manifest, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return manifest_bytes + b"\n" + b"".join(payload_parts)

def _parse_plaintext(plaintext: bytes) -> tuple[dict, bytes]:
    manifest_bytes, payload = plaintext.split(b"\n", 1)
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    return manifest, payload

def _encrypt_layers(plaintext: bytes, master_key: bytes, layers: list[BundleAlg], kdf: KdfKind) -> tuple[bytes, list[dict]]:
    """Encrypt sequentially. Returns ciphertext and per-layer metadata."""
    layer_meta: list[dict] = []
    data = plaintext

    for idx, alg in enumerate(layers):
        info = b"blankobf.bundle.v2|" + alg.value.encode("ascii") + b"|" + str(idx).encode("ascii")
        if alg == BundleAlg.aesgcm:
            key = _hkdf_expand(master_key, info, 32)
            nonce = os.urandom(12)
            aead = AESGCM(key)
            aad = (MAGIC_V2 + alg.value.encode("ascii") + kdf.value.encode("ascii") + str(idx).encode("ascii"))
            data = aead.encrypt(nonce, data, aad)
            layer_meta.append({"alg": alg.value, "nonce": base64.b64encode(nonce).decode("ascii")})
        elif alg == BundleAlg.chacha20:
            key = _hkdf_expand(master_key, info, 32)
            nonce = os.urandom(12)
            aead = ChaCha20Poly1305(key)
            aad = (MAGIC_V2 + alg.value.encode("ascii") + kdf.value.encode("ascii") + str(idx).encode("ascii"))
            data = aead.encrypt(nonce, data, aad)
            layer_meta.append({"alg": alg.value, "nonce": base64.b64encode(nonce).decode("ascii")})
        elif alg == BundleAlg.aessiv:
            if AESSIV is None:
                raise ValueError("AESSIV not available in your cryptography version.")
            key = _hkdf_expand(master_key, info, 64)  # AESSIV expects 32/48/64
            aead = AESSIV(key)
            # AESSIV API uses a list of associated data items
            aad = [MAGIC_V2, alg.value.encode("ascii"), kdf.value.encode("ascii"), str(idx).encode("ascii")]
            data = aead.encrypt(data, aad)
            layer_meta.append({"alg": alg.value})
        else:
            raise ValueError("Unsupported algorithm")

    return data, layer_meta

def _decrypt_layers(ciphertext: bytes, master_key: bytes, layers_meta: list[dict], kdf: KdfKind) -> bytes:
    data = ciphertext
    # decrypt in reverse order
    for idx_rev, meta in enumerate(reversed(layers_meta)):
        idx = len(layers_meta) - 1 - idx_rev
        alg = BundleAlg(meta["alg"])
        info = b"blankobf.bundle.v2|" + alg.value.encode("ascii") + b"|" + str(idx).encode("ascii")

        if alg == BundleAlg.aesgcm:
            key = _hkdf_expand(master_key, info, 32)
            nonce = base64.b64decode(meta["nonce"])
            aead = AESGCM(key)
            aad = (MAGIC_V2 + alg.value.encode("ascii") + kdf.value.encode("ascii") + str(idx).encode("ascii"))
            data = aead.decrypt(nonce, data, aad)
        elif alg == BundleAlg.chacha20:
            key = _hkdf_expand(master_key, info, 32)
            nonce = base64.b64decode(meta["nonce"])
            aead = ChaCha20Poly1305(key)
            aad = (MAGIC_V2 + alg.value.encode("ascii") + kdf.value.encode("ascii") + str(idx).encode("ascii"))
            data = aead.decrypt(nonce, data, aad)
        elif alg == BundleAlg.aessiv:
            if AESSIV is None:
                raise ValueError("AESSIV not available in your cryptography version.")
            key = _hkdf_expand(master_key, info, 64)
            aead = AESSIV(key)
            aad = [MAGIC_V2, alg.value.encode("ascii"), kdf.value.encode("ascii"), str(idx).encode("ascii")]
            data = aead.decrypt(data, aad)
        else:
            raise ValueError("Unsupported algorithm")

    return data

def bundle_encrypt(
    in_dir: str,
    out_file: str,
    password: str,
    alg: BundleAlg | None = None,
    kdf: KdfKind = KdfKind.scrypt,
    algs: list[BundleAlg] | None = None,
) -> None:
    """Encrypt a folder into a .bobf bundle.

    - Use `algs=[...]` to apply multiple encryption layers in order.
    - If `algs` is None, falls back to the single `alg` (legacy behavior).
    """
    if algs is None:
        if alg is None:
            alg = BundleAlg.chacha20
        algs = [alg]

    if not algs:
        raise ValueError("Choose at least one algorithm")

    plaintext = _build_plaintext(in_dir)
    salt = os.urandom(16)
    master_key = _derive_master_key(password, salt, kdf)

    ciphertext, layers_meta = _encrypt_layers(plaintext, master_key, algs, kdf)

    header = {
        "version": 2,
        "kdf": kdf.value,
        "salt": base64.b64encode(salt).decode("ascii"),
        "layers": layers_meta,  # list of {alg, nonce?}
    }
    header_bytes = json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    blob = MAGIC_V2 + struct.pack(">I", len(header_bytes)) + header_bytes + ciphertext

    with open(out_file, "wb") as f:
        f.write(blob)

def bundle_decrypt(in_file: str, out_dir: str, password: str) -> None:
    with open(in_file, "rb") as f:
        blob = f.read()

    if blob.startswith(MAGIC_V2):
        idx = len(MAGIC_V2)
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

        manifest, payload = _parse_plaintext(plaintext)
        _write_files(out_dir, manifest, payload)
        return

    # ---- Legacy v1 support (single-layer) ----
    if not blob.startswith(MAGIC_V1):
        raise ValueError("Not a BOBF bundle.")

    idx = len(MAGIC_V1)
    header_len = struct.unpack(">I", blob[idx:idx+4])[0]
    idx += 4
    header = json.loads(blob[idx:idx+header_len].decode("utf-8"))
    idx += header_len
    ciphertext = blob[idx:]

    alg = BundleAlg(header["alg"])
    kdf = KdfKind(header["kdf"])
    salt = base64.b64decode(header["salt"])
    nonce = base64.b64decode(header["nonce"])

    master_key = _derive_master_key(password, salt, kdf)

    if alg == BundleAlg.aesgcm:
        aead = AESGCM(master_key)
        aad = (MAGIC_V1 + alg.value.encode("ascii") + kdf.value.encode("ascii"))
        plaintext = aead.decrypt(nonce, ciphertext, aad)
    elif alg == BundleAlg.chacha20:
        aead = ChaCha20Poly1305(master_key)
        aad = (MAGIC_V1 + alg.value.encode("ascii") + kdf.value.encode("ascii"))
        plaintext = aead.decrypt(nonce, ciphertext, aad)
    else:
        raise ValueError("Unsupported legacy algorithm")

    manifest, payload = _parse_plaintext(plaintext)
    _write_files(out_dir, manifest, payload)

def _write_files(out_dir: str, manifest: dict, payload: bytes) -> None:
    os.makedirs(out_dir, exist_ok=True)

    pidx = 0
    for entry in manifest["files"]:
        (plen,) = struct.unpack(">I", payload[pidx:pidx+4]); pidx += 4
        rel = payload[pidx:pidx+plen].decode("utf-8"); pidx += plen
        (dlen,) = struct.unpack(">Q", payload[pidx:pidx+8]); pidx += 8
        data = payload[pidx:pidx+dlen]; pidx += dlen

        sha = hashlib.sha256(data).hexdigest()
        if sha != entry["sha256"]:
            raise ValueError(f"Integrity mismatch for {rel}")

        out_path = os.path.join(out_dir, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(data)
