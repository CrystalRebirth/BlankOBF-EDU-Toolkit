# BlankOBF EDU Toolkit

An **educational** open-source toolkit for learning about:

- Python **AST transforms** (renaming identifiers, encoding constants, attribute indirection, etc.)
- How “packing layers” work (clearly labeled as a learning module)
- **Legitimate encryption** for files/asset bundles using modern, audited cryptography (**AEAD**)

## Responsible scope

This project is intended for **learning and defensive/commercial IP protection** patterns (e.g., protecting assets/configs).
It is **not** designed for stealth, persistence, or executing downloaded/external payloads.

By default, the obfuscator runs in **AST-only** mode (`--no-pack`). Packing layers exist for educational exploration.

## Crypto choices (legit, modern)

This project implements **Authenticated Encryption with Associated Data (AEAD)**:

- **AES-256-GCM**
- **ChaCha20-Poly1305** (RFC 8439)

For password-based encryption, we use a strong KDF:

- **scrypt** (salted; parameters configurable)

### Why AEAD?
AEAD gives you **confidentiality + integrity** (tamper detection). “Encrypt without authentication” is a common footgun.

## Install

```bash
pip install -e .
```

## Obfuscate (educational)

AST-only (recommended):
```bash
blankobf obfuscate -i examples/basic.py -o /tmp/basic_obf.py --seed 123 --report /tmp/report.json --no-pack
```

Enable packing layers (educational; slower and easier to reverse by design):
```bash
blankobf obfuscate -i examples/basic.py -o /tmp/basic_packed.py --seed 123 --report /tmp/report.json
```

## Encrypt bundles (recommended “real” protection)

Create an encrypted bundle from a folder:
```bash
blankobf bundle-encrypt --in-dir examples/assets --out-file /tmp/assets.bobf --alg chacha20 --kdf scrypt
```

Decrypt bundle:
```bash
blankobf bundle-decrypt --in-file /tmp/assets.bobf --out-dir /tmp/assets_out
```

## Run tests

```bash
python -m unittest -v
```

## Project layout

- `blankobf/` core package
  - `engine.py` pipeline runner + context
  - `transforms/` AST transforms (teaching-friendly)
  - `layers/` packing layers (educational)
  - `crypto/` legitimate bundle encryption
- `tests/` round-trip tests
- `examples/` small programs + assets

## License

MIT
\n\n## GUI (modern CustomTkinter)\n\nInstall GUI extras:\n\n```bash\npip install -e .[gui]\n```\n\nRun the GUI:\n\n```bash\npython run_app.py\n# or\nblankobf-gui\n```\n

### GUI extras
The GUI uses CustomTkinter. Drag&drop uses `tkinterdnd2` and syntax highlighting uses `pygments`.

```bash
pip install -e .[gui]
python run_app.py
```


### Theme + Icon
The GUI uses a **grey/white** theme (CustomTkinter JSON theme) and sets the window icon from `blankobf/assets/icon.ico` (Windows) and `blankobf/assets/icon.png` (fallback).


## Multi-layer encryption (educational)
You can apply **more than one** authenticated encryption layer to a bundle.
Example (apply in order):

```bash
blankobf bundle-encrypt --in-dir examples/assets --out-file assets.bobf --algs chacha20,aesgcm
```

Additional option:
- `aessiv` (AES-SIV) is nonce-misuse resistant (if your `cryptography` build includes it).
