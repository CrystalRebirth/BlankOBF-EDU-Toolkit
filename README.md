# BlankOBF EDU Toolkit

This project started as a personal learning experiment and slowly turned into a full toolkit.

BlankOBF EDU Toolkit is a graphical application that lets you:

- obfuscate Python scripts  
- encrypt files and folders  
- decrypt them again  
- build simple EXE/BAT distributions  

Everything is wrapped in a modern, beginner-friendly GUI.

---

## Why this project exists

I wanted to understand:

- how Python code obfuscation works  
- how real encryption systems are built  
- how tools like PyInstaller package applications  

Instead of just reading about it, I decided to build a practical tool that shows all of this in action.

The goal is **education and legitimate software protection**, not anything shady.

---

## What it can do

### Python Obfuscation

- AST-based transformations  
- rename variables and identifiers  
- encode constants  
- add dummy structures  
- optional experimental XOR layer  
- configurable recursion  
- reproducible results via seed  

Result: your script stays runnable, but much harder to read.

---

### File Encryption

Supports real, modern cryptography only:

- ChaCha20-Poly1305  
- AES-256-GCM  
- AES-SIV  

You can combine layers if you want to experiment.

Features:

- password-based encryption  
- safe overwrite mode with `.bak` backup  
- decrypt-to-temp option  
- works with any file type  

Important:  
Encrypted `.py` files are **not runnable** until decrypted again.  
Obfuscation keeps code runnable, encryption does not.

---

### Folder Bundles

You can encrypt an entire folder into a single container file:

- packs all files  
- keeps structure  
- encrypts everything as one unit  
- restores it exactly on decryption  

The output format is `.bobf` (BlankOBF bundle file).

---

### Simple Compiler Tools

Convenience features for distributing scripts:

- create a small `.bat` launcher  
- build standalone `.exe` files using PyInstaller  
- optional custom icon  

Nothing fancy – just practical helpers.

---

## Running it

Requirements:

- Python 3.10 or newer  

Install dependencies:

```bash
pip install -e .[gui]
