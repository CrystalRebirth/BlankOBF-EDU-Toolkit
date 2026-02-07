from __future__ import annotations

import os
import sys
import threading
import tempfile
import shutil
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

from .engine import Context, run_pipeline
from .report import write_report
from .transforms import (
    StripDocstrings,
    RenameIdentifiers,
    EncodeConstants,
    GetattrAttributes,
    InsertDummyComments,
)
from .layers import ZlibB64Split, IPTable, XORBruteforceLab
from .crypto import (
    bundle_encrypt, bundle_decrypt,
    encrypt_file, decrypt_file, decrypt_file_to_dir,
    BundleAlg, KdfKind,
)

APP_TITLE = "BlankOBF EDU Toolkit"
DEFAULT_GEOMETRY = "1250x820"

# ---------------- Theme (code-based, stable) ----------------
PALETTE = {
    "app_bg": "#F5F6F7",
    "card_bg": "#FFFFFF",
    "border": "#D0D4D9",
    "text": "#111316",
    "muted": "#6B7078",
    "btn": "#EDEFF2",
    "btn_hover": "#E2E5E9",
}

def apply_theme(root: tk.Tk) -> None:
    ctk.set_appearance_mode("Light")
    ctk.set_default_color_theme("blue")
    root.configure(bg=PALETTE["app_bg"])

def style_frame(w: ctk.CTkFrame) -> None:
    w.configure(fg_color=PALETTE["card_bg"])

def style_label(w: ctk.CTkLabel, *, muted: bool = False) -> None:
    w.configure(text_color=PALETTE["muted"] if muted else PALETTE["text"])

def style_button(w: ctk.CTkButton, *, ghost: bool = False) -> None:
    if ghost:
        w.configure(
            fg_color="transparent",
            border_width=1,
            border_color=PALETTE["border"],
            text_color=PALETTE["text"],
            hover_color=PALETTE["btn_hover"],
        )
    else:
        w.configure(
            fg_color=PALETTE["btn"],
            hover_color=PALETTE["btn_hover"],
            border_width=1,
            border_color=PALETTE["border"],
            text_color=PALETTE["text"],
        )

def style_entry(w: ctk.CTkEntry) -> None:
    w.configure(
        fg_color=PALETTE["card_bg"],
        border_color=PALETTE["border"],
        text_color=PALETTE["text"],
    )

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        apply_theme(self)
        self.title(APP_TITLE)
        self._set_window_icon()
        self.geometry(DEFAULT_GEOMETRY)
        self.minsize(1050, 680)

        self._stop_event = threading.Event()

        self._build_ui()

    # ---------------- Core helpers ----------------
    def _set_window_icon(self) -> None:
        base = os.path.join(os.path.dirname(__file__), "assets")
        ico = os.path.join(base, "icon.ico")
        png = os.path.join(base, "icon.png")

        try:
            if os.name == "nt" and os.path.exists(ico):
                self.iconbitmap(ico)
        except Exception:
            pass
        try:
            if os.path.exists(png):
                img = tk.PhotoImage(file=png)
                self.iconphoto(True, img)
                self._icon_ref = img
        except Exception:
            pass

    def _log(self, s: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", s.rstrip() + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _cancel(self) -> None:
        self._stop_event.set()

    # ---------------- UI ----------------
    def _build_ui(self) -> None:
        outer = ctk.CTkFrame(self, corner_radius=14)
        outer.pack(fill="both", expand=True, padx=18, pady=18)
        style_frame(outer)

        header = ctk.CTkLabel(outer, text="BlankOBF EDU Toolkit", font=("Segoe UI", 20, "bold"))
        header.pack(pady=(16, 2), padx=18, anchor="w")
        style_label(header)

        sub = ctk.CTkLabel(
            outer,
            text="Obfuscation + file encryption + folder bundles + compiler (PyInstaller).",
            font=("Segoe UI", 12),
        )
        sub.pack(pady=(0, 12), padx=18, anchor="w")
        style_label(sub, muted=True)

        body = ctk.CTkFrame(outer, corner_radius=12)
        body.pack(fill="both", expand=True, padx=18, pady=(0, 12))
        style_frame(body)
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(0, weight=1)
        body.grid_rowconfigure(1, weight=0)

        self.tabs = ctk.CTkTabview(body, corner_radius=12)
        self.tabs.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)

        t_obf = self.tabs.add("Obfuscate")
        t_fenc = self.tabs.add("Encrypt file")
        t_fdec = self.tabs.add("Decrypt file")
        t_benc = self.tabs.add("Encrypt folder (bundle)")
        t_bdec = self.tabs.add("Decrypt bundle")
        t_comp = self.tabs.add("Compiler")
        t_about = self.tabs.add("About")

        self._build_obfuscate_tab(t_obf)
        self._build_file_encrypt_tab(t_fenc)
        self._build_file_decrypt_tab(t_fdec)
        self._build_bundle_encrypt_tab(t_benc)
        self._build_bundle_decrypt_tab(t_bdec)
        self._build_compiler_tab(t_comp)
        self._build_about_tab(t_about)

        logbox = ctk.CTkFrame(body, corner_radius=12)
        logbox.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 12))
        style_frame(logbox)
        logbox.grid_columnconfigure(0, weight=1)

        ll = ctk.CTkLabel(logbox, text="Output / Log", font=("Segoe UI", 12, "bold"))
        ll.grid(row=0, column=0, padx=12, pady=(10, 6), sticky="w")
        style_label(ll)

        self.log = ctk.CTkTextbox(logbox, height=140)
        self.log.grid(row=1, column=0, padx=12, pady=(0, 12), sticky="ew")
        self.log.configure(state="disabled")

    # ---------------- Obfuscate tab ----------------
    def _build_obfuscate_tab(self, parent):
        parent.grid_columnconfigure(1, weight=1)

        self.obf_in = tk.StringVar()
        self.obf_out = tk.StringVar()
        self.obf_report = tk.StringVar()
        self.obf_seed = tk.StringVar()
        self.obf_rec = tk.StringVar(value="1")
        self.obf_ast_only = tk.BooleanVar(value=True)
        self.obf_lab_xor = tk.BooleanVar(value=False)

        row = 0
        ctk.CTkLabel(parent, text="Input .py").grid(row=row, column=0, padx=12, pady=10, sticky="w")
        e1 = ctk.CTkEntry(parent, textvariable=self.obf_in)
        e1.grid(row=row, column=1, padx=12, pady=10, sticky="ew"); style_entry(e1)
        b1 = ctk.CTkButton(parent, text="Browse", width=120, command=self._pick_obf_in)
        b1.grid(row=row, column=2, padx=12, pady=10); style_button(b1)

        row += 1
        ctk.CTkLabel(parent, text="Output .py").grid(row=row, column=0, padx=12, pady=10, sticky="w")
        e2 = ctk.CTkEntry(parent, textvariable=self.obf_out)
        e2.grid(row=row, column=1, padx=12, pady=10, sticky="ew"); style_entry(e2)
        b2 = ctk.CTkButton(parent, text="Browse", width=120, command=self._pick_obf_out)
        b2.grid(row=row, column=2, padx=12, pady=10); style_button(b2)

        row += 1
        ctk.CTkLabel(parent, text="Report .json (optional)").grid(row=row, column=0, padx=12, pady=10, sticky="w")
        e3 = ctk.CTkEntry(parent, textvariable=self.obf_report)
        e3.grid(row=row, column=1, padx=12, pady=10, sticky="ew"); style_entry(e3)
        b3 = ctk.CTkButton(parent, text="Browse", width=120, command=self._pick_obf_report)
        b3.grid(row=row, column=2, padx=12, pady=10); style_button(b3)

        row += 1
        opts = ctk.CTkFrame(parent, corner_radius=12)
        opts.grid(row=row, column=0, columnspan=3, padx=12, pady=(6, 10), sticky="ew")
        style_frame(opts)

        ctk.CTkLabel(opts, text="Seed").grid(row=0, column=0, padx=(12,6), pady=12, sticky="w")
        seed = ctk.CTkEntry(opts, textvariable=self.obf_seed, width=140)
        seed.grid(row=0, column=1, padx=(0,12), pady=12, sticky="w"); style_entry(seed)

        ctk.CTkLabel(opts, text="Recursion").grid(row=0, column=2, padx=(12,6), pady=12, sticky="w")
        rec = ctk.CTkEntry(opts, textvariable=self.obf_rec, width=90)
        rec.grid(row=0, column=3, padx=(0,12), pady=12, sticky="w"); style_entry(rec)

        self.cb_obf_ast = ctk.CTkCheckBox(opts, text="AST-only (recommended)", variable=self.obf_ast_only, command=self._sync_obf_mode)
        self.cb_obf_ast.grid(row=0, column=4, padx=(12,6), pady=12, sticky="w")
        self.cb_obf_xor = ctk.CTkCheckBox(opts, text="XOR lab layer (slow)", variable=self.obf_lab_xor, command=self._sync_obf_mode)
        self.cb_obf_xor.grid(row=0, column=5, padx=(12,6), pady=12, sticky="w")

        row += 1
        bar = ctk.CTkFrame(parent, corner_radius=12)
        bar.grid(row=row, column=0, columnspan=3, padx=12, pady=10, sticky="ew")
        style_frame(bar)
        bar.grid_columnconfigure(2, weight=1)

        run = ctk.CTkButton(bar, text="Obfuscate", command=self._run_obfuscate)
        run.grid(row=0, column=0, padx=12, pady=12); style_button(run)
        cancel = ctk.CTkButton(bar, text="Cancel", command=self._cancel, width=120)
        cancel.grid(row=0, column=1, padx=12, pady=12); style_button(cancel, ghost=True)

        self.obf_prog = ctk.CTkProgressBar(bar)
        self.obf_prog.grid(row=0, column=2, padx=12, pady=12, sticky="ew")
        self.obf_prog.set(0)

        self.obf_status = ctk.CTkLabel(parent, text="", font=("Segoe UI", 12))
        self.obf_status.grid(row=row+1, column=0, columnspan=3, padx=12, pady=(0, 10), sticky="w")
        style_label(self.obf_status, muted=True)

        self.after(0, self._sync_obf_mode)

    def _sync_obf_mode(self) -> None:
        ast_on = bool(self.obf_ast_only.get())
        xor_on = bool(self.obf_lab_xor.get())

        if ast_on and xor_on:
            self.obf_ast_only.set(False)
            ast_on = False

        if ast_on:
            self.obf_lab_xor.set(False)
            self.cb_obf_xor.configure(state="disabled")
        else:
            self.cb_obf_xor.configure(state="normal")

        self.cb_obf_ast.configure(state=("disabled" if xor_on else "normal"))

    def _pick_obf_in(self):
        p = filedialog.askopenfilename(filetypes=[("Python files","*.py"), ("All files","*.*")])
        if p:
            self.obf_in.set(p)

    def _pick_obf_out(self):
        p = filedialog.asksaveasfilename(filetypes=[("Python files","*.py")], defaultextension=".py")
        if p:
            self.obf_out.set(p)

    def _pick_obf_report(self):
        p = filedialog.asksaveasfilename(filetypes=[("JSON","*.json")], defaultextension=".json")
        if p:
            self.obf_report.set(p)

    def _run_obfuscate(self):
        in_path = self.obf_in.get().strip()
        out_path = self.obf_out.get().strip()
        rep_path = self.obf_report.get().strip() or None

        if not in_path or not os.path.isfile(in_path):
            messagebox.showerror("Missing input", "Choose a valid .py input file.")
            return
        if not out_path:
            out_path = os.path.join(os.path.dirname(in_path), "Obfuscated_" + os.path.basename(in_path))
            self.obf_out.set(out_path)

        try:
            seed_val = int(self.obf_seed.get()) if self.obf_seed.get().strip() else None
        except ValueError:
            messagebox.showerror("Seed", "Seed must be an integer (or empty).")
            return

        try:
            rec = max(1, int(self.obf_rec.get()))
        except ValueError:
            messagebox.showerror("Recursion", "Recursion must be integer >= 1.")
            return

        transforms = [StripDocstrings(), RenameIdentifiers(), EncodeConstants(), GetattrAttributes(), InsertDummyComments()]
        layers = []
        if not self.obf_ast_only.get():
            layers = [ZlibB64Split(), IPTable()]
            if self.obf_lab_xor.get():
                layers.append(XORBruteforceLab())

        self._stop_event.clear()
        self.obf_status.configure(text="Working…")
        self._log(f"[obfuscate] input={in_path} output={out_path} rec={rec} seed={seed_val} ast_only={self.obf_ast_only.get()} xor_lab={self.obf_lab_xor.get()}")

        # Engine signature is run_pipeline(code, ctx, transforms, layers) in this project.
        # We can't stop mid-run if engine doesn't support cancel callbacks, but we can skip writing output if cancelled.
        self.obf_prog.configure(mode="indeterminate")
        self.obf_prog.start()

        def work():
            try:
                with open(in_path, "r", encoding="utf-8") as f:
                    code = f.read()
                ctx = Context(seed=seed_val, recursion=rec, include_imports=False)
                out = run_pipeline(code, ctx, transforms, layers)

                def finish_ok():
                    self.obf_prog.stop()
                    self.obf_prog.configure(mode="determinate")
                    self.obf_prog.set(1.0)

                    if self._stop_event.is_set():
                        self.obf_status.configure(text="Cancelled (no file written) ⛔")
                        self._log("[obfuscate] cancelled; output not written.")
                        return

                    with open(out_path, "w", encoding="utf-8") as wf:
                        wf.write(out)

                    if rep_path:
                        write_report(rep_path, ctx)

                    self.obf_status.configure(text="Done ✅")
                    self._log(f"[obfuscate] saved: {out_path}")
                    if rep_path:
                        self._log(f"[obfuscate] report: {rep_path}")

                self.after(0, finish_ok)

            except Exception as e:
                def fail():
                    self.obf_prog.stop()
                    self.obf_prog.configure(mode="determinate")
                    self.obf_prog.set(0)
                    self.obf_status.configure(text="Failed ❌")
                    messagebox.showerror("Error", str(e))
                    self._log(f"[obfuscate] error: {e}")
                self.after(0, fail)

        threading.Thread(target=work, daemon=True).start()

    # ---------------- File Encrypt tab ----------------
    def _build_file_encrypt_tab(self, parent):
        parent.grid_columnconfigure(1, weight=1)

        self.f_in = tk.StringVar()
        self.f_out = tk.StringVar()
        self.f_pass = tk.StringVar()

        self.f_chacha = tk.BooleanVar(value=True)
        self.f_aesgcm = tk.BooleanVar(value=False)
        self.f_aessiv = tk.BooleanVar(value=False)

        self.f_overwrite = tk.BooleanVar(value=False)
        self.f_confirm_overwrite = tk.BooleanVar(value=False)

        row = 0
        ctk.CTkLabel(parent, text="Input file").grid(row=row, column=0, padx=12, pady=10, sticky="w")
        e1 = ctk.CTkEntry(parent, textvariable=self.f_in)
        e1.grid(row=row, column=1, padx=12, pady=10, sticky="ew"); style_entry(e1)
        b1 = ctk.CTkButton(parent, text="Browse", width=120, command=self._pick_f_in)
        b1.grid(row=row, column=2, padx=12, pady=10); style_button(b1)

        row += 1
        ctk.CTkLabel(parent, text="Output file").grid(row=row, column=0, padx=12, pady=10, sticky="w")
        e2 = ctk.CTkEntry(parent, textvariable=self.f_out)
        e2.grid(row=row, column=1, padx=12, pady=10, sticky="ew"); style_entry(e2)
        b2 = ctk.CTkButton(parent, text="Browse", width=120, command=self._pick_f_out)
        b2.grid(row=row, column=2, padx=12, pady=10); style_button(b2)

        row += 1
        ctk.CTkLabel(parent, text="Password").grid(row=row, column=0, padx=12, pady=10, sticky="w")
        e3 = ctk.CTkEntry(parent, textvariable=self.f_pass, show="•")
        e3.grid(row=row, column=1, padx=12, pady=10, sticky="w"); style_entry(e3)

        row += 1
        box = ctk.CTkFrame(parent, corner_radius=12)
        box.grid(row=row, column=0, columnspan=3, padx=12, pady=(6, 10), sticky="ew")
        style_frame(box)
        ctk.CTkLabel(box, text="Encryption layers (left → right)").grid(row=0, column=0, padx=12, pady=12, sticky="w")
        ctk.CTkCheckBox(box, text="ChaCha20-Poly1305", variable=self.f_chacha).grid(row=0, column=1, padx=12, pady=12, sticky="w")
        ctk.CTkCheckBox(box, text="AES-256-GCM", variable=self.f_aesgcm).grid(row=0, column=2, padx=12, pady=12, sticky="w")
        ctk.CTkCheckBox(box, text="AES-SIV", variable=self.f_aessiv).grid(row=0, column=3, padx=12, pady=12, sticky="w")

        row += 1
        ow = ctk.CTkCheckBox(parent, text="Overwrite input file (creates .bak backup first)", variable=self.f_overwrite)
        ow.grid(row=row, column=0, columnspan=3, padx=12, pady=(0, 6), sticky="w")
        row += 1
        cf = ctk.CTkCheckBox(parent, text="I understand overwrite makes the file non-runnable until decrypted back", variable=self.f_confirm_overwrite)
        cf.grid(row=row, column=0, columnspan=3, padx=12, pady=(0, 10), sticky="w")

        row += 1
        bar = ctk.CTkFrame(parent, corner_radius=12)
        bar.grid(row=row, column=0, columnspan=3, padx=12, pady=10, sticky="ew")
        style_frame(bar)
        bar.grid_columnconfigure(2, weight=1)

        run = ctk.CTkButton(bar, text="Encrypt file", command=self._run_file_encrypt)
        run.grid(row=0, column=0, padx=12, pady=12); style_button(run)
        cancel = ctk.CTkButton(bar, text="Cancel", command=self._cancel, width=120)
        cancel.grid(row=0, column=1, padx=12, pady=12); style_button(cancel, ghost=True)

        self.f_prog = ctk.CTkProgressBar(bar)
        self.f_prog.grid(row=0, column=2, padx=12, pady=12, sticky="ew")
        self.f_prog.set(0)

        self.f_status = ctk.CTkLabel(parent, text="", font=("Segoe UI", 12))
        self.f_status.grid(row=row+1, column=0, columnspan=3, padx=12, pady=(0, 10), sticky="w")
        style_label(self.f_status, muted=True)

    def _pick_f_in(self):
        p = filedialog.askopenfilename(filetypes=[("All files","*.*")])
        if p:
            self.f_in.set(p)

    def _pick_f_out(self):
        # User requested ".py" output (even though it will be encrypted bytes and not valid Python).
        p = filedialog.asksaveasfilename(filetypes=[("Python files","*.py"), ("All files","*.*")], defaultextension=".py")
        if p:
            self.f_out.set(p)

    def _run_file_encrypt(self):
        in_file = self.f_in.get().strip()
        out_file = self.f_out.get().strip()
        pw = self.f_pass.get()

        if not in_file or not os.path.isfile(in_file):
            messagebox.showerror("Missing input", "Choose a valid input file.")
            return
        if not pw:
            messagebox.showerror("Missing password", "Enter a password.")
            return

        algs = []
        if self.f_chacha.get(): algs.append(BundleAlg.chacha20)
        if self.f_aesgcm.get(): algs.append(BundleAlg.aesgcm)
        if self.f_aessiv.get(): algs.append(BundleAlg.aessiv)
        if not algs:
            messagebox.showerror("No algorithms", "Select at least one encryption method.")
            return

        if self.f_overwrite.get():
            if not self.f_confirm_overwrite.get():
                messagebox.showerror("Confirm overwrite", "Tick the confirmation checkbox before overwriting.")
                return
            try:
                bak = in_file + ".bak"
                shutil.copyfile(in_file, bak)
                self._log(f"[file-encrypt] backup created: {bak}")
            except Exception as e:
                messagebox.showerror("Backup failed", str(e))
                return
            out_file = in_file
            self.f_out.set(out_file)
        else:
            if not out_file:
                base, _ext = os.path.splitext(in_file)
                out_file = base + "_encrypted.py"
                self.f_out.set(out_file)

        self._stop_event.clear()
        self.f_prog.set(0)
        self.f_status.configure(text="Encrypting…")
        self._log(f"[file-encrypt] input={in_file} output={out_file} layers={','.join(a.value for a in algs)}")

        def work():
            try:
                self.after(0, lambda: self.f_prog.set(0.2))
                encrypt_file(in_file, out_file, password=pw, algs=algs, kdf=KdfKind.scrypt)
                self.after(0, lambda: self.f_prog.set(1.0))
                self.after(0, lambda: self.f_status.configure(text="Done ✅"))
                self.after(0, lambda: self._log(f"[file-encrypt] saved: {out_file}"))
            except Exception as e:
                self.after(0, lambda: self.f_status.configure(text="Failed ❌"))
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
                self.after(0, lambda: self._log(f"[file-encrypt] error: {e}"))
        threading.Thread(target=work, daemon=True).start()

    # ---------------- File Decrypt tab ----------------
    def _build_file_decrypt_tab(self, parent):
        parent.grid_columnconfigure(1, weight=1)
        self.fd_in = tk.StringVar()
        self.fd_out = tk.StringVar()
        self.fd_pass = tk.StringVar()

        row = 0
        ctk.CTkLabel(parent, text="Input encrypted file").grid(row=row, column=0, padx=12, pady=10, sticky="w")
        e1 = ctk.CTkEntry(parent, textvariable=self.fd_in)
        e1.grid(row=row, column=1, padx=12, pady=10, sticky="ew"); style_entry(e1)
        b1 = ctk.CTkButton(parent, text="Browse", width=120, command=self._pick_fd_in)
        b1.grid(row=row, column=2, padx=12, pady=10); style_button(b1)

        row += 1
        ctk.CTkLabel(parent, text="Output file (optional)").grid(row=row, column=0, padx=12, pady=10, sticky="w")
        e2 = ctk.CTkEntry(parent, textvariable=self.fd_out)
        e2.grid(row=row, column=1, padx=12, pady=10, sticky="ew"); style_entry(e2)
        b2 = ctk.CTkButton(parent, text="Browse", width=120, command=self._pick_fd_out)
        b2.grid(row=row, column=2, padx=12, pady=10); style_button(b2)

        row += 1
        ctk.CTkLabel(parent, text="Password").grid(row=row, column=0, padx=12, pady=10, sticky="w")
        e3 = ctk.CTkEntry(parent, textvariable=self.fd_pass, show="•")
        e3.grid(row=row, column=1, padx=12, pady=10, sticky="w"); style_entry(e3)

        row += 1
        bar = ctk.CTkFrame(parent, corner_radius=12)
        bar.grid(row=row, column=0, columnspan=3, padx=12, pady=10, sticky="ew")
        style_frame(bar)
        bar.grid_columnconfigure(3, weight=1)

        run = ctk.CTkButton(bar, text="Decrypt (save as)", command=self._run_file_decrypt)
        run.grid(row=0, column=0, padx=12, pady=12); style_button(run)
        openf = ctk.CTkButton(bar, text="Decrypt → temp + open", command=self._decrypt_to_temp_open)
        openf.grid(row=0, column=1, padx=12, pady=12); style_button(openf, ghost=True)
        cancel = ctk.CTkButton(bar, text="Cancel", command=self._cancel, width=120)
        cancel.grid(row=0, column=2, padx=12, pady=12); style_button(cancel, ghost=True)

        self.fd_prog = ctk.CTkProgressBar(bar)
        self.fd_prog.grid(row=0, column=3, padx=12, pady=12, sticky="ew")
        self.fd_prog.set(0)

        self.fd_status = ctk.CTkLabel(parent, text="", font=("Segoe UI", 12))
        self.fd_status.grid(row=row+1, column=0, columnspan=3, padx=12, pady=(0, 10), sticky="w")
        style_label(self.fd_status, muted=True)

    def _pick_fd_in(self):
        # accept anything because user might save encrypted bytes as .py
        p = filedialog.askopenfilename(filetypes=[("All files","*.*")])
        if p:
            self.fd_in.set(p)

    def _pick_fd_out(self):
        p = filedialog.asksaveasfilename(filetypes=[("All files","*.*")])
        if p:
            self.fd_out.set(p)

    def _run_file_decrypt(self):
        in_file = self.fd_in.get().strip()
        out_file = self.fd_out.get().strip()
        pw = self.fd_pass.get()

        if not in_file or not os.path.isfile(in_file):
            messagebox.showerror("Missing input", "Choose a valid encrypted file.")
            return
        if not pw:
            messagebox.showerror("Missing password", "Enter the password.")
            return
        if not out_file:
            out_file = in_file + ".decrypted"
            self.fd_out.set(out_file)

        self.fd_prog.set(0)
        self.fd_status.configure(text="Decrypting…")
        self._log(f"[file-decrypt] input={in_file} output={out_file}")

        def work():
            try:
                self.after(0, lambda: self.fd_prog.set(0.2))
                decrypt_file(in_file, out_file, password=pw)
                self.after(0, lambda: self.fd_prog.set(1.0))
                self.after(0, lambda: self.fd_status.configure(text="Done ✅"))
                self.after(0, lambda: self._log(f"[file-decrypt] saved: {out_file}"))
            except Exception as e:
                self.after(0, lambda: self.fd_status.configure(text="Failed ❌"))
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
                self.after(0, lambda: self._log(f"[file-decrypt] error: {e}"))
        threading.Thread(target=work, daemon=True).start()

    def _decrypt_to_temp_open(self):
        in_file = self.fd_in.get().strip()
        pw = self.fd_pass.get()

        if not in_file or not os.path.isfile(in_file):
            messagebox.showerror("Missing input", "Choose a valid encrypted file.")
            return
        if not pw:
            messagebox.showerror("Missing password", "Enter the password.")
            return

        self.fd_prog.set(0)
        self.fd_status.configure(text="Decrypting to temp…")

        def work():
            try:
                self.after(0, lambda: self.fd_prog.set(0.2))
                tmpdir = tempfile.mkdtemp(prefix="blankobf_decrypted_")
                out_path = decrypt_file_to_dir(in_file, tmpdir, password=pw)
                self.after(0, lambda: self.fd_prog.set(1.0))
                self.after(0, lambda: self.fd_status.configure(text=f"Decrypted to temp ✅  {out_path}"))
                self.after(0, lambda: self._log(f"[file-decrypt] temp: {out_path}"))
                try:
                    folder = os.path.dirname(out_path)
                    if os.name == "nt":
                        os.startfile(folder)  # type: ignore
                    else:
                        subprocess.Popen(["xdg-open", folder])
                except Exception:
                    pass
            except Exception as e:
                self.after(0, lambda: self.fd_status.configure(text="Failed ❌"))
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
                self.after(0, lambda: self._log(f"[file-decrypt] error: {e}"))
        threading.Thread(target=work, daemon=True).start()

    # ---------------- Bundle tabs (folder) ----------------
    def _build_bundle_encrypt_tab(self, parent):
        parent.grid_columnconfigure(1, weight=1)
        self.b_in = tk.StringVar()
        self.b_out = tk.StringVar()
        self.b_pass = tk.StringVar()
        self.b_chacha = tk.BooleanVar(value=True)
        self.b_aesgcm = tk.BooleanVar(value=False)
        self.b_aessiv = tk.BooleanVar(value=False)

        row = 0
        ctk.CTkLabel(parent, text="Input folder").grid(row=row, column=0, padx=12, pady=10, sticky="w")
        e1 = ctk.CTkEntry(parent, textvariable=self.b_in)
        e1.grid(row=row, column=1, padx=12, pady=10, sticky="ew"); style_entry(e1)
        b1 = ctk.CTkButton(parent, text="Browse", width=120, command=lambda: self._pick_dir(self.b_in))
        b1.grid(row=row, column=2, padx=12, pady=10); style_button(b1)

        row += 1
        ctk.CTkLabel(parent, text="Output bundle (.bobf)").grid(row=row, column=0, padx=12, pady=10, sticky="w")
        e2 = ctk.CTkEntry(parent, textvariable=self.b_out)
        e2.grid(row=row, column=1, padx=12, pady=10, sticky="ew"); style_entry(e2)
        b2 = ctk.CTkButton(parent, text="Browse", width=120, command=lambda: self._pick_save(self.b_out, ".bobf"))
        b2.grid(row=row, column=2, padx=12, pady=10); style_button(b2)

        row += 1
        ctk.CTkLabel(parent, text="Password").grid(row=row, column=0, padx=12, pady=10, sticky="w")
        e3 = ctk.CTkEntry(parent, textvariable=self.b_pass, show="•")
        e3.grid(row=row, column=1, padx=12, pady=10, sticky="w"); style_entry(e3)

        row += 1
        box = ctk.CTkFrame(parent, corner_radius=12)
        box.grid(row=row, column=0, columnspan=3, padx=12, pady=(6, 10), sticky="ew")
        style_frame(box)
        ctk.CTkLabel(box, text="Layers (left → right)").grid(row=0, column=0, padx=12, pady=12, sticky="w")
        ctk.CTkCheckBox(box, text="ChaCha20-Poly1305", variable=self.b_chacha).grid(row=0, column=1, padx=12, pady=12, sticky="w")
        ctk.CTkCheckBox(box, text="AES-256-GCM", variable=self.b_aesgcm).grid(row=0, column=2, padx=12, pady=12, sticky="w")
        ctk.CTkCheckBox(box, text="AES-SIV", variable=self.b_aessiv).grid(row=0, column=3, padx=12, pady=12, sticky="w")

        row += 1
        bar = ctk.CTkFrame(parent, corner_radius=12)
        bar.grid(row=row, column=0, columnspan=3, padx=12, pady=10, sticky="ew")
        style_frame(bar)
        bar.grid_columnconfigure(2, weight=1)

        run = ctk.CTkButton(bar, text="Encrypt folder", command=self._run_bundle_encrypt)
        run.grid(row=0, column=0, padx=12, pady=12); style_button(run)
        cancel = ctk.CTkButton(bar, text="Cancel", command=self._cancel, width=120)
        cancel.grid(row=0, column=1, padx=12, pady=12); style_button(cancel, ghost=True)

        self.b_prog = ctk.CTkProgressBar(bar)
        self.b_prog.grid(row=0, column=2, padx=12, pady=12, sticky="ew")
        self.b_prog.set(0)

        self.b_status = ctk.CTkLabel(parent, text="A .bobf file is an encrypted folder bundle (multiple files).", font=("Segoe UI", 12))
        self.b_status.grid(row=row+1, column=0, columnspan=3, padx=12, pady=(0, 10), sticky="w")
        style_label(self.b_status, muted=True)

    def _build_bundle_decrypt_tab(self, parent):
        parent.grid_columnconfigure(1, weight=1)
        self.bd_in = tk.StringVar()
        self.bd_out = tk.StringVar()
        self.bd_pass = tk.StringVar()

        row = 0
        ctk.CTkLabel(parent, text="Input bundle (.bobf)").grid(row=row, column=0, padx=12, pady=10, sticky="w")
        e1 = ctk.CTkEntry(parent, textvariable=self.bd_in)
        e1.grid(row=row, column=1, padx=12, pady=10, sticky="ew"); style_entry(e1)
        b1 = ctk.CTkButton(parent, text="Browse", width=120, command=lambda: self._pick_open(self.bd_in, [("BOBF","*.bobf"),("All","*.*")]))
        b1.grid(row=row, column=2, padx=12, pady=10); style_button(b1)

        row += 1
        ctk.CTkLabel(parent, text="Output folder").grid(row=row, column=0, padx=12, pady=10, sticky="w")
        e2 = ctk.CTkEntry(parent, textvariable=self.bd_out)
        e2.grid(row=row, column=1, padx=12, pady=10, sticky="ew"); style_entry(e2)
        b2 = ctk.CTkButton(parent, text="Browse", width=120, command=lambda: self._pick_dir(self.bd_out))
        b2.grid(row=row, column=2, padx=12, pady=10); style_button(b2)

        row += 1
        ctk.CTkLabel(parent, text="Password").grid(row=row, column=0, padx=12, pady=10, sticky="w")
        e3 = ctk.CTkEntry(parent, textvariable=self.bd_pass, show="•")
        e3.grid(row=row, column=1, padx=12, pady=10, sticky="w"); style_entry(e3)

        row += 1
        bar = ctk.CTkFrame(parent, corner_radius=12)
        bar.grid(row=row, column=0, columnspan=3, padx=12, pady=10, sticky="ew")
        style_frame(bar)
        bar.grid_columnconfigure(2, weight=1)

        run = ctk.CTkButton(bar, text="Decrypt bundle", command=self._run_bundle_decrypt)
        run.grid(row=0, column=0, padx=12, pady=12); style_button(run)
        cancel = ctk.CTkButton(bar, text="Cancel", command=self._cancel, width=120)
        cancel.grid(row=0, column=1, padx=12, pady=12); style_button(cancel, ghost=True)

        self.bd_prog = ctk.CTkProgressBar(bar)
        self.bd_prog.grid(row=0, column=2, padx=12, pady=12, sticky="ew")
        self.bd_prog.set(0)

        self.bd_status = ctk.CTkLabel(parent, text="", font=("Segoe UI", 12))
        self.bd_status.grid(row=row+1, column=0, columnspan=3, padx=12, pady=(0, 10), sticky="w")
        style_label(self.bd_status, muted=True)

    def _pick_dir(self, var: tk.StringVar):
        p = filedialog.askdirectory()
        if p:
            var.set(p)

    def _pick_save(self, var: tk.StringVar, ext: str):
        p = filedialog.asksaveasfilename(defaultextension=ext, filetypes=[(ext.upper().strip("."), f"*{ext}"), ("All files","*.*")])
        if p:
            var.set(p)

    def _pick_open(self, var: tk.StringVar, filetypes):
        p = filedialog.askopenfilename(filetypes=filetypes)
        if p:
            var.set(p)

    def _run_bundle_encrypt(self):
        in_dir = self.b_in.get().strip()
        out_file = self.b_out.get().strip()
        pw = self.b_pass.get()

        if not in_dir or not os.path.isdir(in_dir):
            messagebox.showerror("Missing input", "Choose a valid folder.")
            return
        if not out_file:
            messagebox.showerror("Missing output", "Choose an output .bobf file.")
            return
        if not pw:
            messagebox.showerror("Missing password", "Enter a password.")
            return

        algs = []
        if self.b_chacha.get(): algs.append(BundleAlg.chacha20)
        if self.b_aesgcm.get(): algs.append(BundleAlg.aesgcm)
        if self.b_aessiv.get(): algs.append(BundleAlg.aessiv)
        if not algs:
            messagebox.showerror("No algorithms", "Select at least one encryption method.")
            return

        self.b_prog.set(0)
        self.b_status.configure(text="Encrypting…")
        self._log(f"[bundle-encrypt] folder={in_dir} out={out_file} layers={','.join(a.value for a in algs)}")

        def work():
            try:
                self.after(0, lambda: self.b_prog.set(0.2))
                bundle_encrypt(in_dir, out_file, password=pw, algs=algs, kdf=KdfKind.scrypt)
                self.after(0, lambda: self.b_prog.set(1.0))
                self.after(0, lambda: self.b_status.configure(text="Done ✅"))
                self.after(0, lambda: self._log(f"[bundle-encrypt] saved: {out_file}"))
            except Exception as e:
                self.after(0, lambda: self.b_status.configure(text="Failed ❌"))
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
                self.after(0, lambda: self._log(f"[bundle-encrypt] error: {e}"))
        threading.Thread(target=work, daemon=True).start()

    def _run_bundle_decrypt(self):
        in_file = self.bd_in.get().strip()
        out_dir = self.bd_out.get().strip()
        pw = self.bd_pass.get()

        if not in_file or not os.path.isfile(in_file):
            messagebox.showerror("Missing input", "Choose a valid .bobf file.")
            return
        if not out_dir:
            messagebox.showerror("Missing output", "Choose output folder.")
            return
        if not pw:
            messagebox.showerror("Missing password", "Enter password.")
            return

        self.bd_prog.set(0)
        self.bd_status.configure(text="Decrypting…")
        self._log(f"[bundle-decrypt] input={in_file} out={out_dir}")

        def work():
            try:
                self.after(0, lambda: self.bd_prog.set(0.2))
                bundle_decrypt(in_file, out_dir, password=pw)
                self.after(0, lambda: self.bd_prog.set(1.0))
                self.after(0, lambda: self.bd_status.configure(text="Done ✅"))
                self.after(0, lambda: self._log(f"[bundle-decrypt] extracted: {out_dir}"))
            except Exception as e:
                self.after(0, lambda: self.bd_status.configure(text="Failed ❌"))
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
                self.after(0, lambda: self._log(f"[bundle-decrypt] error: {e}"))
        threading.Thread(target=work, daemon=True).start()

    # ---------------- Compiler tab ----------------
    def _build_compiler_tab(self, parent):
        parent.grid_columnconfigure(1, weight=1)
        self.c_in = tk.StringVar()
        self.c_out = tk.StringVar()
        self.c_onefile = tk.BooleanVar(value=True)
        self.c_icon = tk.StringVar()

        row = 0
        ctk.CTkLabel(parent, text="Python entry file (.py)").grid(row=row, column=0, padx=12, pady=10, sticky="w")
        e1 = ctk.CTkEntry(parent, textvariable=self.c_in)
        e1.grid(row=row, column=1, padx=12, pady=10, sticky="ew"); style_entry(e1)
        b1 = ctk.CTkButton(parent, text="Browse", width=120, command=self._pick_c_in)
        b1.grid(row=row, column=2, padx=12, pady=10); style_button(b1)

        row += 1
        ctk.CTkLabel(parent, text="Output folder").grid(row=row, column=0, padx=12, pady=10, sticky="w")
        e2 = ctk.CTkEntry(parent, textvariable=self.c_out)
        e2.grid(row=row, column=1, padx=12, pady=10, sticky="ew"); style_entry(e2)
        b2 = ctk.CTkButton(parent, text="Browse", width=120, command=self._pick_c_out)
        b2.grid(row=row, column=2, padx=12, pady=10); style_button(b2)

        row += 1
        ctk.CTkLabel(parent, text="Icon (.ico) (optional)").grid(row=row, column=0, padx=12, pady=10, sticky="w")
        e3 = ctk.CTkEntry(parent, textvariable=self.c_icon)
        e3.grid(row=row, column=1, padx=12, pady=10, sticky="ew"); style_entry(e3)
        b3 = ctk.CTkButton(parent, text="Browse", width=120, command=self._pick_c_icon)
        b3.grid(row=row, column=2, padx=12, pady=10); style_button(b3)

        row += 1
        ctk.CTkCheckBox(parent, text="Onefile (single .exe)", variable=self.c_onefile).grid(row=row, column=0, columnspan=3, padx=12, pady=(0, 10), sticky="w")

        row += 1
        bar = ctk.CTkFrame(parent, corner_radius=12)
        bar.grid(row=row, column=0, columnspan=3, padx=12, pady=10, sticky="ew")
        style_frame(bar)
        bar.grid_columnconfigure(2, weight=1)

        bbat = ctk.CTkButton(bar, text="Create .bat wrapper", command=self._make_bat)
        bbat.grid(row=0, column=0, padx=12, pady=12); style_button(bbat)

        bexe = ctk.CTkButton(bar, text="Build .exe (PyInstaller)", command=self._build_exe)
        bexe.grid(row=0, column=1, padx=12, pady=12); style_button(bexe)

        self.c_prog = ctk.CTkProgressBar(bar)
        self.c_prog.grid(row=0, column=2, padx=12, pady=12, sticky="ew")
        self.c_prog.set(0)

        note = ctk.CTkLabel(parent, text="EXE build uses PyInstaller (install: pip install pyinstaller).", font=("Segoe UI", 12))
        note.grid(row=row+1, column=0, columnspan=3, padx=12, pady=(0, 10), sticky="w")
        style_label(note, muted=True)

    def _pick_c_in(self):
        p = filedialog.askopenfilename(filetypes=[("Python files","*.py"), ("All files","*.*")])
        if p:
            self.c_in.set(p)

    def _pick_c_out(self):
        p = filedialog.askdirectory()
        if p:
            self.c_out.set(p)

    def _pick_c_icon(self):
        p = filedialog.askopenfilename(filetypes=[("Icon files","*.ico"), ("All files","*.*")])
        if p:
            self.c_icon.set(p)

    def _make_bat(self):
        src = self.c_in.get().strip()
        outdir = self.c_out.get().strip() or os.path.dirname(src)

        if not src or not os.path.isfile(src):
            messagebox.showerror("Missing input", "Choose a valid .py file.")
            return
        os.makedirs(outdir, exist_ok=True)

        name = os.path.splitext(os.path.basename(src))[0]
        bat = os.path.join(outdir, name + ".bat")
        pyexe = os.path.abspath(os.sys.executable)

        try:
            shutil.copyfile(src, os.path.join(outdir, name + ".py"))
        except Exception:
            pass

        with open(bat, "w", encoding="utf-8") as f:
            f.write(f'@echo off\n"{pyexe}" "%~dp0{name}.py" %*\n')

        self._log(f"[compiler] .bat created: {bat}")
        messagebox.showinfo("Done", f"Created: {bat}")

    def _build_exe(self):
        src = self.c_in.get().strip()
        outdir = self.c_out.get().strip()
        if not src or not os.path.isfile(src):
            messagebox.showerror("Missing input", "Choose a valid .py file.")
            return
        if not outdir:
            messagebox.showerror("Missing output", "Choose an output folder.")
            return

        icon_path = self.c_icon.get().strip()
        onefile = self.c_onefile.get()
        self.c_prog.set(0)
        self._log(f"[compiler] building exe via PyInstaller (onefile={onefile})")

        def work():
            try:
                self.after(0, lambda: self.c_prog.set(0.2))
                cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm"]
                if icon_path and os.path.isfile(icon_path):
                    cmd += ["--icon", icon_path]
                if onefile:
                    cmd.append("--onefile")
                cmd += ["--distpath", outdir, "--workpath", os.path.join(outdir, "build"), "--specpath", outdir, src]

                p = subprocess.run(cmd, capture_output=True, text=True)
                self.after(0, lambda: self.c_prog.set(1.0))
                self.after(0, lambda: self._log(p.stdout))
                if p.stderr:
                    self.after(0, lambda: self._log(p.stderr))
                if p.returncode != 0:
                    raise RuntimeError("PyInstaller failed. See log output for details. Common cause: PyInstaller installed in a different Python environment than the one running this app.")
                self.after(0, lambda: messagebox.showinfo("Done", "EXE build finished. Check the output folder."))
            except Exception as e:
                self.after(0, lambda e=e: messagebox.showerror("Build error", str(e)))
                self.after(0, lambda e=e: self._log(f"[compiler] error: {e}"))
        threading.Thread(target=work, daemon=True).start()

    # ---------------- About tab ----------------
    def _build_about_tab(self, parent):
        txt = (
            "Obfuscation:\n"
            "• Seed: optional integer for reproducible results.\n"
            "• Recursion: number of passes (1–2 recommended).\n"
            "• AST-only and XOR-lab are mutually exclusive.\n\n"
            "File encryption:\n"
            "• You can select multiple AEAD layers (left → right).\n"
            "• Output can be saved as .py if you want, but it will be encrypted bytes (not runnable).\n"
            "• Overwrite mode creates a .bak backup first.\n"
            "• Use Decrypt → temp + open for quick access to a usable file.\n\n"
            "Bundle (.bobf):\n"
            "• Encrypts a whole folder into one encrypted container.\n\n"
            "Compiler:\n"
            "• Creates .bat wrapper or builds .exe via PyInstaller.\n"
        )
        lab = ctk.CTkLabel(parent, text=txt, justify="left", font=("Segoe UI", 12))
        lab.pack(padx=16, pady=16, anchor="nw")
        style_label(lab)

def main() -> None:
    App().mainloop()
