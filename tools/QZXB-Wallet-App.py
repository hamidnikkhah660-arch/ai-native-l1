#!/usr/bin/env python3
"""QZXB Wallet — QRun desktop frontend for the native Windows wallet engine."""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

APP_NAME = "QZXB Wallet — QRun"
ACCENT = "#718CFF"
BG = "#0B1220"
PANEL = "#111D30"
FIELD = "#091321"
TEXT = "#E6EDF7"
MUTED = "#9BAFCB"
GOOD = "#91E6B1"
WARN = "#FFD58A"


def parse_field(output: str, field: str) -> str:
    match = re.search(r"(?m)^" + re.escape(field) + r"=(.*)$", output)
    return match.group(1).strip() if match else ""


def wallet_paths() -> tuple[Path, Path, Path]:
    repo = Path(__file__).resolve().parents[1]
    engine = repo / "src" / "native" / "pow_bench" / "target" / "release" / "qzxb_wallet.exe"
    home = Path(os.environ.get("APPDATA", str(Path.home()))) / "QZXB"
    return engine, home, home / "active-wallet-path.txt"


class QZXBWalletApp:
    def __init__(self) -> None:
        self.engine, self.home, self.active_path_file = wallet_paths()
        self.home.mkdir(parents=True, exist_ok=True)
        self.default_wallet = self.home / "wallet.qzw1"
        self.wallet_path = self.default_wallet
        try:
            saved = self.active_path_file.read_text(encoding="utf-8").strip()
            if saved and Path(saved).is_absolute():
                self.wallet_path = Path(saved)
        except OSError:
            pass

        self.root = tk.Tk()
        self.root.title(APP_NAME)
        self.root.geometry("900x650")
        self.root.minsize(780, 570)
        self.root.configure(bg=BG)
        self._configure_styles()
        self._build_ui()

        if not self.engine.is_file():
            self.status_var.set("Wallet engine not built. The project executable is missing.")
            self.status_label.configure(foreground=WARN)
            self.create_btn.configure(state="disabled")
            self.restore_btn.configure(state="disabled")
        else:
            self.refresh_wallet()

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 10))
        style.configure("Title.TLabel", background=BG, foreground="#FFFFFF", font=("Segoe UI", 24, "bold"))
        style.configure("Section.TLabel", background=PANEL, foreground="#FFFFFF", font=("Segoe UI", 15, "bold"))
        style.configure("Status.TLabel", background=PANEL, foreground=GOOD, font=("Segoe UI", 10))
        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), padding=(16, 11),
                        background=ACCENT, foreground="#FFFFFF")
        style.map("Primary.TButton", background=[("active", "#8EA3FF"), ("disabled", "#46516D")])
        style.configure("Secondary.TButton", font=("Segoe UI", 10), padding=(14, 10),
                        background="#243650", foreground=TEXT)
        style.map("Secondary.TButton", background=[("active", "#334A69")])
        style.configure("TEntry", fieldbackground=FIELD, foreground=TEXT, insertcolor=TEXT, padding=8)
        style.configure("TCheckbutton", background="#FFFFFF", foreground="#192235", font=("Segoe UI", 10))

    def _build_ui(self) -> None:
        outer = ttk.Frame(self.root, padding=(26, 24))
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 17))
        titlebox = ttk.Frame(header)
        titlebox.pack(side="left", fill="x", expand=True)
        ttk.Label(titlebox, text="QZXB WALLET", style="Title.TLabel").pack(anchor="w")
        ttk.Label(titlebox, text="QRun • Quantum Run • Native QZXB", style="Muted.TLabel").pack(anchor="w", pady=(4, 0))
        self.mainnet_badge = tk.Label(header, text="MAINNET NOT LAUNCHED", bg="#392D20",
                                      fg=WARN, padx=12, pady=9, font=("Segoe UI", 9, "bold"))
        self.mainnet_badge.pack(side="right", padx=(12, 0), pady=6)

        location_panel = tk.Frame(outer, bg="#152238", padx=16, pady=14)
        location_panel.pack(fill="x", pady=(0, 15))
        tk.Label(location_panel, text="WALLET FILE", bg="#152238", fg=MUTED,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.path_var = tk.StringVar()
        self.path_entry = ttk.Entry(location_panel, textvariable=self.path_var, state="readonly")
        self.path_entry.pack(fill="x", pady=(6, 8))
        self.status_var = tk.StringVar(value="Checking wallet…")
        self.status_label = tk.Label(location_panel, textvariable=self.status_var, bg="#152238",
                                     fg=TEXT, anchor="w", wraplength=800, justify="left")
        self.status_label.pack(fill="x")

        panel = tk.Frame(outer, bg=PANEL, padx=22, pady=20)
        panel.pack(fill="both", expand=True)
        tk.Label(panel, text="Your QZXB account ID", bg=PANEL, fg="#FFFFFF",
                 font=("Segoe UI", 15, "bold")).pack(anchor="w")
        tk.Label(panel, text="A public 32-byte native-chain account identifier. It does not prove that the account has a Mainnet balance.",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 10), wraplength=780, justify="left").pack(anchor="w", pady=(8, 12))

        self.account_var = tk.StringVar()
        self.account_entry = tk.Entry(panel, textvariable=self.account_var, state="readonly",
                                      readonlybackground=FIELD, fg="#B9D8FF", insertbackground=TEXT,
                                      font=("Consolas", 11), relief="flat", bd=0, highlightthickness=1,
                                      highlightbackground="#2E405C", highlightcolor=ACCENT)
        self.account_entry.pack(fill="x", ipady=15, pady=(0, 16))

        buttons = ttk.Frame(panel, style="Panel.TFrame")
        buttons.pack(fill="x", pady=(0, 16))
        self.create_btn = ttk.Button(buttons, text="Create wallet", style="Primary.TButton", command=self.create_wallet)
        self.create_btn.pack(side="left", padx=(0, 8), pady=3)
        self.restore_btn = ttk.Button(buttons, text="Restore 12 words", style="Secondary.TButton", command=self.restore_wallet)
        self.restore_btn.pack(side="left", padx=8, pady=3)
        self.copy_btn = ttk.Button(buttons, text="Copy account ID", style="Secondary.TButton", command=self.copy_account, state="disabled")
        self.copy_btn.pack(side="left", padx=8, pady=3)
        self.open_btn = ttk.Button(buttons, text="Open wallet folder", style="Secondary.TButton", command=self.open_folder)
        self.open_btn.pack(side="left", padx=8, pady=3)

        security = tk.Frame(panel, bg="#1B2A40", padx=12, pady=11)
        security.pack(fill="x")
        tk.Label(security, text="LOCAL KEY SECURITY", bg="#1B2A40", fg="#D6E3F5",
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Label(security, text="The wallet file is protected by Windows DPAPI. The 12-word recovery phrase is shown once and is not written to the wallet file. Recovery derivation is specific to QZXB; this wallet has not been externally audited.",
                 bg="#1B2A40", fg="#C6D5E8", font=("Segoe UI", 9), wraplength=790,
                 justify="left").pack(anchor="w", pady=(5, 0))

        tk.Label(outer, text="Independent-chain candidate • Live balances and transfers stay disabled until a production Mainnet node is qualified.",
                 bg=BG, fg=MUTED, font=("Segoe UI", 9), wraplength=820, justify="left").pack(fill="x", pady=(14, 0))

    def run_engine(self, args: list[str], secret_input: str | None = None) -> subprocess.CompletedProcess[str]:
        if not self.engine.is_file():
            raise FileNotFoundError(f"Wallet engine was not found: {self.engine}")
        return subprocess.run(
            [str(self.engine), *args],
            input=(secret_input + "\n") if secret_input is not None else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )

    def save_active_path(self) -> None:
        self.active_path_file.write_text(str(self.wallet_path), encoding="utf-8")

    def refresh_wallet(self) -> None:
        self.path_var.set(str(self.wallet_path))
        if self.wallet_path.is_file() and self.engine.is_file():
            try:
                result = self.run_engine(["address", "--wallet", str(self.wallet_path)])
                account = parse_field(result.stdout, "account_id_hex") if result.returncode == 0 else ""
                if account:
                    self.account_var.set(account)
                    self.status_var.set("Local wallet found • encrypted for this Windows user")
                    self.status_label.configure(fg=GOOD)
                    self.copy_btn.configure(state="normal")
                    return
                self.account_var.set("")
                self.status_var.set("Wallet file exists but could not be unlocked by this Windows profile.")
                self.status_label.configure(fg=WARN)
            except Exception as exc:
                self.account_var.set("")
                self.status_var.set(f"Wallet could not be opened: {exc}")
                self.status_label.configure(fg=WARN)
        else:
            self.account_var.set("")
            self.status_var.set("No local wallet yet. Create or restore one below.")
            self.status_label.configure(fg=MUTED)
        self.copy_btn.configure(state="disabled")

    def create_wallet(self) -> None:
        if self.wallet_path.exists():
            messagebox.showwarning("QZXB Wallet", "A wallet already exists at this path. Existing keys are never overwritten. Restore to a new file or select your existing wallet.")
            self.refresh_wallet()
            return
        try:
            result = self.run_engine(["create", "--output", str(self.wallet_path)])
            if result.returncode != 0:
                messagebox.showerror("Create wallet", (result.stderr + "\n" + result.stdout).strip())
                return
            phrase = parse_field(result.stdout, "recovery_phrase")
            account = parse_field(result.stdout, "account_id_hex")
            if len(phrase.split()) != 12 or not account:
                messagebox.showerror("Create wallet", "Wallet creation output failed validation. Do not fund this wallet.")
                return
            self.save_active_path()
            self.refresh_wallet()
            accepted = self.show_recovery_phrase(phrase)
            phrase = ""
            if not accepted:
                try:
                    self.wallet_path.unlink(missing_ok=True)
                except OSError:
                    pass
                self.wallet_path = self.default_wallet
                self.save_active_path()
                self.refresh_wallet()
                messagebox.showinfo("Wallet creation cancelled", "The newly created wallet file was removed because its recovery phrase was not confirmed as backed up.")
                return
            messagebox.showinfo("QZXB Wallet", "Wallet file created and locally protected. Your recovery phrase was shown once. Mainnet balance is not created because the production network is not launched.")
        except Exception as exc:
            messagebox.showerror("Create wallet", str(exc))
        finally:
            self.refresh_wallet()

    def show_recovery_phrase(self, phrase: str) -> bool:
        words = phrase.split()
        if len(words) != 12:
            return False
        dlg = tk.Toplevel(self.root)
        dlg.title("QZXB Wallet — recovery phrase")
        dlg.configure(bg="#FFFFFF")
        dlg.resizable(False, False)
        dlg.transient(self.root)
        dlg.grab_set()
        result = {"confirmed": False}
        tk.Label(dlg, text="Write down these 12 words", bg="#FFFFFF", fg="#172033",
                 font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=24, pady=(22, 6))
        tk.Label(dlg, text="This phrase controls the wallet. It is shown once and is not stored in the wallet file. Never share it or keep it in cloud notes.",
                 bg="#FFFFFF", fg="#8C2020", font=("Segoe UI", 10), wraplength=530,
                 justify="left").pack(anchor="w", padx=24, pady=(0, 14))
        words_frame = tk.Frame(dlg, bg="#F1F5FB", padx=18, pady=14)
        words_frame.pack(fill="x", padx=24)
        for i, word in enumerate(words):
            row, col = i % 6, i // 6
            tk.Label(words_frame, text=f"{i + 1:02d}.  {word}", bg="#F1F5FB", fg="#152238",
                     font=("Consolas", 12), width=19, anchor="w").grid(row=row, column=col, padx=6, pady=5)
        ack = tk.BooleanVar(value=False)
        ttk.Checkbutton(dlg, text="I wrote down all 12 words and checked the order.",
                        variable=ack).pack(anchor="w", padx=24, pady=(16, 10))
        buttons = tk.Frame(dlg, bg="#FFFFFF")
        buttons.pack(fill="x", padx=24, pady=(0, 22))
        confirm = ttk.Button(buttons, text="I saved the phrase", style="Primary.TButton",
                             command=lambda: (result.update(confirmed=True), dlg.destroy()) if ack.get() else None)
        confirm.pack(side="right")
        cancel = ttk.Button(buttons, text="Cancel and delete wallet", style="Secondary.TButton",
                            command=dlg.destroy)
        cancel.pack(side="right", padx=(0, 8))
        dlg.protocol("WM_DELETE_WINDOW", dlg.destroy)
        self.root.wait_window(dlg)
        for child in words_frame.winfo_children():
            child.configure(text="")
        words.clear()
        phrase = ""
        return result["confirmed"]

    def restore_wallet(self) -> None:
        dlg = tk.Toplevel(self.root)
        dlg.title("Restore QZXB wallet")
        dlg.configure(bg="#FFFFFF")
        dlg.geometry("640x310")
        dlg.resizable(False, False)
        dlg.transient(self.root)
        dlg.grab_set()

        tk.Label(dlg, text="Restore from 12 words", bg="#FFFFFF", fg="#172033",
                 font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=22, pady=(20, 5))
        tk.Label(dlg, text="The phrase is processed locally and sent to the wallet engine via standard input, never as command-line text.",
                 bg="#FFFFFF", fg="#44546A", font=("Segoe UI", 9), wraplength=590,
                 justify="left").pack(anchor="w", padx=22, pady=(0, 12))
        phrase_var = tk.StringVar()
        phrase_entry = ttk.Entry(dlg, textvariable=phrase_var, show="•")
        phrase_entry.pack(fill="x", padx=22, ipady=6)
        phrase_entry.focus_set()

        dest_var = tk.StringVar(value=str(self.home / "wallet-restored.qzw1"))
        dest_row = tk.Frame(dlg, bg="#FFFFFF")
        dest_row.pack(fill="x", padx=22, pady=14)
        ttk.Entry(dest_row, textvariable=dest_var).pack(side="left", fill="x", expand=True, ipady=5)
        def browse() -> None:
            destination = filedialog.asksaveasfilename(
                parent=dlg, initialdir=str(self.home), initialfile="wallet-restored.qzw1",
                defaultextension=".qzw1", filetypes=[("QZXB wallet", "*.qzw1")])
            if destination:
                dest_var.set(destination)
        ttk.Button(dest_row, text="Browse…", style="Secondary.TButton", command=browse).pack(side="left", padx=(8, 0))

        status = tk.StringVar(value="A valid BIP39 checksum is required.")
        tk.Label(dlg, textvariable=status, bg="#FFFFFF", fg="#526175",
                 font=("Segoe UI", 9)).pack(anchor="w", padx=22)
        def do_restore() -> None:
            destination = Path(dest_var.get().strip())
            phrase = phrase_var.get().strip()
            if not destination.is_absolute():
                messagebox.showwarning("Restore wallet", "Choose an absolute wallet-file path.", parent=dlg); return
            if destination.exists():
                messagebox.showwarning("Restore wallet", "That file already exists; choose a new destination. Existing wallets are never overwritten.", parent=dlg); return
            if len(phrase.split()) != 12:
                messagebox.showwarning("Restore wallet", "Enter exactly 12 English recovery words.", parent=dlg); return
            restore_button.configure(state="disabled")
            try:
                response = self.run_engine(["restore", "--output", str(destination)], secret_input=phrase)
                phrase_var.set("")
                phrase = ""
                if response.returncode != 0:
                    status.set("Restore failed. Check spelling and the phrase checksum.")
                    messagebox.showerror("Restore wallet", (response.stderr + "\n" + response.stdout).strip(), parent=dlg)
                    return
                self.wallet_path = destination
                self.save_active_path()
                result_box["ok"] = True
                dlg.destroy()
            except Exception as exc:
                phrase_var.set("")
                messagebox.showerror("Restore wallet", str(exc), parent=dlg)
            finally:
                restore_button.configure(state="normal")
        button_row = tk.Frame(dlg, bg="#FFFFFF")
        button_row.pack(fill="x", padx=22, pady=(10, 20))
        restore_button = ttk.Button(button_row, text="Restore wallet", style="Primary.TButton", command=do_restore)
        restore_button.pack(side="right")
        result_box = {"ok": False}
        dlg.protocol("WM_DELETE_WINDOW", lambda: (phrase_var.set(""), dlg.destroy()))
        self.root.wait_window(dlg)
        phrase_var.set("")
        self.refresh_wallet()
        if result_box["ok"]:
            messagebox.showinfo("QZXB Wallet", "Wallet restored and protected for this Windows user. No recovery phrase was saved in the wallet file.")

    def copy_account(self) -> None:
        value = self.account_var.get().strip()
        if value:
            self.root.clipboard_clear()
            self.root.clipboard_append(value)
            self.status_var.set("Public account ID copied. The recovery phrase was not copied.")
            self.status_label.configure(fg=GOOD)

    def open_folder(self) -> None:
        self.wallet_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(str(self.wallet_path.parent))
        except Exception as exc:
            messagebox.showerror("Open folder", str(exc))

    def run(self) -> None:
        self.root.mainloop()


def self_test() -> int:
    engine, home, _ = wallet_paths()
    if not engine.is_file():
        print("WALLET_ENGINE=missing")
        return 2
    print("WALLET_ENGINE=present")
    print("TKINTER=available")
    print("MNEMONIC_ENGINE=external_qzxb_wallet")
    print("NETWORK_STATUS=mainnet_not_launched")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(self_test())
    if os.name != "nt":
        print("QZXB Wallet requires Windows DPAPI.")
        raise SystemExit(2)
    QZXBWalletApp().run()
