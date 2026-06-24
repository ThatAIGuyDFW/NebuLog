"""First-run setup wizard (tkinter GUI).

Collects:
  - Admin password for the embedded PostgreSQL database
  - Optional Azure AD credentials (can be skipped for local-only mode)

Writes DATA_DIR/.env on completion.
"""

from __future__ import annotations

import secrets
import string
import tkinter as tk
from tkinter import messagebox, ttk
from typing import NamedTuple

from launcher.config import (
    ENV_FILE, DATA_DIR, API_PORT, INGEST_UDP_PORT,
    INGEST_TCP_PORT, INGEST_API_PORT, REDIS_PORT, PG_PORT,
    PG_USER, PG_DB, UI_DIST_DIR, VERSION,
)


class SetupResult(NamedTuple):
    db_password: str
    azure_tenant_id: str
    azure_client_id: str
    azure_client_secret: str
    cancelled: bool


def _random_password(length: int = 32) -> str:
    # Use only RFC 3986 "unreserved" characters so the password can be embedded
    # in a DATABASE_URL / DSN without percent-encoding.  Special characters like
    # @ : # % & break asyncpg/SQLAlchemy URL parsing.
    alphabet = string.ascii_letters + string.digits + "-_.~"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def run_wizard() -> SetupResult:
    """Show the setup wizard and return the collected values."""
    root = tk.Tk()
    root.title(f"Sentinel SIEM — First-Time Setup (v{VERSION})")
    root.resizable(False, False)

    # Centre the window
    root.update_idletasks()
    w, h = 520, 520
    x = (root.winfo_screenwidth() - w) // 2
    y = (root.winfo_screenheight() - h) // 2
    root.geometry(f"{w}x{h}+{x}+{y}")

    result: dict = {"cancelled": True}

    # ── Header ──────────────────────────────────────────────────────────────
    header = tk.Frame(root, bg="#1e293b", pady=16)
    header.pack(fill="x")
    tk.Label(
        header, text="⚡ Sentinel SIEM",
        font=("Helvetica", 18, "bold"), fg="white", bg="#1e293b",
    ).pack()
    tk.Label(
        header, text="Initial Configuration",
        font=("Helvetica", 11), fg="#94a3b8", bg="#1e293b",
    ).pack()

    body = tk.Frame(root, padx=24, pady=16)
    body.pack(fill="both", expand=True)

    # ── Section: Database ────────────────────────────────────────────────────
    tk.Label(body, text="Database Password", font=("Helvetica", 11, "bold"),
             anchor="w").pack(fill="x", pady=(8, 2))
    tk.Label(
        body,
        text="A strong password will be auto-generated. You can change it or enter your own.",
        font=("Helvetica", 9), fg="#64748b", wraplength=470, justify="left", anchor="w",
    ).pack(fill="x")

    pw_frame = tk.Frame(body)
    pw_frame.pack(fill="x", pady=(4, 0))

    db_pw_var = tk.StringVar(value=_random_password())
    pw_entry = tk.Entry(pw_frame, textvariable=db_pw_var, show="•", width=38, font=("Courier", 10))
    pw_entry.pack(side="left")

    show_var = tk.BooleanVar(value=False)

    def _toggle_show():
        pw_entry.config(show="" if show_var.get() else "•")

    tk.Checkbutton(pw_frame, text="Show", variable=show_var,
                   command=_toggle_show).pack(side="left", padx=6)

    def _regen():
        db_pw_var.set(_random_password())

    tk.Button(pw_frame, text="↺ Generate", command=_regen,
              font=("Helvetica", 9)).pack(side="left")

    # ── Section: Azure AD (optional) ─────────────────────────────────────────
    ttk.Separator(body, orient="horizontal").pack(fill="x", pady=14)

    azure_frame = tk.LabelFrame(
        body, text="  Azure AD — Optional (leave blank for local-only mode)  ",
        font=("Helvetica", 10), padx=10, pady=8,
    )
    azure_frame.pack(fill="x")

    fields: dict[str, tk.StringVar] = {}
    azure_fields = [
        ("Tenant ID", "AZURE_TENANT_ID"),
        ("Client ID", "AZURE_CLIENT_ID"),
        ("Client Secret", "AZURE_CLIENT_SECRET"),
    ]
    for label, key in azure_fields:
        row = tk.Frame(azure_frame)
        row.pack(fill="x", pady=2)
        tk.Label(row, text=f"{label}:", width=14, anchor="w",
                 font=("Helvetica", 9)).pack(side="left")
        var = tk.StringVar()
        fields[key] = var
        show = key != "AZURE_CLIENT_SECRET"
        e = tk.Entry(row, textvariable=var,
                     show="" if show else "•", width=38, font=("Courier", 9))
        e.pack(side="left")

    # ── Info banner ──────────────────────────────────────────────────────────
    ttk.Separator(body, orient="horizontal").pack(fill="x", pady=14)
    info = (
        f"Dashboard → http://localhost:{API_PORT}   "
        f"API → http://localhost:{API_PORT}/docs\n"
        f"Syslog UDP :{INGEST_UDP_PORT}   "
        f"Syslog TLS TCP :{INGEST_TCP_PORT}   "
        f"Agent HTTP :{INGEST_API_PORT}"
    )
    tk.Label(body, text=info, font=("Courier", 8), fg="#475569",
             justify="left", anchor="w").pack(fill="x")

    # ── Buttons ──────────────────────────────────────────────────────────────
    btn_frame = tk.Frame(root, pady=12)
    btn_frame.pack(fill="x", padx=24)

    def _cancel():
        result["cancelled"] = True
        root.destroy()

    def _finish():
        pw = db_pw_var.get().strip()
        if len(pw) < 8:
            messagebox.showerror("Invalid password",
                                 "Database password must be at least 8 characters.")
            return
        result.update(
            db_password=pw,
            azure_tenant_id=fields["AZURE_TENANT_ID"].get().strip(),
            azure_client_id=fields["AZURE_CLIENT_ID"].get().strip(),
            azure_client_secret=fields["AZURE_CLIENT_SECRET"].get().strip(),
            cancelled=False,
        )
        root.destroy()

    tk.Button(btn_frame, text="Cancel", command=_cancel,
              width=10, font=("Helvetica", 10)).pack(side="right", padx=(6, 0))
    tk.Button(btn_frame, text="Install →", command=_finish,
              width=14, font=("Helvetica", 10, "bold"),
              bg="#2563eb", fg="white", activebackground="#1d4ed8",
              activeforeground="white").pack(side="right")

    root.protocol("WM_DELETE_WINDOW", _cancel)
    root.mainloop()

    if result.get("cancelled", True):
        return SetupResult("", "", "", "", cancelled=True)

    return SetupResult(
        db_password=result["db_password"],
        azure_tenant_id=result["azure_tenant_id"],
        azure_client_id=result["azure_client_id"],
        azure_client_secret=result["azure_client_secret"],
        cancelled=False,
    )


def write_env(r: SetupResult) -> None:
    """Write the .env file to DATA_DIR."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    from launcher.embedded_pg import connection_url
    from launcher.embedded_redis import connection_url as redis_url

    db_url = connection_url(r.db_password)
    redis = redis_url()

    ui_path = str(UI_DIST_DIR) if UI_DIST_DIR.exists() else ""

    content = f"""\
# Sentinel SIEM - auto-generated configuration
# Generated by the installer setup wizard.
# Edit this file to change settings, then restart Sentinel.

DATABASE_URL={db_url}
REDIS_URL={redis}

# Azure AD (leave blank to use local dev mode - no login required)
AZURE_TENANT_ID={r.azure_tenant_id}
AZURE_CLIENT_ID={r.azure_client_id}
AZURE_CLIENT_SECRET={r.azure_client_secret}

# Azure Blob Storage (optional - leave blank to archive locally)
AZURE_STORAGE_ACCOUNT=
AZURE_STORAGE_KEY=
AZURE_STORAGE_CONTAINER=sentinel-raw

# Ingest service
INGEST_HOST=0.0.0.0
INGEST_UDP_PORT={INGEST_UDP_PORT}
INGEST_TCP_PORT={INGEST_TCP_PORT}
INGEST_API_PORT={INGEST_API_PORT}
INGEST_NODE_NAME=sentinel-01

# TLS syslog (optional - leave blank to skip TLS listener)
INGEST_TLS_CERT=
INGEST_TLS_KEY=
INGEST_TLS_CA=

# GeoIP (download GeoLite2-City.mmdb from maxmind.com)
GEOIP_DB_PATH=

# API
CORS_ORIGINS=http://localhost:{API_PORT}
LOG_LEVEL=INFO

# Pre-built UI path (set by installer)
UI_DIST_PATH={ui_path}

# Internal - set by the launcher (do not edit)
_SENTINEL_DB_PASSWORD={r.db_password}
"""
    ENV_FILE.write_text(content, encoding="utf-8")
