#!/usr/bin/env python3
"""Check the two Windows scan-history locations without changing saved records.

Diagnostic version 1.0.1. No Gmail login or network calls are made.
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from pathlib import Path

from scan_history import history_path


def check_folder(label: str, filename: Path, *, create: bool = False) -> bool:
    print(f"\n{label}: {filename}")
    try:
        print(f"Database exists: {filename.exists()}")
        if filename.is_dir():
            print("ERROR: The database filename is a directory.")
            return False
        if filename.parent.is_dir():
            print("Parent directory exists: yes")
        elif create:
            filename.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            print("Parent directory created for testing")
        else:
            print("Parent directory exists: no. There is no saved database here.")
            return True
        probe = None
        try:
            with tempfile.NamedTemporaryFile(prefix=".sqlite-test-", suffix=".db",
                                             dir=filename.parent, delete=False) as handle:
                probe = Path(handle.name)
            conn = sqlite3.connect(probe, timeout=5)
            try:
                with conn:
                    conn.execute("CREATE TABLE check_write (value INTEGER)")
                    conn.execute("INSERT INTO check_write VALUES (1)")
            finally:
                conn.close()
            print("SQLite write test: PASS")
            return True
        finally:
            if probe is not None:
                probe.unlink(missing_ok=True)
    except (OSError, sqlite3.DatabaseError) as exc:
        print(f"SQLite write test: FAIL. {type(exc).__name__}: {exc}")
        return False


def main() -> None:
    print("Gmail Unsubscriber v3.1.2 | Scan-history storage diagnostic")
    print(f"Python interpreter: {sys.executable}")
    print(f"User profile: {Path.home()}")
    print(f"LOCALAPPDATA: {os.environ.get('LOCALAPPDATA', '(not set)')}")
    selected = history_path()
    print(f"Selected database: {selected}")
    if sys.platform == "win32":
        home = Path.home()
        old = (Path(os.environ.get("LOCALAPPDATA") or home / "AppData" / "Local") /
               "gmail-unsubscriber" / "progress.sqlite3")
        current = home / ".gmail-unsubscriber" / "progress.sqlite3"
        if selected == old:
            if not check_folder("Existing AppData location", old):
                raise SystemExit(1)
        else:
            print(f"\nLegacy AppData database not selected: {old}")
            print("No legacy file was found by the permitted Windows path check.")
            if not check_folder("User-profile location", current, create=True):
                raise SystemExit(1)
    else:
        if not check_folder("Current state location", selected, create=True):
            raise SystemExit(1)
    print("\nThis diagnostic does not access Gmail, read existing records, or remove progress.")


if __name__ == "__main__":
    main()
