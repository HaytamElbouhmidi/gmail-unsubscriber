"""Durable per-account scan checkpoints and unsubscribe delivery ledger.

Version 3.1.2. No credentials or message bodies are stored.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


def _native_legacy_state(path: Path) -> str:
    """Ask Windows PowerShell when packaged Python cannot inspect a legacy path.

    Keep the filename on standard input, never in PowerShell source. This probe
    must return a definite absent/present result or the caller fails closed.
    """
    import subprocess

    script = r"""
$path = [Console]::In.ReadToEnd().Trim()
try {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item -is [System.IO.FileInfo]) {
        Write-Output 'FILE'
    }
    else {
        Write-Output 'OTHER'
    }
}
catch {
    if ($_.Exception -is [System.Management.Automation.ItemNotFoundException] -or
            $_.FullyQualifiedErrorId -match 'PathNotFound|ItemNotFound') {
        Write-Output 'MISSING'
    }
    else {
        Write-Output 'UNKNOWN'
    }
}
"""
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            input=str(path), capture_output=True, text=True, timeout=12,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False
        )
    except (OSError, subprocess.SubprocessError):
        return "UNKNOWN"
    state = result.stdout.strip()
    return state if result.returncode == 0 and state in {"FILE", "MISSING", "OTHER"} else "UNKNOWN"


def history_path() -> Path:
    """Use the user profile on Windows without losing an existing AppData ledger.

    Microsoft Store Python can redirect writes under AppData. A profile-local
    directory works for standard installations. If an older database exists,
    keep using it to preserve prior submissions and resume checkpoints.
    """
    if sys.platform == "win32":
        legacy = (Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
                  / "gmail-unsubscriber" / "progress.sqlite3")
        profile = Path.home() / ".gmail-unsubscriber" / "progress.sqlite3"
        try:
            if legacy.exists():
                return legacy
        except PermissionError as exc:
            # Store Python sometimes reports WinError 5 for a missing AppData
            # path. Never discard a real legacy ledger on an ambiguous result.
            state = _native_legacy_state(legacy)
            if state == "FILE":
                return legacy
            if state == "MISSING":
                return profile
            raise PermissionError(
                f"Cannot safely determine whether the legacy scan-history file exists at {legacy}. "
                "Windows PowerShell could not confirm its absence. Do not delete or replace saved history."
            ) from exc
        return profile
    base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    return base / "gmail-unsubscriber" / "progress.sqlite3"


def account_key(account: str) -> str:
    return hashlib.sha256(account.strip().casefold().encode("utf-8")).hexdigest()


def encode(value: Any) -> str:
    return json.dumps(asdict(value), default=lambda item: item.isoformat() if isinstance(item, datetime) else str(item),
                      ensure_ascii=False, separators=(",", ":"))


def decode_candidate(value: str) -> Any:
    from gmail_unsubscriber import Candidate, Target
    data = json.loads(value)
    data["targets"] = tuple(Target(**target) for target in data["targets"])
    if data["sent_at"]:
        data["sent_at"] = datetime.fromisoformat(data["sent_at"])
    return Candidate(**data)


def decode_message(value: str) -> Any:
    from gmail_unsubscriber import MessageInfo
    data = json.loads(value)
    if data["sent_at"]:
        data["sent_at"] = datetime.fromisoformat(data["sent_at"])
    return MessageInfo(**data)


def decode_result(value: str) -> Any:
    from gmail_unsubscriber import Result
    data = json.loads(value)
    data["candidate"] = decode_candidate(json.dumps(data["candidate"]))
    return Result(**data)


class HistoryStore:
    """Each thread owns a connection. Every change is committed before the next message."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path if path is not None else history_path()).expanduser()
        self.db: sqlite3.Connection | None = None
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if self.path.is_dir():
                raise IsADirectoryError("The database filename is a folder, not a SQLite file.")
            if os.name != "nt":
                self.path.parent.chmod(0o700)
            self.db = sqlite3.connect(self.path, timeout=30)
            if os.name != "nt":
                self.path.chmod(0o600)
            self.db.execute("PRAGMA busy_timeout = 30000")
            self.db.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY, account TEXT NOT NULL, settings TEXT NOT NULL,
                mailboxes TEXT NOT NULL, stats TEXT NOT NULL, state TEXT NOT NULL,
                created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS run_lookup ON runs(account, settings, state);
            CREATE TABLE IF NOT EXISTS scanned (
                run_id INTEGER NOT NULL, folder TEXT NOT NULL, uid TEXT NOT NULL,
                message TEXT, candidate TEXT, unreadable INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(run_id, folder, uid)
            );
            CREATE TABLE IF NOT EXISTS seen (
                run_id INTEGER NOT NULL, key TEXT NOT NULL,
                PRIMARY KEY(run_id, key)
            );
            CREATE TABLE IF NOT EXISTS outcomes (
                id INTEGER PRIMARY KEY, account TEXT NOT NULL, run_id INTEGER,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ledger (
                account TEXT NOT NULL, method TEXT NOT NULL, target TEXT NOT NULL,
                status TEXT NOT NULL, PRIMARY KEY(account, method, target)
            );
            """)
            self.db.commit()
        except (OSError, sqlite3.DatabaseError) as exc:
            if self.db is not None:
                self.db.close()
            raise sqlite3.OperationalError(
                f"Cannot access the scan-history database at {self.path}. "
                f"{type(exc).__name__}: {exc}. "
                "Check that the folder is writable and the file is not a directory. "
                "Existing progress and request history have not been deleted."
            ) from exc

    def __enter__(self) -> HistoryStore:
        return self

    def __exit__(self, *_: Any) -> None:
        self.db.close()

    def latest_incomplete(self, account: str, settings: dict[str, Any]) -> tuple[int, list[dict], dict] | None:
        row = self.db.execute(
            "SELECT id, mailboxes, stats FROM runs WHERE account=? AND settings=? "
            "AND state IN ('running','interrupted') ORDER BY id DESC LIMIT 1",
            (account_key(account), json.dumps(settings, sort_keys=True))
        ).fetchone()
        if row is None:
            return None
        return row[0], json.loads(row[1]), json.loads(row[2])

    def new_run(self, account: str, settings: dict[str, Any], mailboxes: list[dict], stats: dict) -> int:
        with self.db:
            cur = self.db.execute(
                "INSERT INTO runs(account, settings, mailboxes, stats, state) VALUES(?,?,?,?, 'running')",
                (account_key(account), json.dumps(settings, sort_keys=True),
                 json.dumps(mailboxes, separators=(",", ":")), json.dumps(stats),)
            )
        return int(cur.lastrowid)

    def state(self, run_id: int, status: str) -> None:
        if status not in {"running", "interrupted", "complete"}:
            raise ValueError("Unsupported run state")
        with self.db:
            self.db.execute("UPDATE runs SET state=? WHERE id=?", (status, run_id))

    def checkpoints(self, run_id: int) -> dict[tuple[str, str], tuple[Any, Any, bool]]:
        items = {}
        for folder, uid, message, candidate, unreadable in self.db.execute(
            "SELECT folder, uid, message, candidate, unreadable FROM scanned WHERE run_id=?", (run_id,)
        ):
            items[folder, uid] = (decode_message(message) if message else None,
                                  decode_candidate(candidate) if candidate else None, bool(unreadable))
        return items

    def seen_keys(self, run_id: int) -> set[str]:
        return {row[0] for row in self.db.execute("SELECT key FROM seen WHERE run_id=?", (run_id,))}

    def outcomes(self, run_id: int) -> list[Any]:
        return [decode_result(row[0]) for row in self.db.execute(
            "SELECT payload FROM outcomes WHERE run_id=? ORDER BY id", (run_id,))]

    def checkpoint(self, run_id: int, folder: str, uid: str, message: Any,
                   candidate: Any, unreadable: bool, stats: dict, seen: bool = False) -> None:
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO scanned(run_id,folder,uid,message,candidate,unreadable) VALUES(?,?,?,?,?,?)",
                (run_id, folder, uid, encode(message) if message else None,
                 encode(candidate) if candidate else None, int(unreadable))
            )
            if seen and candidate is not None:
                self.db.execute("INSERT OR IGNORE INTO seen(run_id,key) VALUES(?,?)", (run_id, candidate.key))
            self.db.execute("UPDATE runs SET stats=? WHERE id=?", (json.dumps(stats), run_id))

    def record_result(self, account: str, run_id: int | None, result: Any) -> None:
        with self.db:
            self.db.execute("INSERT INTO outcomes(account,run_id,payload) VALUES(?,?,?)",
                            (account_key(account), run_id, encode(result)))

    def load_ledger(self, account: str) -> dict[tuple[str, str, str], str]:
        return {(account.casefold(), kind, target): status for kind, target, status in self.db.execute(
            "SELECT method,target,status FROM ledger WHERE account=?", (account_key(account),))}

    @staticmethod
    def _keys(account: str, candidate: Any, target: Any) -> list[tuple[str, str, str]]:
        from gmail_unsubscriber import subscription_key
        keys = [(account.casefold(), target.method, target.uri),
                (account.casefold(), "ENTRY", candidate.key)]
        group = subscription_key(candidate)
        if group:
            keys.append((account.casefold(), "LIST", group))
        return keys

    def reserve(self, account: str, candidate: Any, target: Any,
                ledger: dict[tuple[str, str, str], str]) -> None:
        """Reserve before network I/O. A crash cannot cause an automatic resend."""
        keys = self._keys(account, candidate, target)
        with self.db:
            for key in keys:
                if key not in ledger:
                    ledger[key] = "Outcome unknown"
                    self.db.execute(
                        "INSERT OR REPLACE INTO ledger(account,method,target,status) VALUES(?,?,?,?)",
                        (account_key(account), key[1], key[2], ledger[key])
                    )

    def finalize(self, account: str, candidate: Any, target: Any, status: str,
                 ledger: dict[tuple[str, str, str], str]) -> None:
        from gmail_unsubscriber import SUCCESS_STATUSES, UNCERTAIN_STATUSES
        keys = self._keys(account, candidate, target)
        with self.db:
            for key in keys:
                if status in SUCCESS_STATUSES | UNCERTAIN_STATUSES:
                    ledger[key] = status
                    self.db.execute("INSERT OR REPLACE INTO ledger(account,method,target,status) VALUES(?,?,?,?)",
                                    (account_key(account), key[1], key[2], status))
                elif ledger.get(key) == "Outcome unknown":
                    ledger.pop(key, None)
                    self.db.execute("DELETE FROM ledger WHERE account=? AND method=? AND target=?",
                                    (account_key(account), key[1], key[2]))

    def clear_account(self, account: str) -> None:
        """Remove checkpoints and delivery history only after explicit user confirmation."""
        account_id = account_key(account)
        with self.db:
            ids = [row[0] for row in self.db.execute("SELECT id FROM runs WHERE account=?", (account_id,))]
            for run_id in ids:
                self.db.execute("DELETE FROM scanned WHERE run_id=?", (run_id,))
                self.db.execute("DELETE FROM seen WHERE run_id=?", (run_id,))
            self.db.execute("DELETE FROM runs WHERE account=?", (account_id,))
            self.db.execute("DELETE FROM outcomes WHERE account=?", (account_id,))
            self.db.execute("DELETE FROM ledger WHERE account=?", (account_id,))
