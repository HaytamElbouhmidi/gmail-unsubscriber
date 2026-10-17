"""Regression tests for profile-local database storage and legacy history safety.

Version 1.0.2. Tests use temporary directories, with no Gmail access.
"""
from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scan_history as history


class HistoryStorageTests(unittest.TestCase):
    def windows_paths(self, home: Path):
        local = home / "AppData" / "Local"
        return (patch.object(history.sys, "platform", "win32"),
                patch.object(history.Path, "home", return_value=home),
                patch.dict(os.environ, {"LOCALAPPDATA": str(local)}))

    def test_new_windows_store_uses_user_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "user"
            home.mkdir()
            path_patch, home_patch, env_patch = self.windows_paths(home)
            with path_patch, home_patch, env_patch:
                wanted = home / ".gmail-unsubscriber" / "progress.sqlite3"
                self.assertEqual(history.history_path(), wanted)
                with history.HistoryStore() as store:
                    self.assertEqual(store.path, wanted)
                    self.assertEqual(store.db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertTrue(wanted.is_file())
                self.assertFalse((home / "AppData" / "Local" / "gmail-unsubscriber" /
                                  "progress.sqlite3").exists())

    def test_existing_appdata_database_and_ledger_remain_in_use(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "user"
            home.mkdir()
            old_path = home / "AppData" / "Local" / "gmail-unsubscriber" / "progress.sqlite3"
            old_path.parent.mkdir(parents=True)
            db = sqlite3.connect(old_path)
            try:
                with db:
                    db.execute("CREATE TABLE legacy_data (value TEXT)")
                    db.execute("INSERT INTO legacy_data VALUES ('keep saved progress')")
            finally:
                db.close()
            path_patch, home_patch, env_patch = self.windows_paths(home)
            with path_patch, home_patch, env_patch:
                self.assertEqual(history.history_path(), old_path)
                with history.HistoryStore() as store:
                    self.assertEqual(store.path, old_path)
                    self.assertEqual(store.db.execute("SELECT value FROM legacy_data").fetchone()[0],
                                     "keep saved progress")
            self.assertFalse((home / ".gmail-unsubscriber" / "progress.sqlite3").exists())

    def test_store_python_permission_error_with_confirmed_absent_legacy(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "user"
            home.mkdir()
            path_patch, home_patch, env_patch = self.windows_paths(home)
            with path_patch, home_patch, env_patch, patch.object(
                    history.Path, "exists", side_effect=PermissionError("WinError 5")), patch.object(
                    history, "_native_legacy_state", return_value="MISSING") as native:
                wanted = home / ".gmail-unsubscriber" / "progress.sqlite3"
                self.assertEqual(history.history_path(), wanted)
                native.assert_called_once_with(home / "AppData" / "Local" /
                                               "gmail-unsubscriber" / "progress.sqlite3")

    def test_store_python_permission_error_with_confirmed_existing_legacy(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "user"
            home.mkdir()
            path_patch, home_patch, env_patch = self.windows_paths(home)
            with path_patch, home_patch, env_patch, patch.object(
                    history.Path, "exists", side_effect=PermissionError("WinError 5")), patch.object(
                    history, "_native_legacy_state", return_value="FILE"):
                self.assertEqual(history.history_path(), home / "AppData" / "Local" /
                                 "gmail-unsubscriber" / "progress.sqlite3")

    def test_store_python_permission_error_is_not_ignored_when_ambiguous(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "user"
            home.mkdir()
            path_patch, home_patch, env_patch = self.windows_paths(home)
            with path_patch, home_patch, env_patch, patch.object(
                    history.Path, "exists", side_effect=PermissionError("WinError 5")), patch.object(
                    history, "_native_legacy_state", return_value="UNKNOWN"):
                with self.assertRaisesRegex(PermissionError, "Cannot safely determine"):
                    history.history_path()
            self.assertFalse((home / ".gmail-unsubscriber").exists())

    def test_native_probe_handles_powershell_status_without_embedding_path_in_script(self):
        import subprocess
        from types import SimpleNamespace
        filename = Path(r"C:\Users\Some Name\AppData\Local\gmail-unsubscriber\progress.sqlite3")
        for message, expected in (("FILE\n", "FILE"), ("MISSING\n", "MISSING"),
                                  ("OTHER\n", "OTHER"), ("UNKNOWN\n", "UNKNOWN")):
            with self.subTest(message=message), patch.object(subprocess, "run", return_value=SimpleNamespace(
                    stdout=message, returncode=0)) as run:
                self.assertEqual(history._native_legacy_state(filename), expected)
                command = run.call_args.args[0]
                self.assertEqual(command[0], "powershell.exe")
                self.assertEqual(run.call_args.kwargs["input"], str(filename))
                self.assertNotIn(str(filename), command[-1])

    def test_native_probe_fails_closed_when_powershell_does_not_complete(self):
        import subprocess
        from types import SimpleNamespace
        filename = Path(r"C:\Users\hayta\AppData\Local\gmail-unsubscriber\progress.sqlite3")
        with patch.object(subprocess, "run", return_value=SimpleNamespace(
                stdout="MISSING", returncode=1)):
            self.assertEqual(history._native_legacy_state(filename), "UNKNOWN")
        with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired("powershell.exe", 12)):
            self.assertEqual(history._native_legacy_state(filename), "UNKNOWN")

    def test_existing_directory_instead_of_db_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "progress.sqlite3"
            path.mkdir()
            with self.assertRaises(sqlite3.OperationalError) as ctx:
                history.HistoryStore(path)
            self.assertIn(str(path), str(ctx.exception))
            self.assertIn("not a SQLite file", str(ctx.exception))
            self.assertTrue(path.is_dir())

    def test_unopenable_legacy_state_is_not_silently_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "user"
            home.mkdir()
            old_path = home / "AppData" / "Local" / "gmail-unsubscriber" / "progress.sqlite3"
            old_path.parent.mkdir(parents=True)
            old_path.write_bytes(b"previous scan history")
            path_patch, home_patch, env_patch = self.windows_paths(home)
            with path_patch, home_patch, env_patch, patch.object(
                    history.sqlite3, "connect", side_effect=sqlite3.OperationalError("unable to open database file")):
                with self.assertRaises(sqlite3.OperationalError) as ctx:
                    history.HistoryStore()
                self.assertIn(str(old_path), str(ctx.exception))
                self.assertIn("Existing progress", str(ctx.exception))
            self.assertEqual(old_path.read_bytes(), b"previous scan history")
            self.assertFalse((home / ".gmail-unsubscriber" / "progress.sqlite3").exists())

    def test_offline_suite_uses_a_separate_database_for_each_case(self):
        from test_gmail_unsubscriber import OfflineCase
        files = []
        for _ in range(2):
            case = OfflineCase()
            case.setUp()
            try:
                location = history.history_path()
                self.assertEqual(location, Path(os.environ["LOCALAPPDATA"]) / "progress.sqlite3")
                with history.HistoryStore() as store:
                    self.assertEqual(store.path, location)
                    with store.db:
                        store.db.execute("CREATE TABLE harness_probe (marker TEXT)")
                files.append(location)
            finally:
                case.doCleanups()
        self.assertNotEqual(files[0], files[1])
        self.assertFalse(files[0].exists())
        self.assertFalse(files[1].exists())

    def test_explicit_path_and_linux_location_remain_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            location = Path(directory)
            explicit = location / "custom" / "records.sqlite3"
            with history.HistoryStore(explicit) as store:
                self.assertEqual(store.path, explicit)
                self.assertEqual(len(store.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()), 5)
            with patch.object(history.sys, "platform", "linux"), patch.dict(
                    os.environ, {"XDG_STATE_HOME": str(location / "state")}), patch.object(
                    history.Path, "home", return_value=location):
                self.assertEqual(history.history_path(), location / "state" / "gmail-unsubscriber" /
                                 "progress.sqlite3")


if __name__ == "__main__":
    unittest.main()
