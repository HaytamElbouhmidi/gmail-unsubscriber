#!/usr/bin/env python3
"""Apply the Gmail Unsubscriber 3.1.0 update to a 3.0 source checkout.

Place this package in the repository root, then run python upgrade_v3_1_0.py.
The original source is backed up and the updated source is syntax checked.
"""
from __future__ import annotations

import hashlib
import os
import py_compile
import shutil
import sys
import tempfile
from pathlib import Path

VERSION = "3.1.0"
BASE_BLOB_SHA = "0f1a2f61c7732a21051f2292064b15cfd8ec9228"
ROOT = Path(__file__).resolve().parent
PARTS = ROOT / "patch_parts"


def patch_source(original: str) -> str:
    source = original

    def replace(old: str, new: str) -> None:
        nonlocal source
        amount = source.count(old)
        if amount != 1:
            raise ValueError(f"Could not safely update source. Expected one match, found {amount}: {old[:85]!r}")
        source = source.replace(old, new, 1)

    def span(start: str, end: str, contents: str) -> None:
        nonlocal source
        if source.count(start) != 1 or source.count(end) != 1:
            raise ValueError(f"Could not find unique update boundaries: {start!r}, {end!r}")
        a, b = source.index(start), source.index(end)
        if b <= a:
            raise ValueError(f"Invalid source order for {start!r}")
        source = source[:a] + contents.rstrip() + "\n\n\n" + source[b:]

    def part(name: str) -> str:
        return (PARTS / name).read_text(encoding="utf-8")

    replace("from contextlib import contextmanager\n", "from contextlib import ExitStack, contextmanager\n")
    replace("from urllib.parse import unquote, urlsplit, urlunsplit\n",
            "from urllib.parse import unquote, urlsplit, urlunsplit\nfrom scan_history import HistoryStore\n")
    replace('POST_BODY = POST_VALUE.encode("ascii")\n',
            'POST_BODY = POST_VALUE.encode("ascii")\nAPP_VERSION = "3.1.0"\n')
    replace('"User-Agent": "Gmail-Auto-Unsubscriber/3.0",',
            '"User-Agent": f"Gmail-Auto-Unsubscriber/{APP_VERSION}",')
    replace('    sent_at: datetime | None = None\n\n    @property\n    def key(self) -> str:',
            '    sent_at: datetime | None = None\n    folder: str = "INBOX"\n\n    @property\n    def key(self) -> str:')

    gmail_name = '''def spam_mailbox_name(mail: Any, guard: NetworkGuard) -> str:
    """Prefer the Gmail IMAP mailbox flagged as Junk to a localized name."""
    with guard.operation():
        status, data = mail.list()
        require_ok(status, "Discover Spam folder", data)
    for item in data or ():
        if not isinstance(item, bytes):
            continue
        match = re.match(rb"\\(([^)]*)\\)\\s+\\S+\\s+(.+)$", item)
        if not match or b"\\\\junk" not in match.group(1).lower():
            continue
        raw = match.group(2).strip()
        if raw.startswith(b'"') and raw.endswith(b'"'):
            raw = raw[1:-1].replace(b'\\\\"', b'"').replace(b'\\\\\\\\', b'\\\\')
        try:
            return raw.decode("ascii")
        except UnicodeError:
            break
    return "[Gmail]/Spam"


'''
    replace('@contextmanager\ndef gmail_inbox(account: str, password: str, guard: NetworkGuard) -> Iterator[tuple[Any, str]]:',
            gmail_name + '@contextmanager\ndef gmail_inbox(account: str, password: str, guard: NetworkGuard,\n'
            '                *, folder: str = "INBOX") -> Iterator[tuple[Any, str]]:')
    replace('            status, data = mail.select("INBOX", readonly=True)\n'
            '            require_ok(status, "Read-only INBOX selection", data)',
            '            mailbox = "INBOX" if folder == "INBOX" else spam_mailbox_name(mail, guard)\n'
            '            status, data = mail.select(mailbox, readonly=True)\n'
            '            require_ok(status, f"Read-only {folder} selection", data)')
    span('def parse_candidate(', 'def scan_mailbox(', part('parse_candidate.py'))

    replace('def execute_candidate(candidate: Candidate, account: str, password: str, guard: NetworkGuard,\n'
            '                      fetch_raw: Callable[[Candidate], bytes], attempted: set[tuple[str, str]],\n'
            '                      ledger: dict[tuple[str, str, str], str], emit: Callable[[str, Any], None]) -> None:',
            'def execute_candidate(candidate: Candidate, account: str, password: str, guard: NetworkGuard,\n'
            '                      fetch_raw: Callable[[Candidate], bytes], attempted: set[tuple[str, str]],\n'
            '                      ledger: dict[tuple[str, str, str], str], emit: Callable[[str, Any], None],\n'
            '                      *, before_send: Callable[[Candidate, Target], None] | None = None,\n'
            '                      after_send: Callable[[Candidate, Target, str], None] | None = None) -> None:')
    replace('        guard.check()\n        attempted.add(target_key)\n'
            '        emit("activity", f"Sending {\'one-click request\' if target.method == \'POST\' else \'unsubscribe email\'} for {candidate.sender_name}...")',
            '        guard.check()\n        if before_send is not None:\n            before_send(candidate, target)\n'
            '        attempted.add(target_key)\n'
            '        method_label = "one-click request" if target.method == "POST" else "unsubscribe request email"\n'
            '        emit("activity", f"Sending {method_label} for {candidate.sender_name}...")')
    replace('        record(target, status, detail)\n        if status in SUCCESS_STATUSES | UNCERTAIN_STATUSES:\n'
            '            ledger[ledger_key] = status\n            ledger[entry_key] = status',
            '        if status in SUCCESS_STATUSES | UNCERTAIN_STATUSES:\n'
            '            ledger[ledger_key] = status\n            ledger[entry_key] = status\n'
            '        if after_send is not None:\n            after_send(candidate, target, status)\n'
            '        record(target, status, detail)\n        if status in SUCCESS_STATUSES | UNCERTAIN_STATUSES:')

    span('def process_selected(', 'class RecoveringInbox:', part('process_selected.py'))
    replace('def __init__(self, account: str, password: str, guard: NetworkGuard,\n'
            '                 emit: Callable[[str, Any], None]) -> None:\n'
            '        self.account, self.password, self.guard, self.emit = account, password, guard, emit',
            'def __init__(self, account: str, password: str, guard: NetworkGuard,\n'
            '                 emit: Callable[[str, Any], None], folder: str = "INBOX") -> None:\n'
            '        self.account, self.password, self.guard, self.emit = account, password, guard, emit\n'
            '        self.folder = folder')
    replace('        context = gmail_inbox(self.account, self.password, self.guard)',
            '        context = (gmail_inbox(self.account, self.password, self.guard) if self.folder == "INBOX"\n'
            '                   else gmail_inbox(self.account, self.password, self.guard, folder=self.folder))')
    replace('            raise StaleScanError("INBOX UIDVALIDITY changed after reconnecting. Stopped to avoid processing the wrong messages.")',
            '            raise StaleScanError(f"{self.folder} UIDVALIDITY changed. Start a fresh scan to avoid mismatched UIDs.")')
    replace('        return self.read("List INBOX messages", search)',
            '        return self.read(f"List {self.folder} messages", search)')
    replace('            raise StaleScanError("Candidate does not belong to the current INBOX generation.")',
            '            raise StaleScanError(f"Candidate does not belong to the current {self.folder} generation.")')
    span('def scan_and_unsubscribe(', 'def csv_text(', part('scan_and_unsubscribe.py'))

    replace('    sent_at: datetime | None\n\n    @property\n    def sender_key(self) -> str:',
            '    sent_at: datetime | None\n    folder: str = "INBOX"\n\n    @property\n    def sender_key(self) -> str:')
    replace('        identity = self.sender_email.casefold() or f"unknown:{self.uid}"',
            '        identity = self.sender_email.casefold() or f"unknown:{self.folder}:{self.uid}"')
    replace('def parse_message_info(raw: bytes, uid: str) -> MessageInfo:',
            'def parse_message_info(raw: bytes, uid: str, *, folder: str = "INBOX") -> MessageInfo:')
    replace('                       parse_sent_date(message))\n\n\ndef candidate_info',
            '                        parse_sent_date(message), folder)\n\n\ndef candidate_info')
    replace('                       candidate.subject, candidate.sent_at)',
            '                        candidate.subject, candidate.sent_at, candidate.folder)')
    replace('        self.message_uids.add(info.uid)',
            '        self.message_uids.add(f"{info.folder}:{info.uid}")')
    replace('        self.entries[f"{candidate.validity}:{candidate.uid}"] = candidate',
            '        self.entries[f"{candidate.folder}:{candidate.validity}:{candidate.uid}"] = candidate')
    sort_part = part('sorted_sender_rows.py')
    sort_head, sort_tail = sort_part.split('def sorted_sender_rows', 1)
    span('SORT_CHOICES = ', 'def parse_sent_date(', sort_head)
    span('def sorted_sender_rows(', 'class UnsubscribeApp:', 'def sorted_sender_rows' + sort_tail)

    replace('        self.root.title("Gmail Unsubscriber - Live Progress" + (" - Administrator" if administrator else ""))',
            '        self.root.title(f"Gmail Unsubscriber v{APP_VERSION}" + (" - Administrator" if administrator else ""))')
    replace('        self.scan_account = ""\n', '        self.scan_account = ""\n        self.current_run_id: int | None = None\n')
    old = '''        self.auto_var = tk.BooleanVar(value=False)
        self.auto_cb = ttk.Checkbutton(options, text="Auto unsubscribe while scanning", variable=self.auto_var)
        self.auto_cb.grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=(7, 2))
        self.mode_hint = ttk.Label(options, text="", wraplength=1040)
        self.mode_hint.grid(row=2, column=0, columnspan=3, sticky=tk.W, pady=(0, 6))
        export_row = ttk.Frame(options)
        export_row.grid(row=3, column=0, columnspan=3, sticky=tk.EW)'''
    new = '''        self.auto_var = tk.BooleanVar(value=False)
        self.auto_cb = ttk.Checkbutton(options, text="Auto unsubscribe while scanning", variable=self.auto_var)
        self.auto_cb.grid(row=1, column=0, sticky=tk.W, pady=(7, 2))
        self.spam_var = tk.BooleanVar(value=False)
        self.spam_cb = ttk.Checkbutton(options, text="Include Spam", variable=self.spam_var,
                                       command=self._mode_changed)
        self.spam_cb.grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=(7, 2))
        self.fallback_var = tk.BooleanVar(value=False)
        self.fallback_cb = ttk.Checkbutton(options, text="Email sender if no automatic unsubscribe works",
                                           variable=self.fallback_var, command=self._fallback_changed)
        self.fallback_cb.grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=(2, 2))
        self.resume_var = tk.BooleanVar(value=True)
        self.resume_cb = ttk.Checkbutton(options, text="Resume interrupted scan", variable=self.resume_var)
        self.resume_cb.grid(row=2, column=2, sticky=tk.W, pady=(2, 2))
        self.mode_hint = ttk.Label(options, text="", wraplength=1040)
        self.mode_hint.grid(row=3, column=0, columnspan=3, sticky=tk.W, pady=(0, 6))
        export_row = ttk.Frame(options)
        export_row.grid(row=4, column=0, columnspan=3, sticky=tk.EW)'''
    replace(old, new)
    replace('        self.sort_combo.grid(row=0, column=4)\n',
            '        self.sort_combo.grid(row=0, column=4)\n') if False else None
    replace('        self.sort_direction_btn.grid(row=0, column=5, padx=(5, 0))\n',
            '''        self.sort_direction_btn.grid(row=0, column=5, padx=(5, 0))
        ttk.Label(filters, text="Outcome:").grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        self.outcome_filter_var = tk.StringVar(value="All")
        self.outcome_filter = ttk.Combobox(filters, textvariable=self.outcome_filter_var,
            values=("All", "Successful", "Failed", "Needs attention", "Pending"),
            state="readonly", width=18)
        self.outcome_filter.grid(row=1, column=1, sticky=tk.W, padx=(6, 0), pady=(5, 0))
''')
    replace('        self.tree.heading("checked", command=self.toggle_visible)\n',
            '        self.tree.heading("checked", command=self.toggle_visible)\n'
            '        self.tree.heading("status", command=lambda: self.sort_by_heading("Outcome"))\n')
    replace('        self.search_var.trace_add("write", lambda *_: self.schedule_refresh())\n',
            '        self.search_var.trace_add("write", lambda *_: self.schedule_refresh())\n'
            '        self.outcome_filter_var.trace_add("write", lambda *_: self.schedule_refresh())\n')
    old = '''    def _mode_changed(self) -> None:
        auto = self.auto_var.get()
        if auto:
            self.checked_senders.clear()
        self.mode_hint.configure(text=(
            "On: Start sends requests as lists are found, including unsubscribe emails. No per-sender approval." if auto else
            "Off: scan only. Check senders below, then click Unsubscribe checked."))
        self.start_btn.configure(text="Scan + auto unsubscribe" if auto else "Scan inbox")
        self._dirty_rows.update(self.senders)
        self.schedule_refresh()
        self.update_controls()'''
    new = '''    def _mode_changed(self) -> None:
        auto = self.auto_var.get()
        if auto:
            self.checked_senders.clear()
        hint = ("Auto mode sends requests without per-sender approval." if auto else
                "Scan-only mode lets me review and check senders before sending.")
        if self.fallback_var.get():
            hint += " Plain request emails are sent only for identified lists in INBOX, never Spam."
        if self.spam_var.get() and auto:
            hint += " Spam is scanned for review only."
        self.mode_hint.configure(text=hint)
        self.start_btn.configure(text="Scan + auto unsubscribe" if auto else
                                 "Scan inbox + Spam" if self.spam_var.get() else "Scan inbox")
        self._dirty_rows.update(self.senders)
        self.schedule_refresh()
        self.update_controls()

    def _fallback_changed(self) -> None:
        if self.fallback_var.get() and not messagebox.askyesno(
                "Email fallback", "Send a plain unsubscribe email to the list sender when there is no usable "
                "automated method? This can reveal that your address is active. The app will not send this "
                "fallback to Spam senders or ordinary personal messages.",
                parent=self.root, default=messagebox.NO):
            self.fallback_var.set(False)
        self._mode_changed()'''
    replace(old, new)
    replace('            self.descending_var.set(self._last_sort == "Latest email")',
            '            self.descending_var.set(self._last_sort == "Latest email")') if False else None
    replace('        if self.sort_var.get() == "Latest email":\n            text = "Newest first" if self.descending_var.get() else "Oldest first"\n'
            '        else:\n            text = "Z to A" if self.descending_var.get() else "A to Z"',
            '        if self.sort_var.get() == "Latest email":\n            text = "Newest first" if self.descending_var.get() else "Oldest first"\n'
            '        elif self.sort_var.get() == "Outcome":\n            text = "Success first" if self.descending_var.get() else "Failure first"\n'
            '        else:\n            text = "Z to A" if self.descending_var.get() else "A to Z"')
    replace('        for widget in (self.email_entry, self.pass_entry, self.show_pass_cb, self.auto_cb, self.save_cb,\n'
            '                       self.start_btn, self.connection_btn):',
            '        for widget in (self.email_entry, self.pass_entry, self.show_pass_cb, self.auto_cb, self.save_cb,\n'
            '                       self.spam_cb, self.fallback_cb, self.resume_cb, self.start_btn, self.connection_btn):')
    replace('        if not methods.intersection({"POST", "MAILTO"}):',
            '        if not methods.intersection({"POST", "MAILTO", "REQUEST"}):')
    replace('        rows = [self.senders[key] for key in self._all_tree_keys if self.senders[key].matches(query)]\n'
            '        ordered = sorted_sender_rows(rows, self.sort_var.get(), self.descending_var.get())',
            '        category = self.outcome_filter_var.get()\n'
            '        rows = [self.senders[key] for key in self._all_tree_keys\n'
            '                if self.senders[key].matches(query) and\n'
            '                (category == "All" or outcome_category(self._sender_status(self.senders[key])) == category)]\n'
            '        ordered = sorted_sender_rows(rows, self.sort_var.get(), self.descending_var.get(),\n'
            '                                     status_for=self._sender_status)')
    replace('            if not messagebox.askyesno("Scan entire inbox?",\n'
            '                "Scan every message currently in INBOX?\\n\\nThis can take longer than a limited scan. "\n'
            '                "Archived mail, Spam, and Trash are not included.\\n\\n" + detail,',
            '            if not messagebox.askyesno("Scan all selected folders?",\n'
            '                "Scan every message in INBOX" + (" and Spam" if self.spam_var.get() else "") +\n'
            '                "?\\n\\nArchived mail and Trash are excluded.\\n\\n" + detail,')
    replace('        automatic = bool(self.auto_var.get())\n        if limit == 0:',
            '        automatic = bool(self.auto_var.get())\n'
            '        include_spam = bool(self.spam_var.get())\n'
            '        request_fallback = bool(self.fallback_var.get())\n'
            '        resume = bool(self.resume_var.get())\n'
            '        if limit == 0:')
    replace('        self.active_task = "auto" if automatic else "scan"\n'
            '        self.scan_account = credentials[0]',
            '        self.active_task = "auto" if automatic else "scan"\n'
            '        self.scan_account = credentials[0]\n'
            '        self.current_run_id = None')
    replace('            scan_and_unsubscribe(account, password, amount, guard, self.ledger, emit, automatic=automatic)',
            '            with HistoryStore() as history:\n'
            '                scan_and_unsubscribe(account, password, amount, guard, self.ledger, emit,\n'
            '                                     automatic=automatic, include_spam=include_spam,\n'
            '                                     request_fallback=request_fallback, history=history, resume=resume)')
    replace('        notice += "All distinct mailing lists found for these senders are included. Requests may send email from your account."',
            '        notice += "All distinct lists found for these senders are included. Requests may send email from your account."\n'
            '        if self.fallback_var.get():\n'
            '            notice += " Plain request emails can reveal an active address."')
    replace('            process_selected(selected, account, password, guard, self.ledger, emit)',
            '            with HistoryStore() as history:\n'
            '                process_selected(selected, account, password, guard, self.ledger, emit,\n'
            '                                 history=history, run_id=self.current_run_id)')
    replace('            elif kind == "summary":\n                self.last_summary = payload',
            '            elif kind == "run_id":\n                self.current_run_id = payload\n'
            '            elif kind == "summary":\n                self.last_summary = payload')
    replace('                                      "Already-sent requests cannot be recalled. Unexported results will be lost.",',
            '                                      "Sent requests cannot be recalled. Scan progress and outcomes are saved locally.",')
    return source


def prepare_test_updates() -> dict[Path, str]:
    """Keep the existing offline suite aligned with the extended scan arguments."""
    updated: dict[Path, str] = {}
    launch = ROOT / "test_gui_launcher.py"
    if launch.exists():
        source = launch.read_text(encoding="utf-8")
        before = ("                scan.assert_called_once_with(ACCOUNT, PASSWORD, limit, guard, "
                  "self.gui.ledger, emit, automatic=automatic)")
        after = '''                scan.assert_called_once()
                self.assertEqual(scan.call_args.args,
                                 (ACCOUNT, PASSWORD, limit, guard, self.gui.ledger, emit))
                self.assertEqual(scan.call_args.kwargs["automatic"], automatic)
                self.assertFalse(scan.call_args.kwargs["include_spam"])
                self.assertFalse(scan.call_args.kwargs["request_fallback"])
                self.assertTrue(scan.call_args.kwargs["resume"])
                self.assertIsNotNone(scan.call_args.kwargs["history"])'''
        if source.count(before) != 1:
            raise ValueError("test_gui_launcher.py does not match the supported revision.")
        updated[launch] = source.replace(before, after, 1)

    common = ROOT / "test_gmail_unsubscriber.py"
    if common.exists():
        source = common.read_text(encoding="utf-8")
        before = "        gc.collect()\n        self.addCleanup(patch.stopall)"
        after = ("        gc.collect()\n"
                 "        self.addCleanup(patch.stopall)\n"
                 "        state_folder = tempfile.TemporaryDirectory()\n"
                 "        self.addCleanup(state_folder.cleanup)\n"
                 "        patch.dict(os.environ, {\"XDG_STATE_HOME\": state_folder.name,\n"
                 "                                    \"LOCALAPPDATA\": state_folder.name}).start()")
        if source.count(before) != 1:
            raise ValueError("test_gmail_unsubscriber.py does not match the supported revision.")
        updated[common] = source.replace(before, after, 1)
    return updated


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\x00" + data).hexdigest()


def install() -> None:
    source_file = ROOT / "gmail_unsubscriber.py"
    if not source_file.is_file():
        raise SystemExit("Run this updater from the repository root alongside gmail_unsubscriber.py.")
    raw = source_file.read_bytes()
    if b'APP_VERSION = "3.1.0"' in raw:
        raise SystemExit("Version 3.1.0 is already installed. No files changed.")
    if git_blob_sha(raw) != BASE_BLOB_SHA:
        raise SystemExit("Source does not match the supported v3.0 revision. No files changed. "
                         "Review upstream changes before applying this update.")
    readme_source = ROOT / "README-v3.1.md"
    if not readme_source.is_file():
        raise SystemExit("README-v3.1.md is missing. Keep all update package files together.")
    updated = patch_source(raw.decode("utf-8"))
    test_updates = prepare_test_updates()
    backup = source_file.with_name("gmail_unsubscriber.py.v3.0.backup")
    if backup.exists():
        raise SystemExit(f"Backup already exists: {backup}. No files changed.")
    with tempfile.TemporaryDirectory() as temporary:
        candidate = Path(temporary) / "gmail_unsubscriber.py"
        candidate.write_text(updated, encoding="utf-8")
        py_compile.compile(str(candidate), doraise=True)
        for path, content in test_updates.items():
            example = Path(temporary) / path.name
            example.write_text(content, encoding="utf-8")
            py_compile.compile(str(example), doraise=True)
    shutil.copy2(source_file, backup)
    temp = source_file.with_suffix(".update")
    temp.write_text(updated, encoding="utf-8")
    os.replace(temp, source_file)
    for path, content in test_updates.items():
        temporary_test = path.with_suffix(".update")
        temporary_test.write_text(content, encoding="utf-8")
        os.replace(temporary_test, path)
    previous_readme = ROOT / "README.md"
    if previous_readme.exists():
        shutil.copy2(previous_readme, ROOT / "README.md.v3.0.backup")
    staged_readme = ROOT / "README.md.update"
    staged_readme.write_bytes(readme_source.read_bytes())
    os.replace(staged_readme, previous_readme)
    print(f"Updated Gmail Unsubscriber to {VERSION} and refreshed README.md.")
    print(f"Previous source backup: {backup.name}")
    print("Persistent scan data is stored outside the repository, in the local user state folder.")
    print("Run: python -m unittest discover -v")


if __name__ == "__main__":
    install()
