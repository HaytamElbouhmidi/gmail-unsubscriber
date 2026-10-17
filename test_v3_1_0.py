"""Regression checks for Gmail Unsubscriber 3.1.0.

All tests use synthetic messages and local files. No Gmail connection is made.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import gmail_unsubscriber as u
from scan_history import HistoryStore
from test_auto_mode import mailbox
from test_gmail_unsubscriber import ACCOUNT, PASSWORD, MAIL_URL, OfflineCase

VERSION = "3.1.0"


def sample(sender="Newsletter <hello@letters.example.com>", *, list_id=True, unsubscribe=False):
    raw = f"From: {sender}\r\nSubject: Test mailing list\r\n"
    if list_id:
        raw += "List-ID: <newsletter.letters.example.com>\r\n"
    if unsubscribe:
        raw += f"List-Unsubscribe: <{MAIL_URL}>\r\n"
    return (raw + "\r\n").encode()


class SpamAndFallbackTests(OfflineCase):
    def test_spam_mailbox_discovered_by_special_use_flag(self):
        mail = MagicMock()
        mail.list.return_value = ("OK", [b'(\\HasNoChildren \\Junk) "/" "[Gmail]/Spam"'])
        self.assertEqual(u.spam_mailbox_name(mail, u.NetworkGuard()), "[Gmail]/Spam")

    def test_spam_lookup_while_imap_network_scope_is_active(self):
        mail = MagicMock()
        mail.list.return_value = ("OK", [b'(\\HasNoChildren \\Junk) "/" "[Gmail]/Spam"'])
        guard = u.NetworkGuard()
        with guard.operation():
            self.assertEqual(u.spam_mailbox_name(mail, guard), "[Gmail]/Spam")

    def test_spam_does_not_request_plain_fallback(self):
        self.assertIsNone(u.parse_candidate(sample(), "9", "1", folder="SPAM", request_fallback=False))

    def test_opt_in_plain_request_for_identified_list_only(self):
        self.assertIsNone(u.parse_candidate(sample(list_id=False), "9", "1", request_fallback=True))
        c = u.parse_candidate(sample(), "9", "1", request_fallback=True)
        self.assertIsNotNone(c)
        self.assertEqual([t.method for t in c.targets], ["REQUEST"])
        target = u.parse_mailto(c.targets[0].uri)
        self.assertEqual(target.recipients, ("hello@letters.example.com",))
        self.assertIn("remove me", target.body)

    def test_noreply_and_existing_mailto_are_not_plain_fallbacks(self):
        self.assertIsNone(u.parse_candidate(sample(sender="No reply <noreply@letters.example.com>"),
                                            "9", "1", request_fallback=True))
        c = u.parse_candidate(sample(unsubscribe=True), "9", "1", request_fallback=True)
        self.assertEqual([t.method for t in c.targets], ["MAILTO"])

    def test_plain_request_not_issued_by_default(self):
        self.assertIsNone(u.parse_candidate(sample(), "9", "1"))

    def test_manual_link_enables_plain_email_with_no_list_id(self):
        raw = (b"From: Mailer <mailer@example.com>\r\n"
               b"Subject: News\r\n"
               b"List-Unsubscribe: <https://example.com/confirm>\r\n\r\n")
        c = u.parse_candidate(raw, "10", "123", request_fallback=True)
        self.assertEqual([t.method for t in c.targets], ["MANUAL", "REQUEST"])

    def test_malformed_unsubscribe_target_does_not_trigger_plain_email(self):
        raw = (b"From: Mailer <mailer@example.com>\r\n"
               b"List-ID: <news.example.com>\r\n"
               b"List-Unsubscribe: https://example.com/unsub\r\n\r\n")
        c = u.parse_candidate(raw, "10", "123", request_fallback=True)
        self.assertEqual([t.method for t in c.targets], ["BLOCKED"])


class CheckpointTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store_path = Path(self.temp.name) / "checkpoint.db"
        self.guard = u.NetworkGuard()
        self.events = []
        self.ledger = {}
        patch.object(u, "send_mailto", return_value=("Email submitted", "accepted")).start()

    def record(self, folder="INBOX", uid="15"):
        return u.parse_candidate(sample(unsubscribe=True), uid, "123", folder=folder)

    def test_reservation_prevents_duplicate_after_crash(self):
        c = self.record()
        with HistoryStore(self.store_path) as history:
            history.reserve(ACCOUNT, c, c.targets[0], self.ledger)
        with HistoryStore(self.store_path) as history:
            self.assertEqual(history.load_ledger(ACCOUNT)[(ACCOUNT, "ENTRY", c.key)], "Outcome unknown")

    def test_successful_result_survives_restart(self):
        c = self.record()
        result = u.Result(c, ACCOUNT, "MAILTO", MAIL_URL, "Email submitted", "accepted")
        with HistoryStore(self.store_path) as history:
            run = history.new_run(ACCOUNT, {"limit": 1}, [{"folder": "INBOX", "validity": "123", "uids": ["15"]}],
                                  {"checked": 0})
            history.reserve(ACCOUNT, c, c.targets[0], self.ledger)
            history.finalize(ACCOUNT, c, c.targets[0], "Email submitted", self.ledger)
            history.record_result(ACCOUNT, run, result)
            history.checkpoint(run, "INBOX", "15", u.candidate_info(c), c, False, {"checked": 1}, True)
            history.state(run, "interrupted")
        with HistoryStore(self.store_path) as history:
            saved = history.latest_incomplete(ACCOUNT, {"limit": 1})
            self.assertEqual(saved[0], run)
            self.assertEqual(history.checkpoints(run)[("INBOX", "15")][1].folder, "INBOX")
            self.assertEqual(history.outcomes(run)[0].status, "Email submitted")
            self.assertEqual(history.seen_keys(run), {c.key})

    def test_scanning_spam_does_not_auto_submit(self):
        inbox = mailbox({12: sample(unsubscribe=True)})
        spam = mailbox({22: sample(unsubscribe=True)})
        spam.list.return_value = ("OK", [b'(\\HasNoChildren \\Junk) "/" "[Gmail]/Spam"'])
        with patch.object(u, "VerifiedIMAP", side_effect=[inbox, spam]), \
             HistoryStore(self.store_path) as history, \
             patch.object(u, "send_mailto", return_value=("Email submitted", "accepted")) as send:
            u.scan_and_unsubscribe(ACCOUNT, PASSWORD, 0, self.guard, self.ledger,
                                   lambda *event: self.events.append(event),
                                   include_spam=True, history=history)
            self.assertEqual(send.call_count, 1)
            self.assertEqual(spam.select.call_args.args, ("[Gmail]/Spam",))
        folders = {result.folder for kind, result in self.events if kind == "candidate"}
        self.assertEqual(folders, {"INBOX", "SPAM"})

    def test_resume_skips_checked_messages_and_does_not_resend(self):
        contents = {30: sample(unsubscribe=True), 29: sample(unsubscribe=True).replace(
            b"newsletter.letters.example.com", b"other.letters.example.com").replace(
            b"required%2Btoken", b"required2%2Btoken")}
        sent = []

        def sending(*args):
            sent.append(args[0])
            self.guard.cancel()
            return "Email submitted", "accepted"

        first = mailbox(contents)
        with patch.object(u, "VerifiedIMAP", return_value=first), \
             patch.object(u, "send_mailto", side_effect=sending), \
             HistoryStore(self.store_path) as history:
            with self.assertRaises(u.Cancelled):
                u.scan_and_unsubscribe(ACCOUNT, PASSWORD, 0, self.guard, self.ledger,
                                       lambda *event: self.events.append(event),
                                       history=history, resume=True)
            self.assertEqual(len(sent), 1)
        self.guard = u.NetworkGuard()
        second = mailbox(contents)
        with patch.object(u, "VerifiedIMAP", return_value=second), \
             patch.object(u, "send_mailto", return_value=("Email submitted", "accepted")) as send, \
             HistoryStore(self.store_path) as history:
            u.scan_and_unsubscribe(ACCOUNT, PASSWORD, 0, self.guard, self.ledger,
                                   lambda *event: self.events.append(event),
                                   history=history, resume=True)
            self.assertEqual(send.call_count, 1)
            self.assertEqual(history.latest_incomplete(ACCOUNT, dict(
                limit=0, automatic=True, include_spam=False, request_fallback=False)), None)
        self.assertEqual(len(sent) + send.call_count, 2)


class OutcomeSortingTests(OfflineCase):
    def row(self, sender, status):
        c = u.parse_candidate(sample(sender=f"{sender} <{sender.lower()}@example.com>", unsubscribe=True), "9", "1")
        row = u.SenderRow(u.candidate_info(c))
        row.add_candidate(c)
        row.set_status(c, status)
        return row

    def test_filter_categories_and_sort_failed_successful(self):
        success = self.row("Success", "Email submitted")
        failure = self.row("Failure", "Failed")
        pending = self.row("Pending", "Not submitted")
        ordered = u.sorted_sender_rows([success, pending, failure], "Outcome", False,
                                       status_for=lambda r: next(iter(r.states.values())))
        self.assertEqual(ordered[0].latest.sender_name, "Failure")
        self.assertEqual(ordered[-1].latest.sender_name, "Success")
        self.assertEqual(u.outcome_category("Email submitted"), "Successful")
        self.assertEqual(u.outcome_category("Failed"), "Failed")


if __name__ == "__main__":
    unittest.main()
