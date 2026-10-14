"""Tests for auto unsubscribe and IMAP recovery.

Network calls are blocked. IMAP parser tests use an in-memory server transcript.
"""
import imaplib
import os
import ssl
import time
import unittest
from unittest.mock import MagicMock, patch

import gmail_unsubscriber as u
from test_gmail_unsubscriber import ACCOUNT, PASSWORD, MAIL_URL, POST_URL, headers, candidate, OfflineCase


def mailbox(messages=None, *, failure=None, validity="123", trace=None):
    messages = messages if messages is not None else {10: headers([MAIL_URL], post=None)}
    mail = MagicMock()
    mail.login.return_value = ("OK", [b"logged in"])
    mail.select.return_value = ("OK", [str(len(messages)).encode()])
    mail.response.return_value = ("UIDVALIDITY", [validity.encode()])
    mail.logout.return_value = ("BYE", [b"bye"])

    def uid(command, *args):
        if command == "search":
            return "OK", [b" ".join(str(uid).encode() for uid in sorted(messages))]
        number, query = int(args[0]), args[1]
        if trace is not None:
            trace.append(("fetch", number, query))
        if failure:
            result = failure(number, query)
            if result is not None:
                return result
        raw = messages.get(number)
        if raw is None:
            return "OK", [None]
        if query == "(RFC822.SIZE)":
            return "OK", [f"1 (UID {number} RFC822.SIZE {len(raw)})".encode()]
        return "OK", [(f"1 (UID {number} BODY[HEADER] {{{len(raw)}}}".encode(), raw), b")"]

    mail.uid.side_effect = uid
    return mail


class AutomaticTests(OfflineCase):
    def setUp(self):
        super().setUp()
        patch.object(u, "IMAP_RETRY_DELAY", 0).start()
        self.events = []
        self.guard = u.NetworkGuard()
        self.ledger = {}
        self.post = patch.object(u, "submit_one_click", return_value=("Request accepted", "HTTP 200")).start()
        self.smtp = patch.object(u, "send_mailto", return_value=("Email submitted", "SMTP accepted")).start()
        self.verify = patch.object(u, "verify_one_click_dkim", return_value=(True, "offline verified")).start()

    def run_auto(self, factory, limit=0):
        with patch.object(u, "VerifiedIMAP", side_effect=factory) as create:
            u.scan_and_unsubscribe(ACCOUNT, PASSWORD, limit, self.guard, self.ledger,
                                   lambda *event: self.events.append(event))
        return create

    def summary(self):
        return [v for k, v in self.events if k == "summary"][-1]

    def test_submission_occurs_before_next_message_fetch(self):
        trace = []
        messages = {10: headers([MAIL_URL], post=None, list_id="<first.example.com>"),
                    20: headers([MAIL_URL + "2"], post=None, list_id="<second.example.com>")}
        self.smtp.side_effect = lambda *args: (trace.append(("send", args[0])) or ("Email submitted", "accepted"))
        self.run_auto(lambda *_: mailbox(messages, trace=trace))
        self.assertEqual([x[0] for x in trace], ["fetch", "send", "fetch", "send"])
        self.assertEqual([x[1] for x in trace if x[0] == "fetch"], [20, 10])
        self.assertEqual(self.summary()['accepted'], 2)

    def test_exact_user_exception_recovers_on_new_connection(self):
        def fail(*_):
            raise imaplib.IMAP4.abort("command: UID => System Error")
        broken, good = mailbox(failure=fail), mailbox()
        clients = iter([broken, good])
        create = self.run_auto(lambda *_: next(clients))
        self.assertEqual(create.call_count, 2)
        self.smtp.assert_called_once()
        self.assertTrue(any("command: UID => System Error" in str(v) for k, v in self.events if k == "log"))
        self.assertEqual(self.summary()['unreadable'], 0)

    def test_base_imap_error_is_also_recoverable(self):
        def fail(*_):
            raise imaplib.IMAP4.error("command: UID => System Error")
        clients = iter([mailbox(failure=fail), mailbox()])
        self.run_auto(lambda *_: next(clients))
        self.smtp.assert_called_once()

    def test_header_field_failure_uses_and_caches_simpler_fallback(self):
        trace = []
        def fail(_uid, query):
            if "HEADER.FIELDS" in query:
                return "NO", [b"System Error"]
        messages = {10: headers([MAIL_URL], post=None), 20: headers([MAIL_URL], post=None)}
        self.run_auto(lambda *_: mailbox(messages, failure=fail, trace=trace))
        self.assertTrue(any(query == "(BODY.PEEK[HEADER])" for _, _, query in trace))
        uid10 = [q for _, uid, q in trace if uid == 10]
        self.assertEqual(uid10, ["(BODY.PEEK[HEADER])"])
        self.assertFalse(any("<0." in query for _, _, query in trace))
        self.smtp.assert_called_once()

    def test_rfc822_header_fallback_when_both_peek_formats_fail(self):
        def fail(_uid, query):
            if query != "(RFC822.HEADER)":
                return "NO", [b"System Error"]
        self.run_auto(lambda *_: mailbox(failure=fail))
        self.smtp.assert_called_once()

    def test_unreadable_message_does_not_abort_remaining_messages(self):
        def fail(uid, _query):
            if uid == 20:
                raise imaplib.IMAP4.abort("command: UID => System Error")
        messages = {10: headers([MAIL_URL], post=None), 20: headers([MAIL_URL + "2"], post=None)}
        self.run_auto(lambda *_: mailbox(messages, failure=fail))
        self.smtp.assert_called_once()
        self.assertEqual(self.summary()['unreadable'], 1)
        self.assertEqual(self.summary()['checked'], 2)

    def test_repeated_unreadable_messages_stop_with_partial_summary(self):
        def fail(*_):
            raise imaplib.IMAP4.abort("command: UID => System Error")
        messages = {i: headers([MAIL_URL], post=None) for i in range(1, 9)}
        with self.assertRaisesRegex(u.MailboxError, "5 consecutive"):
            self.run_auto(lambda *_: mailbox(messages, failure=fail))
        self.assertEqual(self.summary()['checked'], 5)
        self.assertEqual(self.summary()['unreadable'], 5)
        self.smtp.assert_not_called()
        self.assertFalse(any(str(v).startswith("Finished.") for k, v in self.events if k == "log"))

    def test_uidvalidity_change_after_reconnect_aborts_without_sending(self):
        def fail(*_):
            raise imaplib.IMAP4.abort("System Error")
        clients = iter([mailbox(failure=fail), mailbox(validity="999")])
        with self.assertRaises(u.StaleScanError):
            self.run_auto(lambda *_: next(clients))
        self.smtp.assert_not_called()

    def test_initial_login_abort_is_not_called_bad_password(self):
        broken = mailbox()
        broken.login.side_effect = imaplib.IMAP4.abort("server disconnected")
        clients = iter([broken, mailbox()])
        self.run_auto(lambda *_: next(clients))
        self.smtp.assert_called_once()

    def test_genuine_password_rejection_is_not_retried(self):
        mail = mailbox()
        mail.login.side_effect = imaplib.IMAP4.error("authentication failed")
        with patch.object(u, "VerifiedIMAP", return_value=mail) as create, self.assertRaises(u.AuthenticationError):
            u.scan_and_unsubscribe(ACCOUNT, PASSWORD, 0, self.guard, self.ledger, lambda *e: self.events.append(e))
        self.assertEqual(create.call_count, 1)
        self.smtp.assert_not_called()

    def test_quota_error_stops_without_retrying_all_formats(self):
        def fail(*_):
            return "NO", [b"[OVERQUOTA] bandwidth exceeded"]
        with patch.object(u, "VerifiedIMAP", side_effect=lambda *_: mailbox(failure=fail)) as create, \
                self.assertRaises(u.MailboxLimitError):
            u.scan_and_unsubscribe(ACCOUNT, PASSWORD, 0, self.guard, self.ledger, lambda *e: self.events.append(e))
        self.assertEqual(create.call_count, 1)
        self.smtp.assert_not_called()

    def test_certificate_failure_is_never_retried_or_bypassed(self):
        with patch.object(u, "VerifiedIMAP", side_effect=ssl.SSLCertVerificationError("bad cert")) as create, \
                self.assertRaises(ssl.SSLCertVerificationError):
            u.scan_and_unsubscribe(ACCOUNT, PASSWORD, 0, self.guard, self.ledger, lambda *e: self.events.append(e))
        self.assertEqual(create.call_count, 1)

    def test_scan_limit_means_newest_messages_not_number_of_lists(self):
        trace = []
        messages = {i: b"From: no-list@example.com\r\n\r\n" for i in range(1, 270)}
        self.run_auto(lambda *_: mailbox(messages, trace=trace), limit=250)
        self.assertEqual(len(trace), 250)
        self.assertEqual(trace[0][1], 269)
        self.assertEqual(trace[-1][1], 20)
        self.smtp.assert_not_called()

    def test_40818_uid_listing_is_handled_without_full_scan(self):
        # Use a large inbox fixture, limited to its newest 250 messages.
        messages = {i: b"From: no-list@example.com\r\n\r\n" for i in range(1, 40819)}
        trace = []
        self.run_auto(lambda *_: mailbox(messages, trace=trace), limit=250)
        self.assertEqual(self.summary()['total'], 250)
        self.assertEqual(trace[0][1], 40818)

    def test_empty_inbox_has_summary_and_no_submissions(self):
        self.run_auto(lambda *_: mailbox({}))
        self.assertEqual(self.summary()['total'], 0)
        self.smtp.assert_not_called()

    def test_cancel_before_start_opens_nothing(self):
        self.guard.cancel()
        with patch.object(u, "VerifiedIMAP") as create, self.assertRaises(u.Cancelled):
            u.scan_and_unsubscribe(ACCOUNT, PASSWORD, 0, self.guard, self.ledger, lambda *e: self.events.append(e))
        create.assert_not_called()

    def test_cancel_after_accepted_submission_preserves_ledger(self):
        def submit(*_):
            self.guard.cancel()
            return "Email submitted", "accepted before stopping"
        self.smtp.side_effect = submit
        messages = {10: headers([MAIL_URL], post=None), 20: headers([MAIL_URL + "2"], post=None)}
        with self.assertRaises(u.Cancelled):
            self.run_auto(lambda *_: mailbox(messages))
        self.smtp.assert_called_once()
        self.assertEqual(self.summary()['accepted'], 1)
        self.assertIn("Email submitted", self.ledger.values())

    def test_same_list_different_tokens_only_submitted_once(self):
        messages = {10: headers([MAIL_URL + "older"], post=None), 20: headers([MAIL_URL + "newer"], post=None)}
        self.run_auto(lambda *_: mailbox(messages))
        self.smtp.assert_called_once()
        self.assertEqual(self.summary()['duplicates'], 1)

    def test_distinct_lists_from_same_sender_are_not_combined(self):
        messages = {10: headers([MAIL_URL], post=None, list_id="<first.example.com>"),
                    20: headers([MAIL_URL + "2"], post=None, list_id="<second.example.com>")}
        self.run_auto(lambda *_: mailbox(messages))
        self.assertEqual(self.smtp.call_count, 2)

    def test_failed_submission_does_not_mark_whole_list_complete(self):
        messages = {10: headers([MAIL_URL + "older"], post=None), 20: headers([MAIL_URL + "newer"], post=None)}
        self.smtp.side_effect = [("Failed", "rejected"), ("Email submitted", "accepted")]
        self.run_auto(lambda *_: mailbox(messages))
        self.assertEqual(self.smtp.call_count, 2)
        self.assertEqual(self.summary()['accepted'], 1)

    def test_unknown_result_is_not_retried_via_older_list_token(self):
        self.smtp.return_value = ("Outcome unknown", "connection dropped during submission")
        messages = {10: headers([MAIL_URL + "older"], post=None), 20: headers([MAIL_URL + "newer"], post=None)}
        self.run_auto(lambda *_: mailbox(messages))
        self.smtp.assert_called_once()
        self.assertEqual(self.summary()['unknown'], 1)

    def test_post_success_does_not_also_send_mailto(self):
        self.run_auto(lambda *_: mailbox({10: headers()}))
        self.post.assert_called_once()
        self.smtp.assert_not_called()

    def test_unverified_post_can_use_email_fallback(self):
        self.verify.return_value = (False, "signature unavailable")
        self.run_auto(lambda *_: mailbox({10: headers()}))
        self.post.assert_not_called()
        self.smtp.assert_called_once()

    def test_older_copy_can_verify_after_newer_unsigned_copy(self):
        self.verify.side_effect = [(False, "signature missing"), (True, "verified")]
        self.run_auto(lambda *_: mailbox({10: headers([POST_URL]), 20: headers([POST_URL])}))
        self.assertEqual(self.verify.call_count, 2)
        self.post.assert_called_once()

    def test_ordinary_confirmation_page_remains_manual(self):
        self.run_auto(lambda *_: mailbox({10: headers([POST_URL], post=None)}))
        self.post.assert_not_called()
        self.smtp.assert_not_called()
        self.assertEqual(self.summary()['manual'], 1)

    def test_removed_message_is_reported_not_failure(self):
        def missing(*_):
            return "OK", [None]
        self.run_auto(lambda *_: mailbox(failure=missing))
        self.assertEqual(self.summary()['unreadable'], 1)
        self.smtp.assert_not_called()

    def test_wrong_uid_literal_is_never_processed(self):
        def wrong(*_):
            return "OK", [(b"1 (UID 999 BODY[HEADER] {5}", headers([MAIL_URL]))]
        self.run_auto(lambda *_: mailbox(failure=wrong))
        self.smtp.assert_not_called()
        self.assertEqual(self.summary()['unreadable'], 1)

    def test_oversized_header_is_skipped_not_retried(self):
        with patch.object(u, "MAX_HEADERS", 10):
            create = self.run_auto(lambda *_: mailbox())
        self.assertEqual(create.call_count, 1)
        self.smtp.assert_not_called()
        self.assertEqual(self.summary()['unreadable'], 1)


class InMemorySocket:
    """Replay server responses from memory instead of opening a connection."""
    def __init__(self, fail_fetch=False):
        self.buffer = bytearray(b"* OK offline IMAP test server\r\n")
        self.commands = []
        self.closed = False
        self.fail_fetch = fail_fetch
        self.raw = headers([MAIL_URL], post=None)

    def makefile(self, _mode):
        return self

    def sendall(self, data):
        if self.closed:
            raise OSError("closed")
        self.commands.append(data)
        tag, command = data.rstrip(b"\r\n").split(b" ", 1)
        command = command.upper()
        if command == b"CAPABILITY":
            response = b"* CAPABILITY IMAP4rev1\r\n" + tag + b" OK capabilities\r\n"
        elif command.startswith(b"LOGIN "):
            response = tag + b" OK logged in\r\n"
        elif command == b"EXAMINE INBOX":
            response = b"* 1 EXISTS\r\n* OK [UIDVALIDITY 123] stable\r\n" + tag + b" OK [READ-ONLY] selected\r\n"
        elif command == b"UID SEARCH ALL":
            response = b"* SEARCH 10\r\n" + tag + b" OK search complete\r\n"
        elif command.startswith(b"UID FETCH 10 "):
            if self.fail_fetch:
                response = b"* BYE System Error\r\n"
            else:
                response = (f"* 1 FETCH (UID 10 BODY[HEADER] {{{len(self.raw)}}}\r\n".encode() + self.raw
                            + b")\r\n" + tag + b" OK fetch complete\r\n")
        elif command == b"LOGOUT":
            response = b"* BYE logout\r\n" + tag + b" OK logout complete\r\n"
        else:
            raise AssertionError(f"Unexpected IMAP command: {command!r}")
        self.buffer.extend(response)

    def readline(self, limit=-1):
        stop = self.buffer.find(b"\n") + 1
        if not stop:
            return b""
        if limit >= 0:
            stop = min(stop, limit)
        data = bytes(self.buffer[:stop])
        del self.buffer[:stop]
        return data

    def read(self, count):
        data = bytes(self.buffer[:count])
        del self.buffer[:count]
        return data

    def close(self):
        self.closed = True

    def shutdown(self, _how):
        self.closed = True


class ProtocolReplayTests(OfflineCase):
    def setUp(self):
        super().setUp()
        patch.object(u, "IMAP_RETRY_DELAY", 0).start()

    def test_real_imaplib_parser_produces_exact_reported_exception(self):
        stream = InMemorySocket(fail_fetch=True)
        with patch.object(u.VerifiedIMAP, "_create_socket", return_value=stream):
            mail = u.VerifiedIMAP(u.NetworkGuard())
        mail.login(ACCOUNT, PASSWORD)
        mail.select("INBOX", readonly=True)
        mail.uid("search", None, "ALL")
        with self.assertRaises(imaplib.IMAP4.abort) as caught:
            mail.uid("fetch", "10", u.FETCH_HEADERS)
        self.assertEqual(str(caught.exception), "command: UID => System Error")
        mail.shutdown()

    def test_real_imaplib_reconnects_and_auto_submits_after_bye(self):
        bad, good = InMemorySocket(True), InMemorySocket(False)
        events = []
        with patch.object(u.VerifiedIMAP, "_create_socket", side_effect=[bad, good]) as connect, \
                patch.object(u, "send_mailto", return_value=("Email submitted", "offline SMTP stub")) as send:
            u.scan_and_unsubscribe(ACCOUNT, PASSWORD, 0, u.NetworkGuard(), {}, lambda *e: events.append(e))
        self.assertEqual(connect.call_count, 2)
        send.assert_called_once()
        self.assertTrue(any("command: UID => System Error" in str(value) for _, value in events))
        fetches = [line for line in bad.commands + good.commands if b"UID FETCH" in line]
        self.assertTrue(fetches)
        self.assertFalse(any(b"<0." in line for line in fetches))
        self.assertTrue(all(b"BODY.PEEK[HEADER.FIELDS" in line for line in fetches))
        self.assertTrue(bad.closed and good.closed)

    def test_literal_size_guard_refuses_before_base_read(self):
        client = object.__new__(u.VerifiedIMAP)
        client._literal_limit = 100
        with patch.object(imaplib.IMAP4, "read") as read, self.assertRaises(u.OversizedLiteral):
            client.read(101)
        read.assert_not_called()


@unittest.skipUnless(os.environ.get("DISPLAY") or os.name == "nt", "GUI needs a display")
class AutoGuiTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.root = u.tk.Tk()
        self.app = u.UnsubscribeApp(self.root)
        self.root.update()

    def tearDown(self):
        if self.app.worker is not None:
            self.app.guard.cancel()
            self.app.worker.join(1)
        if not self.app.destroyed:
            self.app._destroy()

    def test_preset_scan_needs_no_amount_popup(self):
        self.app.scan_choice_var.set("250")
        self.app.auto_var.set(True)
        with patch.object(self.app, "credentials", return_value=(ACCOUNT, PASSWORD)), \
                patch.object(self.app, "_start_worker") as start, \
                patch.object(u.messagebox, "askyesno", side_effect=AssertionError("Extra confirmation")):
            self.app.start_scan()
        start.assert_called_once()
        self.assertEqual(self.app.active_task, "auto")
        self.assertEqual(start.call_args.args[1], (ACCOUNT, PASSWORD, 250))

    def test_entire_inbox_confirmation_explains_current_mode(self):
        self.app.scan_choice_var.set("Entire inbox")
        self.app.auto_var.set(True)
        with patch.object(self.app, "credentials", return_value=(ACCOUNT, PASSWORD)), \
                patch.object(self.app, "_start_worker") as start, \
                patch.object(u.messagebox, "askyesno", return_value=True) as question:
            self.app.start_scan()
        question.assert_called_once()
        self.assertIn("Auto unsubscribe is ON", question.call_args.args[1])
        start.assert_called_once()

    def test_duplicate_candidate_event_updates_row_instead_of_crashing(self):
        c = candidate()
        self.app.events.put(("candidate", c))
        self.app.events.put(("candidate", c))
        self.app._poll_events()
        self.app._refresh_results()
        self.assertEqual(len(self.app.tree.get_children()), 1)

    def test_auto_export_is_set_before_worker_starts(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / "results.csv")
            self.app.auto_var.set(True)
            self.app.save_csv_var.set(True)
            self.app.file_path_var.set(path)
            with patch.object(self.app, "credentials", return_value=(ACCOUNT, PASSWORD)), \
                    patch.object(self.app, "_start_worker"):
                self.app.start_scan()
            self.assertEqual(self.app._auto_export_path, path)


if __name__ == "__main__":
    unittest.main()
