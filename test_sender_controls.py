"""Tests for scan settings, sender checkboxes, sorting, and live search.

Gmail connections and unsubscribe requests are mocked.
"""
from dataclasses import replace
from datetime import datetime, timezone
import imaplib
import os
import time
import types
import unittest
from unittest.mock import MagicMock, patch

import gmail_unsubscriber as u
from test_gmail_unsubscriber import ACCOUNT, PASSWORD, POST_URL, MAIL_URL, headers, candidate, OfflineCase
from test_auto_mode import mailbox


def message(uid=10, name="Alpha", address="alpha@example.com", subject="Current newsletter",
            date="Wed, 14 Oct 2026 10:00:00 +0000", list_id="<alpha.example.com>", links=None):
    raw = headers(links or [MAIL_URL], post=None, sender=f"{name} <{address}>", list_id=list_id,
                  extra=(f"Date: {date}\r\n" if date is not None else ""))
    return raw.replace(b"Subject: Test newsletter", f"Subject: {subject}".encode())


def item(uid=10, **kwargs):
    return u.parse_candidate(message(uid, **kwargs), str(uid), "123")


class DateAndSenderTests(OfflineCase):
    def test_header_fetch_includes_date(self):
        self.assertIn(" DATE ", u.HEADER_FIELDS)
        self.assertIn("BODY.PEEK", u.FETCH_HEADERS)

    def test_date_is_normalized_to_utc(self):
        c = item(date="Wed, 14 Oct 2026 10:00:00 -0600")
        self.assertEqual(c.sent_at, datetime(2026, 10, 14, 16, tzinfo=timezone.utc))

    def test_unknown_timezone_offset_uses_utc(self):
        c = item(date="Wed, 14 Oct 2026 10:00:00 -0000")
        self.assertEqual(c.sent_at.hour, 10)
        self.assertEqual(c.sent_at.tzinfo, timezone.utc)

    def test_missing_invalid_and_extreme_dates_are_unknown(self):
        for date in (None, "not a date", "Fri, 99 Oct 2026 99:99:99 +0000", "1 Jan 99999 00:00:00 +0000"):
            with self.subTest(date=date):
                self.assertIsNone(item(date=date).sent_at)
        self.assertEqual(u.display_date(None), "Unknown")

    def test_duplicate_date_headers_are_unknown(self):
        raw = message() + b"Date: Thu, 15 Oct 2026 10:00:00 +0000\r\n"
        # Put the duplicate header before the blank line that ends the headers.
        raw = message().replace(b"\r\n\r\n", b"\r\nDate: Thu, 15 Oct 2026 10:00:00 +0000\r\n\r\n")
        self.assertIsNone(u.parse_candidate(raw, "10", "123").sent_at)

    def test_sender_identity_uses_address_not_display_name(self):
        a, b = item(name="Same", address="one@example.com"), item(name="Same", address="two@example.com")
        self.assertNotEqual(u.candidate_info(a).sender_key, u.candidate_info(b).sender_key)
        self.assertNotEqual(a.key, b.key)

    def test_same_address_different_case_and_name_stays_one_sender(self):
        a, b = item(name="First", address="ALPHA@example.com"), item(name="Second")
        self.assertEqual(u.candidate_info(a).sender_key, u.candidate_info(b).sender_key)

    def test_date_not_uid_defines_latest_subject(self):
        later = item(uid=1, subject="Actually newer", date="15 Oct 2026 00:00:00 +0000")
        earlier = item(uid=99, subject="Older but high UID", date="14 Oct 2026 00:00:00 +0000")
        row = u.SenderRow(u.candidate_info(earlier))
        row.add_candidate(earlier)
        row.add_candidate(later)
        self.assertEqual(row.latest.subject, "Actually newer")

    def test_latest_non_unsubscribe_message_updates_sender_summary(self):
        row = u.SenderRow(u.candidate_info(item()))
        row.add_candidate(item())
        row.add_message(u.parse_message_info(b"From: Alpha <alpha@example.com>\r\nSubject: Latest receipt\r\nDate: 16 Oct 2026 00:00:00 +0000\r\n\r\n", "12"))
        self.assertEqual(row.latest.subject, "Latest receipt")
        self.assertEqual(row.latest.sent_at.day, 16)
        self.assertEqual(row.list_count, 1)

    def test_unknown_dates_use_uid_for_latest_subject_without_faking_date(self):
        first, second = item(uid=10, subject="Old", date=None), item(uid=11, subject="New", date=None)
        row = u.SenderRow(u.candidate_info(first))
        row.add_candidate(first)
        row.add_candidate(second)
        self.assertIsNone(row.latest.sent_at)
        self.assertEqual(row.latest.subject, "New")

    def test_search_matches_older_subject_name_address_and_list_id(self):
        row = u.SenderRow(u.candidate_info(item()))
        row.add_candidate(item())
        row.add_candidate(item(uid=8, subject="Your mountain receipt", date="1 Oct 2026 00:00:00 +0000"))
        for query in ("ALPHA", "alpha@example.com", "mountain receipt", "alpha.example.com", "   "):
            self.assertTrue(row.matches(query), query)
        self.assertFalse(row.matches("notfound"))

    def test_search_treats_metacharacters_as_text(self):
        row = u.SenderRow(u.candidate_info(item(subject="[tag] invoice (paid)")))
        row.add_candidate(item(subject="[tag] invoice (paid)"))
        self.assertTrue(row.matches("[tag] (paid)"))
        self.assertFalse(row.matches(".*"))

    def test_two_lists_from_one_sender_stay_distinct(self):
        row = u.SenderRow(u.candidate_info(item()))
        row.add_candidate(item())
        row.add_candidate(item(uid=12, list_id="<other.example.com>", links=[MAIL_URL + "2"]))
        self.assertEqual(row.list_count, 2)
        self.assertEqual(len(row.entries), 2)

    def test_new_token_for_same_declared_list_does_not_add_another_list_count(self):
        row = u.SenderRow(u.candidate_info(item()))
        row.add_candidate(item())
        row.add_candidate(item(uid=12, links=[MAIL_URL + "2"]))
        self.assertEqual(row.list_count, 1)
        self.assertEqual(len(row.entries), 2)

    def test_date_sort_accounts_for_offsets_not_printed_clock(self):
        a = u.SenderRow(u.candidate_info(item(name="A", date="14 Oct 2026 09:00:00 -0600")))
        b = u.SenderRow(u.candidate_info(item(name="B", address="b@example.com", date="14 Oct 2026 11:00:00 +0000")))
        self.assertEqual(u.sorted_sender_rows([b, a], "Latest email", True), [a, b])

    def test_unknown_dates_sort_last_in_both_directions(self):
        rows = [u.SenderRow(u.candidate_info(item(name="Unknown", date=None))),
                u.SenderRow(u.candidate_info(item(name="Known", address="b@example.com")))]
        for descending in (True, False):
            self.assertEqual(u.sorted_sender_rows(rows, "Latest email", descending)[-1].latest.sender_name, "Unknown")


class ReviewBackendTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.post = patch.object(u, "submit_one_click", return_value=("Request accepted", "HTTP 204")).start()
        self.send = patch.object(u, "send_mailto", return_value=("Email submitted", "SMTP accepted")).start()
        self.verify = patch.object(u, "verify_one_click_dkim", return_value=(True, "offline verified")).start()
        self.events = []

    def test_scan_only_sends_nothing_and_does_not_fetch_full_messages(self):
        mail = mailbox({10: headers(), 20: message(20, links=[MAIL_URL])})
        with patch.object(u, "VerifiedIMAP", return_value=mail):
            u.scan_mailbox(ACCOUNT, PASSWORD, 0, u.NetworkGuard(), lambda *e: self.events.append(e))
        self.post.assert_not_called()
        self.send.assert_not_called()
        self.verify.assert_not_called()
        self.assertFalse(any(call.args[-1] in ("(BODY.PEEK[])", "(RFC822.SIZE)") for call in mail.uid.call_args_list))
        mail.select.assert_called_once_with("INBOX", readonly=True)
        self.assertEqual(len([e for e in self.events if e[0] == "candidate"]), 2)

    def test_scan_only_recovers_the_reported_uid_system_error(self):
        broken = mailbox(failure=lambda *_: (_ for _ in ()).throw(imaplib.IMAP4.abort("command: UID => System Error")))
        good = mailbox()
        with patch.object(u, "VerifiedIMAP", side_effect=[broken, good]) as create:
            u.scan_mailbox(ACCOUNT, PASSWORD, 250, u.NetworkGuard(), lambda *e: self.events.append(e))
        self.assertEqual(create.call_count, 2)
        self.send.assert_not_called()
        self.assertEqual(len([e for e in self.events if e[0] == "candidate"]), 1)

    def test_scan_emits_metadata_even_without_an_unsubscribe_header(self):
        raw = b"From: Alpha <alpha@example.com>\r\nSubject: A receipt\r\nDate: 17 Oct 2026 12:00:00 +0000\r\n\r\n"
        with patch.object(u, "VerifiedIMAP", return_value=mailbox({10: raw})):
            u.scan_mailbox(ACCOUNT, PASSWORD, 250, u.NetworkGuard(), lambda *e: self.events.append(e))
        metadata = [payload for kind, payload in self.events if kind == "message"]
        self.assertEqual(metadata[0].subject, "A receipt")
        self.assertFalse(any(kind == "candidate" for kind, _ in self.events))
        self.send.assert_not_called()

    def test_duplicate_message_variants_are_retained_for_manual_review(self):
        with patch.object(u, "VerifiedIMAP", return_value=mailbox({10: message(10), 20: message(20)})):
            u.scan_mailbox(ACCOUNT, PASSWORD, 250, u.NetworkGuard(), lambda *e: self.events.append(e))
        self.assertEqual(len([e for e in self.events if e[0] == "candidate"]), 2)
        summary = [v for k, v in self.events if k == "summary"][-1]
        self.assertEqual(summary["found"], 1)
        self.assertIn("No requests sent", u.run_summary(summary))

    def test_manual_same_list_rotating_tokens_submit_only_once(self):
        selected = (item(uid=20), item(uid=10, links=[MAIL_URL + "2"]))
        u.process_selected(selected, ACCOUNT, PASSWORD, u.NetworkGuard(), {}, lambda *e: self.events.append(e))
        self.send.assert_called_once()

    def test_manual_distinct_lists_from_same_sender_both_submit(self):
        selected = (item(uid=20), item(uid=10, list_id="<other.example.com>", links=[MAIL_URL + "2"]))
        u.process_selected(selected, ACCOUNT, PASSWORD, u.NetworkGuard(), {}, lambda *e: self.events.append(e))
        self.assertEqual(self.send.call_count, 2)

    def test_manual_unknown_outcome_prevents_fallback_for_same_list(self):
        self.send.return_value = ("Outcome unknown", "Disconnected after sending")
        selected = (item(uid=20), item(uid=10, links=[MAIL_URL + "2"]))
        u.process_selected(selected, ACCOUNT, PASSWORD, u.NetworkGuard(), {}, lambda *e: self.events.append(e))
        self.send.assert_called_once()
        self.assertIn("Outcome unknown", [r.status for k, r in self.events if k == "result"])

    def test_manual_post_read_reconnects_without_replaying_submission(self):
        c = candidate([POST_URL])
        bad = mailbox({10: headers([POST_URL])}, failure=lambda *_: (_ for _ in ()).throw(imaplib.IMAP4.abort("System Error")))
        good = mailbox({10: headers([POST_URL])})
        with patch.object(u, "VerifiedIMAP", side_effect=[bad, good]) as create:
            u.process_selected((c,), ACCOUNT, PASSWORD, u.NetworkGuard(), {}, lambda *e: self.events.append(e))
        self.assertEqual(create.call_count, 2)
        self.post.assert_called_once()
        self.send.assert_not_called()

    def test_unverified_newer_copy_can_use_older_verified_copy(self):
        raw = headers([POST_URL])
        newer = u.parse_candidate(raw, "20", "123")
        older = u.parse_candidate(raw, "10", "123")
        self.verify.side_effect = [(False, "Bad signature"), (True, "verified")]
        with patch.object(u, "VerifiedIMAP", return_value=mailbox({10: raw, 20: raw})):
            u.process_selected((newer, older), ACCOUNT, PASSWORD, u.NetworkGuard(), {}, lambda *e: self.events.append(e))
        self.post.assert_called_once()
        self.assertEqual(self.verify.call_count, 2)


@unittest.skipUnless(os.environ.get("DISPLAY") or os.name == "nt", "GUI tests need a desktop display.")
class SenderControlsGuiTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.root = u.tk.Tk()
        self.app = u.UnsubscribeApp(self.root)
        self.root.update()
        self.app.scan_account = ACCOUNT
        patch.object(self.app, "credentials", return_value=(ACCOUNT, PASSWORD)).start()
        self.errors = patch.object(u.messagebox, "showerror", side_effect=AssertionError("Unexpected error popup")).start()

    def tearDown(self):
        if self.app.worker:
            self.app.guard.cancel()
            self.app.worker.join(2)
        if not self.app.destroyed:
            self.app._destroy()

    def add(self, *candidates):
        for c in candidates:
            self.app.events.put(("candidate", c))
        self.app._poll_events()
        self.app._refresh_results()
        self.root.update()

    def pump(self, predicate, timeout=2):
        end = time.monotonic() + timeout
        while not predicate() and time.monotonic() < end:
            self.root.update()
            time.sleep(0.005)
        self.assertTrue(predicate())

    def test_auto_is_opt_in_and_checkboxes_do_not_start_checked(self):
        self.add(item())
        self.assertFalse(self.app.auto_var.get())
        self.assertFalse(self.app.checked_senders)
        self.assertEqual(self.app.tree.set(self.app.visible_keys[0], "checked"), "☐")

    def test_single_row_per_address_and_multiple_lists_preserved(self):
        self.add(item(), item(uid=12, name="Renamed", list_id="<second.example.com>", links=[MAIL_URL + "2"]))
        self.assertEqual(len(self.app.visible_keys), 1)
        row = self.app.senders[self.app.visible_keys[0]]
        self.assertEqual(row.list_count, 2)
        self.assertEqual(len(row.entries), 2)

    def test_matching_display_names_with_different_addresses_stay_separate(self):
        self.add(item(name="News"), item(uid=11, name="News", address="other@example.com"))
        self.assertEqual(len(self.app.visible_keys), 2)

    def test_checkbox_click_does_not_send_and_space_toggles(self):
        self.add(item())
        key = self.app.visible_keys[0]
        x, y, w, h = self.app.tree.bbox(key, "checked")
        with patch.object(self.app, "_start_worker") as start:
            self.app.tree.event_generate("<Button-1>", x=x + w // 2, y=y + h // 2)
            self.root.update()
            self.assertIn(key, self.app.checked_senders)
            self.assertEqual(self.app.tree.set(key, "checked"), "☑")
            self.app._on_tree_space(None)
        self.assertNotIn(key, self.app.checked_senders)
        start.assert_not_called()

    def test_manual_submission_contains_checked_sender_only_all_its_lists(self):
        first, second, other = item(), item(uid=12, list_id="<second.example.com>", links=[MAIL_URL + "2"]), item(uid=11, address="other@example.com")
        self.add(first, second, other)
        self.app.toggle_checked(u.candidate_info(first).sender_key)
        with patch.object(u.messagebox, "askyesno", return_value=True), patch.object(self.app, "_start_worker") as start:
            self.app.start_selected()
        target, args, password = start.call_args.args
        self.assertEqual(set(c.uid for c in args[2]), {"10", "12"})
        self.assertEqual(len(args[2]), 2)
        with patch.object(u, "process_selected") as process:
            guard, emit = u.NetworkGuard(), MagicMock()
            target(*args, guard=guard, emit=emit)
        process.assert_called_once()
        self.assertEqual(process.call_args.args,
                         (args[2], ACCOUNT, PASSWORD, guard, self.app.ledger, emit))
        self.assertIsNotNone(process.call_args.kwargs["history"])
        self.assertEqual(process.call_args.kwargs["run_id"], None)

    def test_cancelling_manual_confirmation_starts_nothing(self):
        self.add(item())
        self.app.check_visible()
        with patch.object(u.messagebox, "askyesno", return_value=False), patch.object(self.app, "_start_worker") as start:
            self.app.start_selected()
        start.assert_not_called()
        self.assertEqual(len(self.app.checked_senders), 1)

    def test_account_change_blocks_manual_submission(self):
        self.add(item())
        self.app.check_visible()
        self.app.scan_account = "someone-else@gmail.com"
        with patch.object(u.messagebox, "showwarning") as warn, patch.object(self.app, "_start_worker") as start:
            self.app.start_selected()
        start.assert_not_called()
        warn.assert_called_once()

    def test_search_filters_as_typed_without_enter_or_network(self):
        self.add(item(), item(uid=11, name="Beta", address="beta@example.com"))
        with patch.object(self.app, "_start_worker") as start:
            self.app.search_entry.insert(0, "bet")
            self.pump(lambda: len(self.app.tree.get_children()) == 1)
        shown = self.app.senders[self.app.tree.get_children()[0]]
        self.assertEqual(shown.latest.sender_name, "Beta")
        start.assert_not_called()

    def test_search_matches_older_subject_while_row_shows_latest(self):
        self.add(item(subject="Newest"), item(uid=8, subject="Old mountain receipt", date="1 Oct 2026 00:00:00 +0000"))
        self.app.search_var.set("mountain")
        self.app._refresh_results()
        self.assertEqual(len(self.app.visible_keys), 1)
        self.assertEqual(self.app.tree.set(self.app.visible_keys[0], "subject"), "Newest")

    def test_non_unsubscribe_message_updates_latest_and_can_be_searched(self):
        self.add(item())
        info = u.parse_message_info(b"From: Alpha <alpha@example.com>\r\nSubject: Latest receipt\r\nDate: 17 Oct 2026 12:00:00 +0000\r\n\r\n", "30")
        self.app.events.put(("message", info))
        self.app._poll_events()
        self.app.search_var.set("receipt")
        self.app._refresh_results()
        self.assertEqual(self.app.tree.set(self.app.visible_keys[0], "subject"), "Latest receipt")

    def test_metadata_only_sender_is_not_a_false_unsubscribe_result(self):
        self.app.events.put(("message", u.candidate_info(item())))
        self.app._poll_events()
        self.app._refresh_results()
        self.assertEqual(self.app.visible_keys, ())

    def test_sort_sender_and_subject_both_directions(self):
        self.add(item(name="zebra", subject="Apple"), item(uid=11, name="Alpha", address="b@example.com", subject="zoo"))
        self.app.sort_var.set("Sender")
        self.app._refresh_results()
        self.assertTrue(self.app.tree.set(self.app.visible_keys[0], "sender").startswith("Alpha"))
        self.app.reverse_sort()
        self.app._refresh_results()
        self.assertTrue(self.app.tree.set(self.app.visible_keys[0], "sender").startswith("zebra"))
        self.app.sort_var.set("Subject")
        self.app._refresh_results()
        self.assertEqual(self.app.tree.set(self.app.visible_keys[0], "subject"), "Apple")
        self.app.reverse_sort()
        self.app._refresh_results()
        self.assertEqual(self.app.tree.set(self.app.visible_keys[0], "subject"), "zoo")

    def test_clicking_same_date_heading_reverses_order(self):
        self.add(item(date="10 Oct 2026 00:00:00 +0000"), item(uid=11, address="b@example.com", date="12 Oct 2026 00:00:00 +0000"))
        first = self.app.visible_keys[0]
        self.app.sort_by_heading("Latest email")
        self.app._refresh_results()
        self.assertNotEqual(first, self.app.visible_keys[0])
        self.assertEqual(self.app.sort_direction_btn["text"], "Oldest first")

    def test_checked_sender_survives_filter_and_sort(self):
        self.add(item(), item(uid=11, name="Beta", address="beta@example.com"))
        key = u.candidate_info(item()).sender_key
        self.app.toggle_checked(key)
        self.app.search_var.set("Beta")
        self.app.sort_var.set("Sender")
        self.app._refresh_results()
        self.assertIn(key, self.app.checked_senders)
        self.assertNotIn(key, self.app.visible_keys)
        self.assertIn("1 hidden by search", self.app.review_count_var.get())
        self.app.search_var.set("")
        self.app._refresh_results()
        self.assertEqual(self.app.tree.set(key, "checked"), "☑")

    def test_check_shown_does_not_check_hidden_rows(self):
        self.add(item(), item(uid=11, name="Beta", address="beta@example.com"))
        self.app.search_var.set("Beta")
        self.app.check_visible()
        self.assertEqual(len(self.app.checked_senders), 1)
        self.assertEqual(self.app.senders[next(iter(self.app.checked_senders))].latest.sender_name, "Beta")

    def test_clear_checks_also_clears_hidden_checks(self):
        self.add(item(), item(uid=11, name="Beta", address="beta@example.com"))
        self.app.check_visible()
        self.app.search_var.set("Beta")
        self.app._refresh_results()
        self.app.clear_checks()
        self.assertFalse(self.app.checked_senders)

    def test_checkbox_heading_toggles_only_currently_shown_rows(self):
        self.add(item(), item(uid=11, name="Beta", address="beta@example.com"))
        alpha_key = u.candidate_info(item()).sender_key
        self.app.toggle_checked(alpha_key)
        self.app.search_var.set("Beta")
        self.app.toggle_visible()
        self.assertEqual(len(self.app.checked_senders), 2)
        self.app.toggle_visible()
        self.assertEqual(self.app.checked_senders, {alpha_key})

    def test_manual_confirmation_explicitly_counts_hidden_checked_senders(self):
        self.add(item(), item(uid=11, name="Beta", address="beta@example.com"))
        self.app.check_visible()
        self.app.search_var.set("Beta")
        with patch.object(u.messagebox, "askyesno", return_value=True) as ask, patch.object(self.app, "_start_worker") as start:
            self.app.start_selected()
        self.assertIn("1 checked senders are hidden", ask.call_args.args[1])
        self.assertEqual(len(start.call_args.args[1][2]), 2)

    def test_search_and_sort_remain_available_during_scan(self):
        self.add(item(), item(uid=11, name="Beta", address="beta@example.com"))
        self.app.is_running = True
        self.app.active_task = "scan"
        self.app.update_controls()
        self.assertEqual(str(self.app.search_entry["state"]), "normal")
        self.assertEqual(str(self.app.sort_combo["state"]), "readonly")
        self.app.search_var.set("alpha@example.com")
        self.app._refresh_results()
        self.assertEqual(len(self.app.visible_keys), 1)
        self.app.check_visible()
        self.assertEqual(len(self.app.checked_senders), 1)
        self.assertEqual(str(self.app.action_btn["state"]), "disabled")
        self.app.is_running = False

    def test_auto_mode_disables_manual_checks_and_selected_action(self):
        self.add(item())
        self.app.check_visible()
        self.app.auto_var.set(True)
        self.app._refresh_results()
        self.app.toggle_checked(self.app.visible_keys[0])
        self.assertFalse(self.app.checked_senders)
        self.assertEqual(str(self.app.action_btn["state"]), "disabled")
        self.assertEqual(self.app.tree.set(self.app.visible_keys[0], "checked"), "")

    def test_scan_mode_is_snapshotted_before_worker(self):
        self.app.auto_var.set(False)
        with patch.object(self.app, "_start_worker") as start:
            self.app.start_scan()
        target, args, _ = start.call_args.args
        self.app.auto_var.set(True)
        with patch.object(u, "scan_and_unsubscribe") as backend:
            target(*args, guard=u.NetworkGuard(), emit=MagicMock())
        self.assertFalse(backend.call_args.kwargs["automatic"])

    def test_new_scan_removes_previously_filtered_detached_rows(self):
        self.add(item(), item(uid=11, name="Beta", address="beta@example.com"))
        old_keys = tuple(self.app.visible_keys)
        self.app.search_var.set("Beta")
        self.app._refresh_results()
        with patch.object(self.app, "_start_worker"):
            self.app.start_scan()
        self.app._refresh_results()
        self.assertTrue(all(not self.app.tree.exists(k) for k in old_keys))
        self.assertFalse(self.app.checked_senders)
        self.assertEqual(self.app.visible_keys, ())

    def test_cancel_full_inbox_retains_checks_filter_and_rows(self):
        self.add(item())
        self.app.check_visible()
        self.app.search_var.set("Alpha")
        self.app._refresh_results()
        before = self.app.visible_keys
        self.app.scan_choice_var.set("Entire inbox")
        with patch.object(u.messagebox, "askyesno", return_value=False), patch.object(self.app, "_start_worker") as start:
            self.app.start_scan()
        start.assert_not_called()
        self.assertEqual(before, self.app.visible_keys)
        self.assertEqual(self.app.checked_senders, set(before))
        self.assertEqual(self.app.search_var.get(), "Alpha")

    def test_result_after_sort_updates_correct_sender(self):
        a, b = item(), item(uid=11, name="Beta", address="beta@example.com")
        self.add(a, b)
        self.app.sort_var.set("Sender")
        self.app.reverse_sort()
        self.app._record_result(u.Result(a, ACCOUNT, "MAILTO", MAIL_URL, "Email submitted", "SMTP accepted"))
        self.app._refresh_results()
        self.assertEqual(self.app.tree.set(u.candidate_info(a).sender_key, "status"), "Email submitted")
        self.assertEqual(self.app.tree.set(u.candidate_info(b).sender_key, "status"), "Not submitted")

    def test_mixed_sender_outcomes_are_not_reported_as_all_successful(self):
        a, b = item(), item(uid=12, list_id="<second.example.com>", links=[MAIL_URL + "2"])
        self.add(a, b)
        self.app._record_result(u.Result(a, ACCOUNT, "MAILTO", MAIL_URL, "Email submitted", "SMTP accepted"))
        self.app._refresh_results()
        self.assertIn("Mixed", self.app.tree.set(self.app.visible_keys[0], "status"))

    def test_real_thread_review_scan_finishes_without_submission(self):
        with patch.object(u, "VerifiedIMAP", return_value=mailbox({10: message()})), \
                patch.object(u, "send_mailto") as send, patch.object(u, "submit_one_click") as post:
            self.app.start_scan()
            self.pump(lambda: not self.app.is_running)
        send.assert_not_called()
        post.assert_not_called()
        self.assertEqual(len(self.app.visible_keys), 1)
        self.assertIn("No requests sent", self.app.status_var.get())

    def test_real_thread_manual_sends_after_checkbox_action(self):
        self.add(item())
        self.app.check_visible()
        with patch.object(u.messagebox, "askyesno", return_value=True), \
                patch.object(u, "send_mailto", return_value=("Email submitted", "SMTP accepted")) as send:
            self.app.start_selected()
            self.pump(lambda: not self.app.is_running)
        send.assert_called_once()
        self.assertEqual(len(self.app.results), 1)
        self.assertEqual(self.app.tree.set(self.app.visible_keys[0], "status"), "Email submitted")

    def test_real_thread_auto_submits_with_toggle_on(self):
        self.app.auto_var.set(True)
        with patch.object(u, "VerifiedIMAP", return_value=mailbox({10: message()})), \
                patch.object(u, "send_mailto", return_value=("Email submitted", "SMTP accepted")) as send:
            self.app.start_scan()
            self.pump(lambda: not self.app.is_running)
        send.assert_called_once()
        self.assertEqual(len(self.app.results), 1)

    def test_scan_only_does_not_request_or_write_export(self):
        self.app.save_csv_var.set(True)
        self.app.file_path_var.set("/not/a/real/folder/out.csv")
        with patch.object(self.app, "_prepare_export") as export, patch.object(self.app, "_start_worker") as start:
            self.app.start_scan()
        export.assert_not_called()
        self.assertIsNone(self.app._auto_export_path)
        start.assert_called_once()

    def test_small_window_has_visible_controls_and_a_scrollable_table(self):
        self.root.geometry("880x650")
        self.root.update()
        bottom = self.root.winfo_rooty() + self.root.winfo_height()
        for widget in (self.app.scan_amount, self.app.auto_cb, self.app.action_btn, self.app.search_entry,
                       self.app.sort_combo, self.app.status_label, self.app.stop_btn):
            self.assertTrue(widget.winfo_viewable())
            self.assertLessEqual(widget.winfo_rooty() + widget.winfo_height(), bottom)
        self.assertGreater(self.app.tree.winfo_height(), 50)


if __name__ == "__main__":
    unittest.main()
