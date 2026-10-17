"""Tests for parsing, network checks, requests, exports, and the GUI.

Run with python -m unittest discover -v. GUI tests need a desktop display.
Network calls are blocked, and the DKIM verifier is mocked.
"""
import csv
import gc
import imaplib
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
import types
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import gmail_unsubscriber as u

ACCOUNT = "reviewer@gmail.com"
PASSWORD = "fake-app-password"
POST_URL = "https://lists.example.com/unsubscribe/token"
MAIL_URL = "mailto:unsubscribe%2Btoken@example.com?subject=Stop&body=required%2Btoken"


def headers(links=None, *, post=u.POST_VALUE, sender="Newsletter <news@example.com>", list_id="<one.example.com>", extra=""):
    if links is None:
        links = [POST_URL, MAIL_URL]
    text = f"From: {sender}\r\nSubject: Test newsletter\r\nList-ID: {list_id}\r\n"
    text += "List-Unsubscribe: " + ", ".join(f"<{link}>" for link in links) + "\r\n"
    if post is not None:
        text += f"List-Unsubscribe-Post: {post}\r\n"
    text += extra
    return (text + "\r\n").encode("utf-8")


def candidate(links=None, **kwargs):
    return u.parse_candidate(headers(links, **kwargs), "10", "123")


def imap_mock(raw=None):
    mail = MagicMock()
    mail.login.return_value = ("OK", [b"logged in"])
    mail.select.return_value = ("OK", [b"1"])
    mail.response.return_value = ("UIDVALIDITY", [b"123"])
    mail.logout.return_value = ("BYE", [b"bye"])
    raw = raw or headers()

    def uid(command, *args):
        if command == "search":
            return "OK", [b"10"]
        if args[-1] == "(RFC822.SIZE)":
            return "OK", [b"1 (UID 10 RFC822.SIZE " + str(len(raw)).encode() + b")"]
        return "OK", [(b"1 (UID 10 BODY[] {1}", raw), b")"]

    mail.uid.side_effect = uid
    return mail


class OfflineCase(unittest.TestCase):
    def setUp(self):
        # Collect old Tk windows on the main thread before starting workers.
        gc.collect()
        self.addCleanup(patch.stopall)
        state_folder = tempfile.TemporaryDirectory()
        self.addCleanup(state_folder.cleanup)
        patch.dict(os.environ, {"XDG_STATE_HOME": state_folder.name,
                                    "LOCALAPPDATA": state_folder.name}).start()
        patch("scan_history.history_path", return_value=Path(state_folder.name) / "progress.sqlite3").start()
        for name in ("socket.socket.connect", "socket.socket.connect_ex", "socket.socket.sendto"):
            patch(name, side_effect=AssertionError("Live network is forbidden in regression tests")).start()
        patch("socket.getaddrinfo", side_effect=AssertionError("Live DNS is forbidden in regression tests")).start()
        patch.object(u, "SEND_INTERVAL", 0).start()
        patch.object(u, "IMAP_RETRY_DELAY", 0).start()


class ParsingTests(OfflineCase):
    def test_valid_one_click_marker(self):
        self.assertEqual(candidate().targets[0].method, "POST")

    def test_substring_is_not_one_click(self):
        for value in ("Not-One-Click", "x=One-Click", u.POST_VALUE + "; x=y", "One-Click"):
            with self.subTest(value=value):
                self.assertNotIn("POST", [t.method for t in candidate(post=value).targets])

    def test_duplicate_headers_are_blocked(self):
        for extra in ("List-Unsubscribe: <https://other.example.com/>\r\n",
                      "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"):
            self.assertTrue(all(t.method == "BLOCKED" for t in candidate(extra=extra).targets))

    def test_duplicate_from_is_blocked(self):
        self.assertTrue(all(t.method == "BLOCKED" for t in candidate(extra="From: fake@example.com\r\n").targets))

    def test_multiple_https_links_are_manual(self):
        c = candidate([POST_URL, "https://other.example.com/unsubscribe"])
        self.assertTrue(all(t.method == "MANUAL" for t in c.targets))

    def test_http_is_never_automatic(self):
        self.assertEqual(candidate(["http://example.com/unsubscribe"]).targets[0].method, "MANUAL")

    def test_sender_does_not_define_subscription(self):
        self.assertNotEqual(candidate([POST_URL]).key, candidate([POST_URL + "-different"]).key)

    def test_exact_target_sets_are_deduplicated(self):
        self.assertEqual(candidate([POST_URL, MAIL_URL]).key, candidate([MAIL_URL, POST_URL]).key)

    def test_missing_angle_brackets_is_blocked(self):
        raw = b"From: news@example.com\r\nList-Unsubscribe: https://example.com/unsubscribe\r\n\r\n"
        self.assertEqual(u.parse_candidate(raw, "10", "123").targets[0].method, "BLOCKED")

    def test_unknown_charset_falls_back(self):
        self.assertEqual(u.decode_mime_header("=?invalid-charset?b?SGVsbG8=?="), "Hello")

    def test_mailto_decodes_recipient_and_preserves_body(self):
        result = u.parse_mailto(MAIL_URL)
        self.assertEqual(result.recipients, ("unsubscribe+token@example.com",))
        self.assertEqual(result.subject, "Stop")
        self.assertEqual(result.body, "required+token")

    def test_mailto_literal_plus_is_not_a_space(self):
        result = u.parse_mailto("mailto:unsubscribe+tag@example.com?subject=A+B&body=C+D")
        self.assertEqual(result.subject, "A+B")
        self.assertEqual(result.body, "C+D")

    def test_mailto_utf8_and_newline_body(self):
        result = u.parse_mailto("mailto:x@example.com?subject=caf%C3%A9&body=line1%0D%0Aline2")
        self.assertEqual(result.subject, "caf\u00e9")
        self.assertEqual(result.body, "line1\r\nline2")

    def test_mailto_defaults_and_empty_values(self):
        self.assertEqual(u.parse_mailto("mailto:x@example.com").subject, "Unsubscribe")
        self.assertEqual(u.parse_mailto("mailto:x@example.com?subject=&body=").body, "")

    def test_mailto_injection_and_extra_headers_rejected(self):
        bad = [
            "mailto:x@example.com?subject=ok%0D%0ABcc:evil@example.com",
            "mailto:x%0D%0A@example.com", "mailto:x@example.com?bcc=evil@example.com",
            "mailto:x@example.com?cc=evil@example.com", "mailto:x@example.com?to=evil@example.com",
            "mailto:x@example.com?subject=one&subject=two", "mailto:x@example.com?body=a&body=b",
            "mailto:x@example.com?body=%00", "mailto:x@example.com?body=%ZZ", "mailto:x@example.com#fragment",
            "mailto://x@example.com", "mailto:", "mailto:x@example.com?subject=%FF",
        ]
        for value in bad:
            with self.subTest(uri=value):
                with self.assertRaises((u.SafetyError, ValueError)):
                    u.parse_mailto(value)

    def test_mailto_multiple_recipients_are_visible(self):
        result = u.parse_mailto("mailto:one@example.com,two@example.com,one@example.com")
        self.assertEqual(result.recipients, ("one@example.com", "two@example.com"))

    def test_unsafe_web_urls_rejected(self):
        urls = [
            "http://example.com/u", "https://127.0.0.1/u", "https://[::1]/u", "https://localhost/u",
            "https://server.local/u", "https://printer.home.arpa/u", "https://a.internal/u",
            "https://example.com:8080/u", "https://example.com:0/u", "https://example.com:/u",
            "https://user:pass@example.com/u", "https://example.com/u#fragment", "https://2130706433/u",
            "https://0177.0.0.1/u", " https://example.com/u", "https://example.com/\r\nx",
            "https://example.com\\@other.com/u", "https://example.com/%zz", "https:///missing-host",
            "https://example.com/u\x00", "https://example.com:65536/u",
        ]
        for value in urls:
            with self.subTest(url=value):
                with self.assertRaises(u.SafetyError):
                    u.parse_web_url(value)

    def test_valid_https_url(self):
        result = u.parse_web_url("HTTPS://Lists.Example.com:443/unsubscribe?token=A%2BB")
        self.assertEqual(result.host, "lists.example.com")
        self.assertEqual(result.path, "/unsubscribe?token=A%2BB")
        self.assertEqual(result.port, 443)

    def test_nonpublic_and_transition_ips_rejected(self):
        for address in ("127.0.0.1", "10.1.2.3", "172.16.1.1", "192.168.1.1", "169.254.169.254",
                        "100.64.0.1", "0.0.0.0", "192.0.0.9", "198.18.0.1", "224.0.0.1", "255.255.255.255",
                        "::1", "fe80::1", "fc00::1", "::ffff:8.8.8.8", "2002:0808:0808::1", "64:ff9b::808:808"):
            with self.subTest(address=address):
                self.assertFalse(u.is_public_ip(address))
        self.assertTrue(u.is_public_ip("8.8.8.8"))
        self.assertTrue(u.is_public_ip("2606:4700:4700::1111"))


class NetworkTests(OfflineCase):
    def test_dns_mixed_public_private_fails_closed(self):
        resolver = MagicMock()
        resolver.resolve.side_effect = [[types.SimpleNamespace(address="8.8.8.8")],
                                        [types.SimpleNamespace(address="::1")]]
        with patch.object(u, "_system_addresses", side_effect=socket.gaierror("simulated OS lookup failure")), \
                patch("dns.resolver.Resolver", return_value=resolver):
            with self.assertRaises(u.SafetyError):
                u.resolve_public_addresses("example.com", u.NetworkGuard())
        self.assertFalse(resolver.resolve.call_args.kwargs["search"])
        self.assertLessEqual(resolver.resolve.call_args.kwargs["lifetime"], u.DNS_TIMEOUT)

    def test_dns_public_results_are_deduplicated(self):
        resolver = MagicMock()
        resolver.resolve.side_effect = [[types.SimpleNamespace(address="8.8.8.8"), types.SimpleNamespace(address="8.8.8.8")], []]
        with patch.object(u, "_system_addresses", side_effect=socket.gaierror("simulated OS lookup failure")), \
                patch("dns.resolver.Resolver", return_value=resolver):
            self.assertEqual(u.resolve_public_addresses("example.com", u.NetworkGuard()), ("8.8.8.8",))

    def test_dns_failure_is_not_ignored(self):
        import dns.resolver
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.resolver.NXDOMAIN
        with patch.object(u, "_system_addresses", side_effect=socket.gaierror("simulated OS lookup failure")), \
                patch("dns.resolver.Resolver", return_value=resolver):
            with self.assertRaises(u.DNSResolutionError):
                u.resolve_public_addresses("example.com", u.NetworkGuard())

    def test_connect_pins_ip_and_verifies_original_hostname(self):
        raw, wrapped, context = MagicMock(), MagicMock(), MagicMock()
        context.wrap_socket.return_value = wrapped
        guard = u.NetworkGuard()
        with patch.object(u, "resolve_public_addresses", return_value=("8.8.8.8",)) as resolver, \
                patch.object(u.socket, "socket", return_value=raw):
            result = u.connect_tls("example.com", 443, context, guard)
        resolver.assert_called_once()
        raw.connect.assert_called_once_with(("8.8.8.8", 443))
        context.wrap_socket.assert_called_once_with(raw, server_hostname="example.com", do_handshake_on_connect=False)
        wrapped.do_handshake.assert_called_once()
        self.assertIs(result, wrapped)
        guard.abort_sockets()

    def test_imap_constructor_uses_verifying_context(self):
        with patch.object(imaplib.IMAP4_SSL, "__init__", return_value=None) as init:
            u.VerifiedIMAP(u.NetworkGuard())
        context = init.call_args.kwargs["ssl_context"]
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertEqual(init.call_args.kwargs["timeout"], u.IO_TIMEOUT)

    def test_smtp_constructor_uses_verifying_context(self):
        with patch.object(u.smtplib.SMTP_SSL, "__init__", return_value=None) as init:
            u.VerifiedSMTP(u.NetworkGuard())
        self.assertEqual(init.call_args.args[:2], ("smtp.gmail.com", 465))
        context = init.call_args.kwargs["context"]
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def test_stop_closes_active_sockets(self):
        sock = MagicMock()
        guard = u.NetworkGuard()
        guard.watch(sock)
        guard.cancel()
        sock.shutdown.assert_called_once()
        sock.close.assert_called_once()
        with self.assertRaises(u.Cancelled):
            guard.check()

    def test_operation_watchdog_aborts_slow_operation(self):
        guard = u.NetworkGuard()
        sock = MagicMock()
        stopped = threading.Event()
        sock.shutdown.side_effect = lambda *_: stopped.set()
        guard.watch(sock)
        with self.assertRaises(TimeoutError):
            with guard.operation(0.03):
                self.assertTrue(stopped.wait(1))
        self.assertIsNone(guard._expired)

    def test_operation_timer_does_not_fire_after_exit(self):
        guard = u.NetworkGuard()
        sock = MagicMock()
        guard.watch(sock)
        with guard.operation(0.03):
            pass
        time.sleep(0.05)
        sock.shutdown.assert_not_called()
        guard.abort_sockets()


class ImapTests(OfflineCase):
    def test_scan_uses_readonly_uid_and_peek(self):
        mail = imap_mock()
        events = []
        with patch.object(u, "VerifiedIMAP", return_value=mail), patch.object(u, "submit_one_click") as post, patch.object(u, "send_mailto") as smtp:
            u.scan_mailbox(ACCOUNT, PASSWORD, 1000, u.NetworkGuard(), lambda *item: events.append(item))
        mail.select.assert_called_once_with("INBOX", readonly=True)
        self.assertEqual(mail.uid.call_args_list[0].args, ("search", None, "ALL"))
        self.assertIn("BODY.PEEK[HEADER.FIELDS", mail.uid.call_args_list[1].args[-1])
        self.assertEqual(len([e for e in events if e[0] == "candidate"]), 1)
        post.assert_not_called()
        smtp.assert_not_called()
        mail.logout.assert_called_once()
        mail.shutdown.assert_called()

    def test_authentication_failure_is_distinct(self):
        mail = imap_mock()
        mail.login.side_effect = imaplib.IMAP4.error("bad credentials")
        with patch.object(u, "VerifiedIMAP", return_value=mail), self.assertRaises(u.AuthenticationError):
            with u.gmail_inbox(ACCOUNT, PASSWORD, u.NetworkGuard()):
                pass
        mail.shutdown.assert_called()

    def test_search_failure_is_not_login_failure(self):
        mail = imap_mock()
        mail.uid.side_effect = None
        mail.uid.return_value = ("NO", [b"search failed"])
        with patch.object(u, "VerifiedIMAP", return_value=mail), self.assertRaises(u.MailboxError):
            u.scan_mailbox(ACCOUNT, PASSWORD, 1000, u.NetworkGuard(), lambda *_: None)
        self.assertEqual(mail.logout.call_count, u.IMAP_READ_ATTEMPTS)

    def test_select_status_checked(self):
        mail = imap_mock()
        mail.select.return_value = ("NO", [b"no inbox"])
        with patch.object(u, "VerifiedIMAP", return_value=mail), self.assertRaises(u.MailboxError):
            with u.gmail_inbox(ACCOUNT, PASSWORD, u.NetworkGuard()):
                pass
        mail.shutdown.assert_called()

    def test_empty_inbox(self):
        mail = imap_mock()
        mail.uid.side_effect = None
        mail.uid.return_value = ("OK", [b""])
        events = []
        with patch.object(u, "VerifiedIMAP", return_value=mail):
            u.scan_mailbox(ACCOUNT, PASSWORD, 1000, u.NetworkGuard(), lambda *item: events.append(item))
        self.assertFalse(any(kind == "candidate" for kind, _ in events))
        mail.logout.assert_called_once()

    def test_malformed_search_is_an_error(self):
        mail = imap_mock()
        mail.uid.side_effect = None
        mail.uid.return_value = ("OK", ["not bytes"])
        with patch.object(u, "VerifiedIMAP", return_value=mail), self.assertRaises(u.MailboxError):
            u.scan_mailbox(ACCOUNT, PASSWORD, 1000, u.NetworkGuard(), lambda *_: None)

    def test_full_message_fetch_is_peek_and_complete(self):
        raw = headers() + b"message body\r\n"
        mail = imap_mock(raw)
        self.assertEqual(u.fetch_for_verification(mail, candidate(), u.NetworkGuard()), raw)
        self.assertIn("BODY.PEEK[]", mail.uid.call_args_list[-1].args[-1])

    def test_changed_headers_block_post(self):
        mail = imap_mock(headers([POST_URL + "different"]))
        with self.assertRaises(u.SafetyError):
            u.fetch_for_verification(mail, candidate(), u.NetworkGuard())

    def test_oversized_message_not_fetched(self):
        mail = imap_mock()
        mail.uid.side_effect = None
        mail.uid.return_value = ("OK", [f"1 (RFC822.SIZE {u.MAX_MESSAGE + 1})".encode()])
        with self.assertRaises(u.SafetyError):
            u.fetch_for_verification(mail, candidate(), u.NetworkGuard())
        mail.uid.assert_called_once()

    def test_stale_uidvalidity_stops_entire_batch(self):
        mail = imap_mock()
        mail.response.return_value = ("UIDVALIDITY", [b"999"])
        with patch.object(u, "VerifiedIMAP", return_value=mail), patch.object(u, "send_mailto") as send, self.assertRaises(u.StaleScanError):
            u.process_selected((candidate(), candidate([POST_URL + "2"])), ACCOUNT, PASSWORD,
                               u.NetworkGuard(), {}, lambda *_: None)
        send.assert_not_called()


class HttpTests(OfflineCase):
    def perform(self, status=204, connect_error=None, request_error=None, response_error=None):
        connection = MagicMock()
        connection.getresponse.return_value.status = status
        connection.connect.side_effect = connect_error
        connection.request.side_effect = request_error
        connection.getresponse.side_effect = response_error
        with patch.object(u, "PinnedHTTPSConnection", return_value=connection):
            result = u.submit_one_click(POST_URL, u.NetworkGuard())
        return result, connection

    def test_2xx_means_accepted_not_unsubscribed(self):
        for code in (200, 202, 204, 299):
            with self.subTest(code=code):
                result, _ = self.perform(code)
                self.assertEqual(result[0], "Request accepted")
                self.assertIn("not independently confirmed", result[1])

    def test_http_errors_are_failures(self):
        for code in (400, 403, 404, 429, 500, 503):
            with self.subTest(code=code):
                result, _ = self.perform(code)
                self.assertEqual(result[0], "Failed")

    def test_redirects_never_followed(self):
        for code in (301, 302, 303, 307, 308):
            result, connection = self.perform(code)
            self.assertEqual(result[0], "Failed")
            connection.request.assert_called_once()
            self.assertIn("redirect blocked", result[1])

    def test_fixed_post_payload_no_cookies_authorization_or_body_download(self):
        _, connection = self.perform()
        self.assertEqual(connection.request.call_args.args[0], "POST")
        self.assertEqual(connection.request.call_args.kwargs["body"], u.POST_BODY)
        outgoing = {k.lower() for k in connection.request.call_args.kwargs["headers"]}
        self.assertNotIn("cookie", outgoing)
        self.assertNotIn("authorization", outgoing)
        connection.getresponse.return_value.read.assert_not_called()
        connection.close.assert_called_once()

    def test_connect_failure_before_sending_is_failed(self):
        result, connection = self.perform(connect_error=ConnectionRefusedError())
        self.assertEqual(result[0], "Failed")
        connection.request.assert_not_called()

    def test_timeout_after_request_may_be_unknown(self):
        result, _ = self.perform(response_error=TimeoutError())
        self.assertEqual(result[0], "Outcome unknown")

    def test_exception_mid_send_may_be_unknown(self):
        result, _ = self.perform(request_error=ConnectionResetError())
        self.assertEqual(result[0], "Outcome unknown")

    def test_cancel_mid_send_is_unknown(self):
        result, _ = self.perform(request_error=u.Cancelled())
        self.assertEqual(result[0], "Outcome unknown")

    def test_cancel_before_connect_sends_nothing(self):
        guard = u.NetworkGuard()
        guard.cancel()
        with patch.object(u, "PinnedHTTPSConnection") as connection, self.assertRaises(u.Cancelled):
            u.submit_one_click(POST_URL, guard)
        connection.return_value.connect.assert_not_called()


class SmtpTests(OfflineCase):
    def smtp(self):
        smtp = MagicMock()
        smtp.ehlo.return_value = (250, b"OK")
        smtp.send_message.return_value = {}
        return smtp

    def test_email_submission_preserves_token_and_decoded_recipient(self):
        smtp = self.smtp()
        with patch.object(u, "VerifiedSMTP", return_value=smtp):
            result = u.send_mailto(MAIL_URL, ACCOUNT, PASSWORD, u.NetworkGuard())
        self.assertEqual(result[0], "Email submitted")
        msg = smtp.send_message.call_args.args[0]
        self.assertEqual(str(msg["Subject"]), "Stop")
        self.assertEqual(msg.get_content().strip(), "required+token")
        self.assertEqual(smtp.send_message.call_args.kwargs["to_addrs"], ["unsubscribe+token@example.com"])
        self.assertEqual(smtp.send_message.call_args.kwargs["from_addr"], ACCOUNT)
        smtp.close.assert_called_once()

    def test_partial_recipients_are_not_success(self):
        smtp = self.smtp()
        smtp.send_message.return_value = {"one@example.com": (550, b"no")}
        with patch.object(u, "VerifiedSMTP", return_value=smtp):
            result = u.send_mailto("mailto:one@example.com,two@example.com", ACCOUNT, PASSWORD, u.NetworkGuard())
        self.assertEqual(result[0], "Partial email submission")

    def test_authentication_failure_stops_batch(self):
        smtp = self.smtp()
        smtp.login.side_effect = u.smtplib.SMTPAuthenticationError(535, b"denied")
        with patch.object(u, "VerifiedSMTP", return_value=smtp), self.assertRaises(u.AuthenticationError):
            u.send_mailto(MAIL_URL, ACCOUNT, PASSWORD, u.NetworkGuard())
        smtp.send_message.assert_not_called()
        smtp.close.assert_called_once()

    def test_explicit_rejection_is_failure(self):
        smtp = self.smtp()
        smtp.send_message.side_effect = u.smtplib.SMTPDataError(550, b"rejected")
        with patch.object(u, "VerifiedSMTP", return_value=smtp):
            self.assertEqual(u.send_mailto(MAIL_URL, ACCOUNT, PASSWORD, u.NetworkGuard())[0], "Failed")

    def test_mid_send_disconnect_is_unknown(self):
        smtp = self.smtp()
        smtp.send_message.side_effect = u.smtplib.SMTPServerDisconnected("lost")
        with patch.object(u, "VerifiedSMTP", return_value=smtp):
            self.assertEqual(u.send_mailto(MAIL_URL, ACCOUNT, PASSWORD, u.NetworkGuard())[0], "Outcome unknown")


class DkimTests(OfflineCase):
    signature = "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=test; h=from:list-unsubscribe:list-unsubscribe-post; b=fake\r\n"

    def test_full_message_and_signature_index_passed_to_library(self):
        raw = headers(extra=self.signature) + b"body\r\n"
        ctor = MagicMock()
        ctor.return_value.verify.return_value = True
        with patch.dict(sys.modules, {"dkim": types.SimpleNamespace(DKIM=ctor)}):
            verified, detail = u.verify_one_click_dkim(raw, u.NetworkGuard())
        self.assertTrue(verified)
        self.assertIn("example.com", detail)
        self.assertIs(ctor.call_args.args[0], raw)
        self.assertEqual(ctor.return_value.verify.call_args.kwargs["idx"], 0)
        self.assertTrue(callable(ctor.return_value.verify.call_args.kwargs["dnsfunc"]))

    def test_unsigned_unsubscribe_headers_are_not_accepted(self):
        ctor = MagicMock()
        extra = self.signature.replace("h=from:list-unsubscribe:list-unsubscribe-post", "h=from:subject")
        with patch.dict(sys.modules, {"dkim": types.SimpleNamespace(DKIM=ctor)}):
            self.assertFalse(u.verify_one_click_dkim(headers(extra=extra), u.NetworkGuard())[0])
        ctor.assert_not_called()

    def test_invalid_signature_fails_closed(self):
        ctor = MagicMock()
        ctor.return_value.verify.return_value = False
        with patch.dict(sys.modules, {"dkim": types.SimpleNamespace(DKIM=ctor)}):
            self.assertFalse(u.verify_one_click_dkim(headers(extra=self.signature), u.NetworkGuard())[0])

    def test_forged_authentication_results_does_not_count(self):
        ctor = MagicMock()
        raw = headers(extra="Authentication-Results: mx.google.com; dkim=pass header.d=example.com\r\n")
        with patch.dict(sys.modules, {"dkim": types.SimpleNamespace(DKIM=ctor)}):
            self.assertFalse(u.verify_one_click_dkim(raw, u.NetworkGuard())[0])
        ctor.assert_not_called()

    def test_missing_dkim_dependency_disables_post(self):
        with patch.dict(sys.modules, {"dkim": None}):
            verified, detail = u.verify_one_click_dkim(headers(), u.NetworkGuard())
        self.assertFalse(verified)
        self.assertIn("dependencies are missing", detail)

    def test_rejects_sha1_signature(self):
        ctor = MagicMock()
        with patch.dict(sys.modules, {"dkim": types.SimpleNamespace(DKIM=ctor)}):
            self.assertFalse(u.verify_one_click_dkim(headers(extra=self.signature.replace("rsa-sha256", "rsa-sha1")), u.NetworkGuard())[0])
        ctor.assert_not_called()


class ExecutionTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.guard = u.NetworkGuard()
        self.attempted = set()
        self.ledger = {}
        self.events = []
        self.fetch = MagicMock(return_value=headers())
        self.post = patch.object(u, "submit_one_click", return_value=("Request accepted", "HTTP 204")).start()
        self.send = patch.object(u, "send_mailto", return_value=("Email submitted", "accepted")).start()
        self.verify = patch.object(u, "verify_one_click_dkim", return_value=(True, "Verified")).start()

    def execute(self, c):
        u.execute_candidate(c, ACCOUNT, PASSWORD, self.guard, self.fetch, self.attempted, self.ledger,
                            lambda *item: self.events.append(item))

    def test_successful_post_does_not_also_send_email(self):
        self.execute(candidate())
        self.post.assert_called_once()
        self.send.assert_not_called()
        self.assertEqual(self.ledger[(ACCOUNT, "POST", POST_URL)], "Request accepted")

    def test_identical_completed_entry_does_not_send_new_fallback_on_rescan(self):
        self.execute(candidate())
        self.attempted.clear()
        self.execute(candidate())
        self.post.assert_called_once()
        self.send.assert_not_called()

    def test_failed_post_allows_mailto_fallback(self):
        self.post.return_value = ("Failed", "HTTP 500")
        self.execute(candidate())
        self.send.assert_called_once()
        self.assertNotIn((ACCOUNT, "POST", POST_URL), self.ledger)

    def test_failed_shared_url_does_not_skip_untried_alternative(self):
        self.post.return_value = ("Failed", "HTTP 500")
        self.execute(candidate([POST_URL]))
        self.execute(candidate([POST_URL, MAIL_URL]))
        self.post.assert_called_once()
        self.send.assert_called_once()

    def test_same_sender_distinct_lists_both_processed(self):
        self.execute(candidate([POST_URL]))
        self.execute(candidate([POST_URL + "-other"]))
        self.assertEqual(self.post.call_count, 2)

    def test_already_submitted_target_does_not_hide_new_alternative(self):
        self.ledger[(ACCOUNT, "POST", POST_URL)] = "Request accepted"
        self.execute(candidate())
        self.post.assert_not_called()
        self.send.assert_called_once()

    def test_unverified_post_never_sent(self):
        self.verify.return_value = (False, "invalid signature")
        self.execute(candidate())
        self.post.assert_not_called()
        self.send.assert_called_once()

    def test_unsigned_message_does_not_poison_attempt_tracking(self):
        self.verify.return_value = (False, "invalid")
        self.execute(candidate([POST_URL]))
        self.verify.return_value = (True, "valid")
        self.execute(candidate([POST_URL]))
        self.post.assert_called_once()

    def test_unknown_outcome_stops_fallback_and_is_not_retried(self):
        self.post.return_value = ("Outcome unknown", "timeout")
        self.execute(candidate())
        self.execute(candidate())
        self.post.assert_called_once()
        self.send.assert_not_called()

    def test_manual_web_page_is_never_fetched(self):
        self.execute(candidate([POST_URL], post=None))
        self.post.assert_not_called()
        self.send.assert_not_called()
        self.fetch.assert_not_called()
        self.assertEqual(self.events[-1][1].status, "Manual action required")

    def test_cancelled_batch_sends_nothing_else(self):
        self.guard.cancel()
        with self.assertRaises(u.Cancelled):
            self.execute(candidate())
        self.post.assert_not_called()
        self.send.assert_not_called()

    def test_ledger_is_account_specific(self):
        self.ledger[("other@gmail.com", "POST", POST_URL)] = "Request accepted"
        self.execute(candidate([POST_URL]))
        self.post.assert_called_once()


class ExportTests(OfflineCase):
    def result(self):
        c = candidate(sender="=HYPERLINK(attack) <news@example.com>")
        return u.Result(c, ACCOUNT, "POST", POST_URL, "Request accepted", "=dangerous-formula")

    def test_formula_cells_are_all_forced_to_text(self):
        for text in ("=1+1", "+SUM(A1)", "-1+1", "@SUM(A1)", "\t=1+1", "\r\n=1+1", "  =1+1", "normal text", "\uff1d1+1"):
            self.assertTrue(u.csv_text(text).startswith("'"))
        self.assertEqual(u.csv_text(""), "")

    def test_csv_has_correct_header_and_sanitized_cells(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.csv"
            u.export_results(path, [self.result()])
            with path.open(encoding="utf-8-sig", newline="") as stream:
                rows = list(csv.reader(stream))
            self.assertEqual(rows[0], list(u.CSV_COLUMNS))
            self.assertTrue(all(not value or value.startswith("'") for value in rows[1]))
            self.assertEqual(rows[1][8], "'Request accepted")

    def test_export_failure_does_not_destroy_existing_file(self):
        results = [self.result()]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.csv"
            path.write_text("existing data")
            with patch.object(u.os, "replace", side_effect=PermissionError("file open")), self.assertRaises(PermissionError):
                u.export_results(path, results)
            self.assertEqual(path.read_text(), "existing data")
            self.assertEqual(len(list(Path(directory).iterdir())), 1)
        self.assertEqual(results[0].status, "Request accepted")


@unittest.skipUnless(os.name == "nt" or os.environ.get("DISPLAY"), "GUI tests require a Windows desktop or Xvfb DISPLAY.")
class GuiTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.root = u.tk.Tk()
        self.app = u.UnsubscribeApp(self.root)
        self.root.update()
        patch.object(u.messagebox, "showerror", side_effect=AssertionError("Unexpected error dialog")).start()

    def tearDown(self):
        if self.app.worker is not None and self.app.worker.is_alive():
            self.app.guard.cancel()
            self.app.worker.join(1)
        if not self.app.destroyed:
            self.app._destroy()

    def pump(self, predicate, timeout=2):
        end = time.monotonic() + timeout
        while not predicate() and time.monotonic() < end:
            if self.app.destroyed:
                break
            self.root.update()
            time.sleep(0.01)
        self.assertTrue(predicate())

    def test_startup_idle_and_no_selection(self):
        self.assertFalse(self.app.is_running)
        self.assertEqual(self.app.tree.selection(), ())
        self.assertFalse(self.app.auto_var.get())
        self.assertEqual(str(self.app.action_btn["state"]), "disabled")
        self.assertEqual(self.app.start_btn["text"], "Scan inbox")

    def test_worker_only_queues_events_and_returns_to_idle(self):
        caller_threads = []
        main_thread = threading.get_ident()
        original_log = self.app.log

        def logged(message):
            caller_threads.append(threading.get_ident())
            original_log(message)

        self.app.log = logged

        def worker(*, guard, emit):
            emit("candidate", candidate())
            emit("log", "Worker event")

        self.app._start_worker(worker, (), PASSWORD)
        self.pump(lambda: not self.app.is_running)
        self.assertEqual(self.app.tree.selection(), ())
        self.assertEqual(len(self.app.candidates), 1)
        self.assertTrue(all(ident == main_thread for ident in caller_threads))

    def test_close_cancels_and_joins_worker_before_destroying_window(self):
        def worker(*, guard, emit):
            guard.stop_event.wait(1)
            guard.check()

        self.app._start_worker(worker, (), PASSWORD)
        thread = self.app.worker
        with patch.object(u.messagebox, "askyesno", return_value=True):
            self.app.on_close()
        self.pump(lambda: self.app.destroyed)
        self.assertFalse(thread.is_alive())

    def test_cancelling_entire_inbox_starts_no_work(self):
        self.app.scan_choice_var.set("Entire inbox")
        with patch.object(self.app, "credentials", return_value=(ACCOUNT, PASSWORD)), \
                patch.object(u.messagebox, "askyesno", return_value=False), \
                patch.object(self.app, "_start_worker") as start:
            self.app.start_scan()
        start.assert_not_called()


if __name__ == "__main__":
    unittest.main()
