"""Offline regression tests for v3.1.1 DKIM failure classification."""
from __future__ import annotations

import sys
import types
import unittest
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import gmail_unsubscriber as u
from test_gmail_unsubscriber import DkimTests, OfflineCase, headers


class DkimDiagnosticTests(OfflineCase):
    def sample(self, extra=""):
        return headers(extra=DkimTests.signature + extra) + b"message body\r\n"

    def check(self, verifier, raw=None):
        constructor = MagicMock(return_value=verifier)
        with patch.dict(sys.modules, {"dkim": types.SimpleNamespace(DKIM=constructor)}):
            result = u.verify_one_click_dkim(raw or self.sample(), u.NetworkGuard())
        return result, constructor

    def test_success_still_requires_signature_verification(self):
        verifier = MagicMock()
        verifier.verify.return_value = True
        (success, detail), constructor = self.check(verifier)
        self.assertTrue(success)
        self.assertIn("example.com", detail)
        self.assertEqual(constructor.return_value.verify.call_args.kwargs["idx"], 0)

    def test_false_verification_reports_cryptographic_failure(self):
        verifier = MagicMock()
        verifier.verify.return_value = False
        (success, detail), _ = self.check(verifier)
        self.assertFalse(success)
        self.assertIn("cryptographic", detail)

    def test_library_failure_reports_type_without_private_exception_text(self):
        verifier = MagicMock()
        verifier.verify.side_effect = RuntimeError("unsubscribe-secret-token")
        (success, detail), _ = self.check(verifier)
        self.assertFalse(success)
        self.assertIn("RuntimeError", detail)
        self.assertNotIn("unsubscribe-secret-token", detail)

    def test_dns_nxdomain_is_distinguished(self):
        verifier = MagicMock()
        verifier.verify.side_effect = lambda idx, dnsfunc: bool(
            dnsfunc(b"selector._domainkey.example.com.", timeout=5))
        with patch("dns.resolver.Resolver") as resolver:
            resolver.return_value.resolve.side_effect = dns.resolver.NXDOMAIN()
            (success, detail), _ = self.check(verifier)
        self.assertFalse(success)
        self.assertIn("NXDOMAIN", detail)

    def test_dns_timeout_is_distinguished(self):
        verifier = MagicMock()
        verifier.verify.side_effect = lambda idx, dnsfunc: bool(
            dnsfunc(b"selector._domainkey.example.com.", timeout=5))
        with patch("dns.resolver.Resolver") as resolver:
            resolver.return_value.resolve.side_effect = dns.exception.Timeout()
            (success, detail), _ = self.check(verifier)
        self.assertFalse(success)
        self.assertIn("timed out", detail)

    def test_multiple_dns_records_are_not_accepted(self):
        verifier = MagicMock()
        verifier.verify.side_effect = lambda idx, dnsfunc: bool(
            dnsfunc(b"selector._domainkey.example.com.", timeout=5))
        with patch("dns.resolver.Resolver") as resolver:
            resolver.return_value.resolve.return_value = [
                types.SimpleNamespace(strings=[b"v=DKIM1; p=one"]),
                types.SimpleNamespace(strings=[b"v=DKIM1; p=two"]),
            ]
            (success, detail), _ = self.check(verifier)
        self.assertFalse(success)
        self.assertIn("ambiguous", detail)

    def test_missing_header_coverage_stays_manual(self):
        verifier = MagicMock()
        verifier.verify.return_value = True
        raw = self.sample().replace(
            b"h=from:list-unsubscribe:list-unsubscribe-post", b"h=from:subject")
        (success, detail), constructor = self.check(verifier, raw)
        self.assertFalse(success)
        self.assertIn("covers both", detail)
        constructor.assert_not_called()

    def test_bad_signature_does_not_trigger_post(self):
        with patch.object(u, "submit_one_click", side_effect=AssertionError("POST not permitted")) as post:
            verifier = MagicMock()
            verifier.verify.return_value = False
            (success, _), _ = self.check(verifier)
        self.assertFalse(success)
        post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
