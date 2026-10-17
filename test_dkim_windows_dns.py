"""Regression tests for the Windows DKIM DNS fallback added in v3.1.3.

All DNS results, Windows processes, and DKIM signatures are simulated.
"""
from __future__ import annotations

import base64
import subprocess
import sys
import types
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import gmail_unsubscriber as u
from test_gmail_unsubscriber import DkimTests, OfflineCase, headers

DNS_NAME = b"selector._domainkey.example.com."
DNS_KEY = b"v=DKIM1; k=rsa; p=abCDE123=="


class WindowsDkimDnsTests(OfflineCase):
    def sample(self):
        return headers(extra=DkimTests.signature) + b"synthetic body\r\n"

    def verify(self, response, *, platform="win32", native=None, python_error=None):
        verifier = MagicMock()

        def simulated_verification(*, idx, dnsfunc):
            key = dnsfunc(DNS_NAME, timeout=5)
            return key == DNS_KEY if response else False

        verifier.verify.side_effect = simulated_verification
        factory = MagicMock(return_value=verifier)
        resolver = MagicMock()
        resolver.resolve.side_effect = python_error or dns.exception.Timeout()
        with patch.object(u.sys, "platform", platform), \
                patch("dns.resolver.Resolver", return_value=resolver), \
                patch.object(u, "_windows_dkim_txt_lookup", return_value=native or (None, "No Windows TXT answer.")) as lookup, \
                patch.dict(sys.modules, {"dkim": types.SimpleNamespace(DKIM=factory)}):
            result = u.verify_one_click_dkim(self.sample(), u.NetworkGuard())
        return result, lookup, factory

    def test_dns_timeout_uses_native_windows_resolver(self):
        (success, detail), lookup, _ = self.verify(True, native=(DNS_KEY, ""))
        self.assertTrue(success)
        self.assertIn("DKIM verified", detail)
        lookup.assert_called_once()

    def test_windows_key_lookup_does_not_bypass_bad_signature(self):
        (success, detail), lookup, _ = self.verify(False, native=(DNS_KEY, ""))
        self.assertFalse(success)
        self.assertIn("cryptographic", detail)
        lookup.assert_called_once()

    def test_second_lookup_uses_windows_after_first_python_timeout(self):
        verifier = MagicMock()
        verifier.verify.side_effect = lambda *, idx, dnsfunc: dnsfunc(DNS_NAME) == DNS_KEY
        factory = MagicMock(return_value=verifier)
        guard = u.NetworkGuard()
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.exception.Timeout()
        with patch.object(u.sys, "platform", "win32"), \
                patch("dns.resolver.Resolver", return_value=resolver), \
                patch.object(u, "_windows_dkim_txt_lookup", return_value=(DNS_KEY, "")) as lookup, \
                patch.dict(sys.modules, {"dkim": types.SimpleNamespace(DKIM=factory)}):
            self.assertTrue(u.verify_one_click_dkim(self.sample(), guard)[0])
            self.assertTrue(u.verify_one_click_dkim(self.sample(), guard)[0])
        self.assertEqual(resolver.resolve.call_count, 1)
        self.assertEqual(lookup.call_count, 2)

    def test_native_lookup_failure_remains_manual(self):
        (success, detail), lookup, _ = self.verify(True, native=(None, "Windows DNS unavailable."))
        self.assertFalse(success)
        self.assertIn("Windows native DNS", detail)
        lookup.assert_called_once()

    def test_nxdomain_does_not_try_alternate_resolvers(self):
        (success, detail), lookup, _ = self.verify(True, python_error=dns.resolver.NXDOMAIN())
        self.assertFalse(success)
        self.assertIn("NXDOMAIN", detail)
        lookup.assert_not_called()

    def test_non_windows_does_not_call_powershell(self):
        (success, detail), lookup, _ = self.verify(True, platform="linux")
        self.assertFalse(success)
        self.assertIn("timed out", detail)
        lookup.assert_not_called()

    def test_native_dns_decodes_txt_key_without_interpolation(self):
        process = MagicMock()
        process.poll.return_value = 0
        process.returncode = 0
        process.communicate.return_value = (b"TXT:" + base64.b64encode(DNS_KEY) + b"\n", None)
        with patch("subprocess.Popen", return_value=process) as launch:
            value, problem = u._windows_dkim_txt_lookup(DNS_NAME, u.NetworkGuard())
        self.assertEqual((value, problem), (DNS_KEY, ""))
        args = launch.call_args.args[0]
        self.assertTrue(args[0].lower().endswith("powershell.exe"))
        self.assertIn("WindowsPowerShell", args[0])
        self.assertIn("Resolve-DnsName", args[-1])
        self.assertNotIn("selector._domainkey.example.com", args[-1])
        self.assertEqual(launch.call_args.kwargs["env"]["GMAIL_UNSUB_DKIM_QUERY"],
                         "selector._domainkey.example.com.")

    def test_native_key_cache_is_limited_to_worker(self):
        process = MagicMock()
        process.poll.return_value = 0
        process.returncode = 0
        process.communicate.return_value = (b"TXT:" + base64.b64encode(DNS_KEY) + b"\n", None)
        guard = u.NetworkGuard()
        with patch("subprocess.Popen", return_value=process) as launch:
            self.assertEqual(u._windows_dkim_txt_lookup(DNS_NAME, guard)[0], DNS_KEY)
            self.assertEqual(u._windows_dkim_txt_lookup(DNS_NAME, guard)[0], DNS_KEY)
            self.assertEqual(u._windows_dkim_txt_lookup(DNS_NAME, u.NetworkGuard())[0], DNS_KEY)
        self.assertEqual(launch.call_count, 2)

    def test_multiple_txt_records_fail_closed(self):
        process = MagicMock()
        process.poll.return_value = 0
        process.returncode = 0
        process.communicate.return_value = (b"AMBIGUOUS_OR_MISSING\n", None)
        with patch("subprocess.Popen", return_value=process):
            value, problem = u._windows_dkim_txt_lookup(DNS_NAME, u.NetworkGuard())
        self.assertIsNone(value)
        self.assertIn("multiple", problem)

    def test_invalid_selector_cannot_become_powershell_source(self):
        with patch("subprocess.Popen") as launch:
            value, problem = u._windows_dkim_txt_lookup(b"selector';Remove-Item._domainkey.example.com.", u.NetworkGuard())
        self.assertIsNone(value)
        self.assertIn("Invalid DKIM", problem)
        launch.assert_not_called()

    def test_stop_kills_running_native_query(self):
        process = MagicMock()
        process.poll.return_value = None
        process.communicate.side_effect = [subprocess.TimeoutExpired("powershell.exe", .1), (b"", None)]
        guard = u.NetworkGuard()
        def communicate_side_effect(*args, **kwargs):
            if kwargs.get("timeout") == 2:
                return (b"", None)
            guard.stop_event.set()
            raise subprocess.TimeoutExpired("powershell.exe", .1)
        process.communicate.side_effect = communicate_side_effect
        with patch("subprocess.Popen", return_value=process):
            with self.assertRaises(u.Cancelled):
                u._windows_dkim_txt_lookup(DNS_NAME, guard)
        process.kill.assert_called_once()


if __name__ == "__main__":
    import unittest
    unittest.main()
