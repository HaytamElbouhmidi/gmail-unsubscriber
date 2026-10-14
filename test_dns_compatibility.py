"""Tests for DNS fallbacks, timeouts, and connection checks. Network calls are mocked."""
import gc
import os
import queue
import socket
import ssl
import threading
import time
import tkinter as tk
import types
import unittest
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import gmail_unsubscriber as u


def records(*addresses):
    return [types.SimpleNamespace(address=value) for value in addresses]


def infos(*addresses):
    return [(socket.AF_INET6 if ':' in value else socket.AF_INET,
             socket.SOCK_STREAM, socket.IPPROTO_TCP, '',
             (value, 0, 0, 0) if ':' in value else (value, 0)) for value in addresses]


class DNSCase(unittest.TestCase):
    def setUp(self):
        gc.collect()
        for name in ('socket.socket.connect', 'socket.socket.connect_ex',
                     'socket.socket.sendto', 'socket.getaddrinfo'):
            patcher = patch(name, side_effect=AssertionError('Live network/DNS forbidden'))
            patcher.start()
            self.addCleanup(patcher.stop)


class SystemResolverTests(DNSCase):
    def test_os_api_receives_absolute_name_and_tcp_hints(self):
        with patch.object(u.socket, 'getaddrinfo', return_value=infos('8.8.8.8')) as lookup:
            result = u._system_addresses('imap.gmail.com', u.NetworkGuard())
        self.assertEqual(result, ('8.8.8.8',))
        lookup.assert_called_once_with('imap.gmail.com.', 0, socket.AF_UNSPEC,
                                       socket.SOCK_STREAM, socket.IPPROTO_TCP)

    def test_native_results_win_without_using_direct_dns(self):
        with patch.object(u.socket, 'getaddrinfo', return_value=infos('8.8.8.8')) as lookup, \
                patch('dns.resolver.Resolver', side_effect=AssertionError('Must not use fallback')):
            self.assertEqual(u.resolve_public_addresses('imap.gmail.com', u.NetworkGuard()), ('8.8.8.8',))
        lookup.assert_called_once()

    def test_native_ipv6_only_answer_is_accepted(self):
        with patch.object(u.socket, 'getaddrinfo', return_value=infos('2606:4700:4700::1111')):
            self.assertEqual(u.resolve_public_addresses('imap.gmail.com', u.NetworkGuard()),
                             ('2606:4700:4700::1111',))

    def test_native_duplicates_are_removed_preserving_order(self):
        answers = ('2606:4700:4700::1111', '8.8.8.8', '8.8.8.8')
        with patch.object(u.socket, 'getaddrinfo', return_value=infos(*answers)):
            self.assertEqual(u.resolve_public_addresses('imap.gmail.com', u.NetworkGuard()), answers[:2])

    def test_native_private_result_is_blocked_without_fallback(self):
        with patch.object(u.socket, 'getaddrinfo', return_value=infos('127.0.0.1')), \
                patch.object(u, '_configured_dns_addresses') as fallback:
            with self.assertRaises(u.SafetyError):
                u.resolve_public_addresses('imap.gmail.com', u.NetworkGuard())
        fallback.assert_not_called()

    def test_mixed_native_result_is_blocked_without_fallback(self):
        with patch.object(u.socket, 'getaddrinfo', return_value=infos('8.8.8.8', '10.0.0.1')), \
                patch.object(u, '_configured_dns_addresses') as fallback:
            with self.assertRaises(u.SafetyError):
                u.resolve_public_addresses('imap.gmail.com', u.NetworkGuard())
        fallback.assert_not_called()

    def test_blocked_and_malformed_native_values_fail_closed(self):
        for value in ('::1', '169.254.169.254', '192.168.1.1', '100.64.0.1',
                      '224.0.0.1', 'fe80::1%3', 'not-an-ip', '::ffff:8.8.8.8'):
            with self.subTest(address=value), patch.object(u, '_system_addresses', return_value=(value,)), \
                    patch.object(u, '_configured_dns_addresses') as fallback:
                with self.assertRaises(u.SafetyError):
                    u.resolve_public_addresses('imap.gmail.com', u.NetworkGuard())
                fallback.assert_not_called()

    def test_cancel_before_lookup_creates_no_thread(self):
        guard = u.NetworkGuard()
        guard.cancel()
        with patch.object(u.threading, 'Thread') as worker:
            with self.assertRaises(u.Cancelled):
                u._system_addresses('imap.gmail.com', guard)
        worker.assert_not_called()

    def test_system_error_is_preserved(self):
        with patch.object(u.socket, 'getaddrinfo', side_effect=socket.gaierror(11001, 'host not found')):
            with self.assertRaisesRegex(socket.gaierror, '11001'):
                u._system_addresses('imap.gmail.com', u.NetworkGuard())

    def test_empty_native_answer_is_a_lookup_error(self):
        with patch.object(u.socket, 'getaddrinfo', return_value=[]):
            with self.assertRaisesRegex(OSError, 'no IPv4 or IPv6'):
                u._system_addresses('imap.gmail.com', u.NetworkGuard())

    def _slow_lookup(self, action):
        entered, release, ended = threading.Event(), threading.Event(), threading.Event()
        def slow(*args, **kwargs):
            entered.set()
            try:
                release.wait(2)
                return infos('8.8.8.8')
            finally:
                ended.set()
        guard = u.NetworkGuard()
        slots = threading.BoundedSemaphore(2)
        with patch.object(u.socket, 'getaddrinfo', side_effect=slow), \
                patch.object(u, '_SYSTEM_DNS_SLOTS', slots):
            try:
                action(guard, entered)
            finally:
                release.set()
                self.assertTrue(ended.wait(2))
        return slots

    def test_slow_lookup_has_bounded_wait(self):
        def action(guard, entered):
            started = time.monotonic()
            with patch.object(u, 'SYSTEM_DNS_TIMEOUT', 0.04), self.assertRaises(TimeoutError):
                u._system_addresses('imap.gmail.com', guard)
            self.assertLess(time.monotonic() - started, 0.8)
            self.assertTrue(entered.is_set())
        self._slow_lookup(action)

    def test_stop_interrupts_wait_for_os_lookup(self):
        def action(guard, entered):
            timer = threading.Timer(0.04, guard.cancel)
            timer.start()
            try:
                with self.assertRaises(u.Cancelled):
                    u._system_addresses('imap.gmail.com', guard)
            finally:
                timer.cancel()
                timer.join()
        self._slow_lookup(action)

    def test_total_deadline_does_not_start_dns_fallback(self):
        def action(guard, entered):
            with patch.object(u, '_configured_dns_addresses') as fallback:
                with self.assertRaises(TimeoutError):
                    with guard.operation(0.04):
                        u.resolve_public_addresses('imap.gmail.com', guard)
                fallback.assert_not_called()
        self._slow_lookup(action)

    def test_saturated_lookup_slots_do_not_create_more_threads(self):
        slots = threading.BoundedSemaphore(1)
        slots.acquire()
        with patch.object(u, '_SYSTEM_DNS_SLOTS', slots), patch.object(u.threading, 'Thread') as worker:
            with self.assertRaisesRegex(TimeoutError, 'still finishing'):
                u._system_addresses('imap.gmail.com', u.NetworkGuard())
        worker.assert_not_called()
        slots.release()

    def test_thread_start_failure_returns_slot(self):
        slots = threading.BoundedSemaphore(1)
        with patch.object(u, '_SYSTEM_DNS_SLOTS', slots), \
                patch.object(u.threading.Thread, 'start', side_effect=RuntimeError('cannot start')):
            with self.assertRaisesRegex(RuntimeError, 'cannot start'):
                u._system_addresses('imap.gmail.com', u.NetworkGuard())
        self.assertTrue(slots.acquire(blocking=False))
        slots.release()


class FallbackTests(DNSCase):
    def run_lookup(self, effects, *, system_error=None):
        resolver = MagicMock()
        resolver.resolve.side_effect = effects
        with patch.object(u, '_system_addresses', side_effect=system_error or socket.gaierror(11001, 'OS failed')), \
                patch('dns.resolver.Resolver', return_value=resolver):
            result = u.resolve_public_addresses('imap.gmail.com', u.NetworkGuard())
        return result, resolver

    def test_a_success_survives_aaaa_timeout(self):
        result, resolver = self.run_lookup([records('8.8.8.8'), dns.exception.Timeout()])
        self.assertEqual(result, ('8.8.8.8',))
        self.assertEqual(resolver.resolve.call_count, 2)

    def test_aaaa_success_survives_a_timeout(self):
        result, _ = self.run_lookup([dns.exception.Timeout(), records('2606:4700:4700::1111')])
        self.assertEqual(result, ('2606:4700:4700::1111',))

    def test_one_family_noanswer_does_not_block_other(self):
        result, _ = self.run_lookup([records('8.8.8.8'), dns.resolver.NoAnswer()])
        self.assertEqual(result, ('8.8.8.8',))

    def test_no_nameservers_on_one_family_keeps_other_answer(self):
        result, _ = self.run_lookup([records('8.8.8.8'), dns.resolver.NoNameservers()])
        self.assertEqual(result, ('8.8.8.8',))

    def test_native_timeout_can_use_configured_dns(self):
        result, _ = self.run_lookup([records('8.8.8.8'), []], system_error=TimeoutError('OS timed out'))
        self.assertEqual(result, ('8.8.8.8',))

    def test_partial_failure_never_allows_a_private_address(self):
        with self.assertRaises(u.SafetyError):
            self.run_lookup([records('127.0.0.1'), dns.exception.Timeout()])

    def test_public_and_private_dns_answers_fail_closed(self):
        with self.assertRaises(u.SafetyError):
            self.run_lookup([records('8.8.8.8'), records('::1')])

    def test_both_families_fail_with_details_not_safetyerror(self):
        with self.assertRaises(u.DNSResolutionError) as caught:
            self.run_lookup([dns.exception.Timeout(), dns.resolver.NXDOMAIN()])
        message = str(caught.exception)
        self.assertIn('imap.gmail.com', message)
        self.assertIn('11001', message)
        self.assertIn('Timeout', message)
        self.assertIn('NXDOMAIN', message)
        self.assertIn('not a Gmail password rejection', message)
        self.assertNotIsInstance(caught.exception, u.SafetyError)

    def test_configured_resolver_constructor_failure_has_context(self):
        with patch.object(u, '_system_addresses', side_effect=socket.gaierror('OS failed')), \
                patch('dns.resolver.Resolver', side_effect=dns.resolver.NoResolverConfiguration()):
            with self.assertRaisesRegex(u.DNSResolutionError, 'NoResolverConfiguration'):
                u.resolve_public_addresses('imap.gmail.com', u.NetworkGuard())

    def test_dns_no_records_is_a_lookup_failure(self):
        with self.assertRaises(u.DNSResolutionError):
            self.run_lookup([[], []])

    def test_fallback_uses_os_config_not_hardcoded_public_dns(self):
        _, resolver = self.run_lookup([records('8.8.8.8'), []])
        self.assertNotIn('nameservers', resolver.__dict__)
        for call in resolver.resolve.call_args_list:
            self.assertEqual(call.args[0], 'imap.gmail.com.')
            self.assertFalse(call.kwargs['search'])
            self.assertLessEqual(call.kwargs['lifetime'], u.DNS_TIMEOUT)

    def test_cancellation_after_a_lookup_prevents_aaaa_and_connection(self):
        guard = u.NetworkGuard()
        resolver = MagicMock()
        def first(*args, **kwargs):
            guard.cancel()
            return records('8.8.8.8')
        resolver.resolve.side_effect = first
        with patch.object(u, '_system_addresses', side_effect=socket.gaierror('OS failed')), \
                patch('dns.resolver.Resolver', return_value=resolver):
            with self.assertRaises(u.Cancelled):
                u.resolve_public_addresses('imap.gmail.com', guard)
        self.assertEqual(resolver.resolve.call_count, 1)


class AddressConnectionTests(DNSCase):
    def test_individual_ipv6_timeout_tries_validated_ipv4(self):
        bad, good, secured, context = (MagicMock() for _ in range(4))
        bad.connect.side_effect = TimeoutError('IPv6 path timed out')
        context.wrap_socket.return_value = secured
        guard = u.NetworkGuard()
        with patch.object(u, 'resolve_public_addresses', return_value=('2606:4700:4700::1111', '8.8.8.8')), \
                patch.object(u.socket, 'socket', side_effect=[bad, good]):
            self.assertIs(u.connect_tls('imap.gmail.com', 993, context, guard), secured)
        bad.close.assert_called_once()
        good.connect.assert_called_once_with(('8.8.8.8', 993))
        self.assertEqual(context.wrap_socket.call_args.kwargs['server_hostname'], 'imap.gmail.com')
        guard.abort_sockets()

    def test_bad_certificate_never_retries_or_disables_verification(self):
        raw, context = MagicMock(), MagicMock()
        context.wrap_socket.side_effect = ssl.SSLCertVerificationError('bad certificate')
        with patch.object(u, 'resolve_public_addresses', return_value=('8.8.8.8', '1.1.1.1')), \
                patch.object(u.socket, 'socket', return_value=raw) as factory:
            with self.assertRaises(ssl.SSLCertVerificationError):
                u.connect_tls('imap.gmail.com', 993, context, u.NetworkGuard())
        self.assertEqual(factory.call_count, 1)
        raw.close.assert_called_once()

    def test_lookup_failure_opens_no_socket(self):
        with patch.object(u, 'resolve_public_addresses', side_effect=u.DNSResolutionError('lookup failed')), \
                patch.object(u.socket, 'socket') as factory:
            with self.assertRaises(u.DNSResolutionError):
                u.connect_tls('imap.gmail.com', 993, ssl.create_default_context(), u.NetworkGuard())
        factory.assert_not_called()


class ConnectionDiagnosticTests(DNSCase):
    def test_diagnostic_uses_secure_ports_and_does_not_authenticate(self):
        emit = MagicMock()
        socks = [MagicMock(), MagicMock()]
        with patch.object(u, 'connect_tls', side_effect=socks) as connect, \
                patch.object(u, 'VerifiedIMAP') as imap, patch.object(u, 'VerifiedSMTP') as smtp:
            u.test_gmail_connection(guard=u.NetworkGuard(), emit=emit)
        self.assertEqual([(c.args[0], c.args[1]) for c in connect.call_args_list],
                         [('imap.gmail.com', 993), ('smtp.gmail.com', 465)])
        for call in connect.call_args_list:
            self.assertEqual(call.args[2].verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(call.args[2].check_hostname)
        for sock in socks:
            sock.close.assert_called_once()
            sock.send.assert_not_called()
            sock.sendall.assert_not_called()
        imap.assert_not_called()
        smtp.assert_not_called()
        report = [c.args[1] for c in emit.call_args_list if c.args[0] == 'connection_report'][0]
        self.assertEqual(report.count('PASS:'), 2)
        self.assertIn('No login was attempted', report)

    def test_imap_failure_still_tests_smtp(self):
        emit = MagicMock()
        with patch.object(u, 'connect_tls', side_effect=[u.DNSResolutionError('lookup failed'), MagicMock()]):
            u.test_gmail_connection(guard=u.NetworkGuard(), emit=emit)
        report = [c.args[1] for c in emit.call_args_list if c.args[0] == 'connection_report'][0]
        self.assertIn('FAIL: Inbox (IMAP)', report)
        self.assertIn('PASS: Outgoing email (SMTP)', report)

    def test_certificate_failure_is_reported_as_failure(self):
        emit = MagicMock()
        with patch.object(u, 'connect_tls', side_effect=ssl.SSLCertVerificationError('untrusted')):
            u.test_gmail_connection(guard=u.NetworkGuard(), emit=emit)
        report = [c.args[1] for c in emit.call_args_list if c.args[0] == 'connection_report'][0]
        self.assertNotIn('PASS:', report)
        self.assertIn('SSLCertVerificationError', report)

    def test_cancelled_diagnostic_stops_without_second_connection(self):
        emit = MagicMock()
        with patch.object(u, 'connect_tls', side_effect=u.Cancelled('Stopped')) as connect:
            with self.assertRaises(u.Cancelled):
                u.test_gmail_connection(guard=u.NetworkGuard(), emit=emit)
        self.assertEqual(connect.call_count, 1)
        self.assertFalse(any(c.args[0] == 'connection_report' for c in emit.call_args_list))


@unittest.skipUnless(os.environ.get('DISPLAY') or os.name == 'nt', 'GUI needs a display')
class ConnectionGuiTests(DNSCase):
    def setUp(self):
        super().setUp()
        self.root = tk.Tk()
        self.app = u.UnsubscribeApp(self.root)
        self.root.update()
        self.addCleanup(self.cleanup)

    def cleanup(self):
        if self.app.worker and self.app.worker.is_alive():
            self.app.guard.cancel()
            self.app.worker.join(2)
        if not self.app.destroyed:
            self.app._destroy()
        gc.collect()

    def test_button_is_available_without_credentials(self):
        self.assertEqual(self.app.email_var.get(), '')
        self.assertEqual(self.app.pass_var.get(), '')
        self.assertEqual(str(self.app.connection_btn.cget('state')), 'normal')

    def test_button_starts_account_free_job_and_preserves_scan(self):
        self.app.candidates['sentinel'] = 'keep me'
        with patch.object(self.app, '_start_worker') as start, \
                patch.object(self.app, 'credentials', side_effect=AssertionError('No credentials needed')):
            self.app.start_connection_test()
        start.assert_called_once_with(u.test_gmail_connection, (), '')
        self.assertEqual(self.app.candidates['sentinel'], 'keep me')
        self.assertEqual(self.app.active_task, 'connection_test')
        self.assertEqual(self.app.workspace.select(), str(self.app.log_tab))
        self.app.candidates.clear()

    def test_button_is_disabled_during_work_and_closing(self):
        for running, closing in [(True, False), (False, True)]:
            self.app.is_running, self.app.closing = running, closing
            self.app.update_controls()
            self.assertEqual(str(self.app.connection_btn.cget('state')), 'disabled')
        self.app.is_running = self.app.closing = False

    def test_report_popup_runs_on_ui_thread(self):
        self.app.events.put(('connection_report', 'Diagnostic result'))
        with patch.object(u.messagebox, 'showinfo') as popup:
            self.app._poll_events()
        popup.assert_called_once_with('Gmail connection test', 'Diagnostic result', parent=self.root)

    def test_no_popup_after_close_was_requested(self):
        self.app.closing = True
        self.app.events.put(('connection_report', 'Diagnostic result'))
        with patch.object(u.messagebox, 'showinfo') as popup:
            self.app._poll_events()
        popup.assert_not_called()
        self.app.closing = False

    def test_empty_password_does_not_corrupt_error_redaction(self):
        def fail(*, guard, emit):
            raise OSError('Readable connection error')
        self.app._start_worker(fail, (), '')
        self.app.worker.join(2)
        events = []
        while not self.app.events.empty():
            events.append(self.app.events.get_nowait())
        self.assertIn(('error', 'OSError: Readable connection error'), events)
        self.assertFalse(any('[redacted]' in str(payload) for _, payload in events))
        self.app.is_running = False

    def test_connection_button_fits_small_window(self):
        self.root.geometry('880x650')
        self.root.update()
        button = self.app.connection_btn
        self.assertLessEqual(button.winfo_rootx() + button.winfo_width(), self.root.winfo_rootx() + 880)
        self.assertLessEqual(button.winfo_rooty() + button.winfo_height(), self.root.winfo_rooty() + 650)


if __name__ == '__main__':
    unittest.main(verbosity=2)
