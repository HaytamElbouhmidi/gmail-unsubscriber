"""Progress counters, large scans, and completion states. No live Gmail calls."""
import gc
import os
from pathlib import Path
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

import gmail_unsubscriber as u
from test_gmail_unsubscriber import ACCOUNT, PASSWORD, MAIL_URL, headers, candidate, OfflineCase


PLAIN = b'From: Notes <notes@example.com>\r\nSubject: A regular message\r\n\r\n'


class MemoryInbox:
    def __init__(self, messages):
        self.messages = messages
        self.validity = '123'

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def message_ids(self, limit):
        ids = sorted(self.messages, key=int, reverse=True)
        return ids[:limit] if limit else ids

    def headers(self, uid):
        value = self.messages[uid]
        if isinstance(value, Exception):
            raise value
        return value

    def verification_message(self, _candidate):
        raise AssertionError('Unexpected full-message fetch')


class ProgressQueueTests(OfflineCase):
    def test_only_latest_progress_is_kept(self):
        events = u.UiEventQueue()
        for index in range(40819):
            events.put(('progress', u.ProgressUpdate(index, 40818, 'Scanning...')))
        self.assertEqual(events.qsize(), 0)
        progress, activity = events.take_progress()
        self.assertEqual(progress.completed, 40818)
        self.assertEqual(activity, 'Scanning...')
        self.assertEqual(events.take_progress(), (None, None))

    def test_results_and_logs_are_never_coalesced(self):
        events = u.UiEventQueue()
        expected = [('message', 1), ('candidate', 2), ('result', 3), ('log', 4), ('summary', 5), ('error', 6), ('done', None)]
        for event in expected:
            events.put(event)
            events.put(('progress', u.ProgressUpdate(1, 3, 'Reading...')))
        self.assertEqual([events.get_nowait() for _ in expected], expected)

    def test_activity_keeps_the_numeric_counter(self):
        events = u.UiEventQueue()
        events.put(('progress', u.ProgressUpdate(15, 100, 'Reading...')))
        events.put(('activity', 'Reconnecting...'))
        progress, activity = events.take_progress()
        self.assertEqual(progress.completed, 15)
        self.assertEqual(activity, 'Reconnecting...')

    def test_new_snapshot_replaces_old_activity(self):
        events = u.UiEventQueue()
        events.put(('activity', 'Reconnecting...'))
        events.put(('progress', u.ProgressUpdate(16, 100, 'Reading next message...')))
        self.assertEqual(events.take_progress()[1], 'Reading next message...')

    def test_legacy_text_progress_is_supported(self):
        events = u.UiEventQueue()
        events.put(('progress', 'Testing connection...'))
        self.assertEqual(events.take_progress(), (None, 'Testing connection...'))

    def test_elapsed_format(self):
        self.assertEqual(u.elapsed_text(-5), '00:00')
        self.assertEqual(u.elapsed_text(61.8), '01:01')
        self.assertEqual(u.elapsed_text(3661), '1:01:01')


class ProgressBackendTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.events = []
        self.guard = u.NetworkGuard()
        self.send = patch.object(u, 'send_mailto', return_value=('Email submitted', 'Mock SMTP accepted')).start()
        self.post = patch.object(u, 'submit_one_click', return_value=('Request accepted', 'Mock HTTP 204')).start()

    def run_scan(self, messages, automatic=False, limit=0, emit=None):
        with patch.object(u, 'RecoveringInbox', return_value=MemoryInbox(messages)):
            u.scan_and_unsubscribe(ACCOUNT, PASSWORD, limit, self.guard, {},
                                  emit or (lambda *event: self.events.append(event)), automatic=automatic)

    def progress(self):
        return [payload for kind, payload in self.events if kind == 'progress']

    def test_plain_messages_update_before_25_messages(self):
        self.run_scan({str(i): PLAIN for i in range(1, 24)})
        counts = {p.completed for p in self.progress() if p.total is not None}
        self.assertEqual(counts, set(range(24)))
        self.assertEqual(self.progress()[-1].total, 23)
        self.send.assert_not_called()
        self.post.assert_not_called()

    def test_scan_only_candidates_also_update_each_message(self):
        self.run_scan({str(i): headers([MAIL_URL], post=None) for i in range(1, 13)})
        self.assertEqual({p.completed for p in self.progress()}, set(range(13)))
        self.send.assert_not_called()
        self.post.assert_not_called()

    def test_auto_duplicates_still_advance(self):
        self.run_scan({str(i): headers([MAIL_URL], post=None) for i in range(1, 13)}, automatic=True)
        self.assertEqual({p.completed for p in self.progress()}, set(range(13)))
        self.send.assert_called_once()

    def test_missing_and_unreadable_messages_count_as_checked(self):
        self.run_scan({'3': None, '2': u.MessageFetchError('Unreadable'), '1': PLAIN})
        self.assertEqual({p.completed for p in self.progress()}, {0, 1, 2, 3})
        stats = [v for k, v in self.events if k == 'summary'][-1]
        self.assertEqual(stats['unreadable'], 2)
        self.assertEqual(stats['checked'], 3)

    def test_count_is_not_advanced_before_read_returns(self):
        inbox = MemoryInbox({'2': PLAIN, '1': PLAIN})
        observed = []
        read = inbox.headers
        def inspect(uid):
            observed.append(self.progress()[-1].completed)
            return read(uid)
        inbox.headers = inspect
        with patch.object(u, 'RecoveringInbox', return_value=inbox):
            u.scan_mailbox(ACCOUNT, PASSWORD, 0, self.guard, lambda *e: self.events.append(e))
        self.assertEqual(observed, [0, 1])

    def test_cancelled_read_does_not_count_unread_message(self):
        inbox = MemoryInbox({'2': PLAIN, '1': PLAIN})
        def read(uid):
            if uid == '1':
                self.guard.cancel()
                raise u.Cancelled('Stopped while reading')
            return PLAIN
        inbox.headers = read
        with patch.object(u, 'RecoveringInbox', return_value=inbox), self.assertRaises(u.Cancelled):
            u.scan_mailbox(ACCOUNT, PASSWORD, 0, self.guard, lambda *e: self.events.append(e))
        self.assertEqual(self.progress()[-1].completed, 1)
        self.assertEqual(self.progress()[-1].total, 2)

    def test_fatal_read_error_preserves_partial_progress(self):
        with self.assertRaises(u.MailboxLimitError):
            self.run_scan({'2': PLAIN, '1': u.MailboxLimitError('Quota reached')})
        self.assertEqual(self.progress()[-1].completed, 1)
        self.assertEqual(self.progress()[-1].total, 2)

    def test_empty_inbox_is_zero_of_zero(self):
        self.run_scan({})
        self.assertEqual(self.progress()[-1].completed, 0)
        self.assertEqual(self.progress()[-1].total, 0)

    def test_scan_limit_uses_actual_work_not_full_mailbox_size(self):
        self.run_scan({str(i): PLAIN for i in range(1, 301)}, limit=250)
        self.assertEqual(self.progress()[-1].total, 250)
        self.assertEqual(self.progress()[-1].completed, 250)

    def test_full_40818_message_scan_reports_every_count(self):
        counts, last = set(), []
        def collect(kind, payload):
            if kind == 'progress' and payload.total is not None:
                counts.add(payload.completed)
                last[:] = [payload]
        self.run_scan({str(i): PLAIN for i in range(1, 40819)}, emit=collect)
        self.assertEqual(counts, set(range(40819)))
        self.assertEqual((last[0].completed, last[0].total), (40818, 40818))
        self.send.assert_not_called()
        self.post.assert_not_called()

    def test_checked_entries_include_duplicates_in_progress(self):
        c = candidate([MAIL_URL], post=None)
        u.process_selected((c, c), ACCOUNT, PASSWORD, self.guard, {}, lambda *e: self.events.append(e))
        self.assertEqual({p.completed for p in self.progress()}, {0, 1, 2})
        self.assertEqual(self.progress()[-1].unit, 'entries')
        self.send.assert_called_once()

    def test_checked_entry_error_does_not_count_unfinished_entry(self):
        c = candidate([MAIL_URL], post=None)
        self.send.side_effect = u.AuthenticationError('Rejected')
        with self.assertRaises(u.AuthenticationError):
            u.process_selected((c,), ACCOUNT, PASSWORD, self.guard, {}, lambda *e: self.events.append(e))
        self.assertEqual(self.progress()[-1].completed, 0)
        self.assertEqual(self.progress()[-1].total, 1)

    def test_auto_mode_reports_outgoing_email_activity(self):
        self.run_scan({'1': headers([MAIL_URL], post=None)}, automatic=True)
        self.assertTrue(any(k == 'activity' and 'Sending unsubscribe email' in v for k, v in self.events))


@unittest.skipUnless(os.environ.get('DISPLAY') or os.name == 'nt', 'GUI tests need a display.')
class ProgressGuiTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.root = u.tk.Tk()
        self.app = u.UnsubscribeApp(self.root)
        self.root.update()
        self.release = threading.Event()

    def tearDown(self):
        self.release.set()
        if self.app.worker is not None:
            self.app.guard.cancel()
            self.app.worker.join(5)
        if not self.app.destroyed:
            self.app._destroy()
        gc.collect()

    def pump(self, condition, timeout=5):
        deadline = time.monotonic() + timeout
        while not condition() and time.monotonic() < deadline:
            self.root.update()
            time.sleep(0.005)
        self.root.update()
        self.assertTrue(condition())

    def start_paused(self, completed=7, total=40818, unit='messages'):
        def job(*, guard, emit):
            emit('progress', u.ProgressUpdate(completed, total, 'Reading the next message...', unit))
            self.release.wait(10)
            guard.check()
        self.app.active_task = 'scan'
        self.app._start_worker(job, (), '')
        self.pump(lambda: self.app._progress is not None)

    def test_bar_tracks_actual_value_and_maximum(self):
        self.start_paused()
        self.assertEqual(str(self.app.progress_bar['mode']), 'determinate')
        self.assertEqual(float(self.app.progress_bar['value']), 7)
        self.assertEqual(float(self.app.progress_bar['maximum']), 40818)
        self.assertIn('7 / 40,818', self.app.progress_text_var.get())
        self.assertNotIn('Complete', self.app.progress_text_var.get())

    def test_elapsed_status_changes_while_network_is_waiting(self):
        self.start_paused()
        before = self.app.status_var.get()
        self.app._task_started -= 5
        self.app._activity_started -= 5
        self.app._poll_events()
        self.assertNotEqual(self.app.status_var.get(), before)
        self.assertIn('Current step', self.app.status_var.get())
        self.assertEqual(float(self.app.progress_bar['value']), 7)

    def test_progress_bypasses_a_large_result_backlog(self):
        info = u.parse_message_info(PLAIN, '1')
        for _ in range(40000):
            self.app.events.put(('message', info))
        self.app.is_running = True
        self.app._task_started = time.monotonic()
        self.app.events.put(('progress', u.ProgressUpdate(31000, 40818, 'Reading current message...')))
        self.app._poll_events()
        self.assertGreater(self.app.events.qsize(), 39000)
        self.assertEqual(float(self.app.progress_bar['value']), 31000)
        self.assertIn('31,000 / 40,818', self.app.progress_text_var.get())
        self.app.is_running = False

    def test_table_refresh_yields_without_dropping_rows(self):
        from dataclasses import replace
        base = candidate([MAIL_URL], post=None)
        for index in range(50):
            self.app._add_candidate(replace(base, uid=str(index + 1), sender_email=f"sender{index}@example.com"))
        clock = iter([0.0, 1.0])
        with patch.object(u.time, 'monotonic', side_effect=lambda: next(clock)):
            self.app._refresh_results(budgeted=True)
        self.assertEqual(len(self.app.visible_keys), 1)
        self.assertEqual(len(self.app._dirty_rows), 49)
        self.assertIsNotNone(self.app._refresh_id)
        self.app._refresh_results()
        self.assertEqual(len(self.app.visible_keys), 50)
        self.assertFalse(self.app._dirty_rows)

    def test_real_scan_updates_before_waiting_for_second_message(self):
        inbox = MemoryInbox({'3': PLAIN, '2': PLAIN, '1': PLAIN})
        def read(uid):
            if uid == '2':
                self.release.wait(10)
            return PLAIN
        inbox.headers = read
        with patch.object(u, 'RecoveringInbox', return_value=inbox), \
             patch.object(self.app, 'credentials', return_value=(ACCOUNT, PASSWORD)):
            self.app.start_scan()
            self.pump(lambda: self.app._progress is not None and self.app._progress.completed == 1)
            self.assertEqual(float(self.app.progress_bar['value']), 1)
            self.assertIn('Reading message 2/3', self.app.status_var.get())
            self.assertFalse(self.app.results)
            self.release.set()
            self.pump(lambda: not self.app.is_running)
        self.assertTrue(self.app.progress_text_var.get().startswith('Complete'))
        self.assertEqual(float(self.app.progress_bar['value']), 3)

    def test_bar_stays_full_after_success(self):
        def job(*, guard, emit):
            emit('progress', u.ProgressUpdate(23, 23, 'Finishing...'))
        self.app.active_task = 'scan'
        self.app._start_worker(job, (), '')
        self.pump(lambda: not self.app.is_running)
        self.assertTrue(self.app.progress_text_var.get().startswith('Complete'))
        self.assertTrue(self.app.status_var.get().startswith('Complete.'))
        self.assertEqual(float(self.app.progress_bar['value']), 23)
        self.assertEqual(float(self.app.progress_bar['maximum']), 23)
        self.app._poll_events()
        self.assertEqual(float(self.app.progress_bar['value']), 23)

    def test_complete_waits_for_worker_exit(self):
        self.start_paused(completed=40818)
        self.assertIn('Finalizing', self.app.progress_text_var.get())
        self.assertNotIn('Complete', self.app.progress_text_var.get())
        self.release.set()
        self.pump(lambda: not self.app.is_running)
        self.assertTrue(self.app.progress_text_var.get().startswith('Complete'))

    def test_stop_keeps_partial_progress(self):
        self.start_paused()
        self.app.stop_process()
        self.release.set()
        self.pump(lambda: not self.app.is_running)
        self.assertTrue(self.app.progress_text_var.get().startswith('Stopped'))
        self.assertEqual(float(self.app.progress_bar['value']), 7)
        self.assertTrue(self.app.status_var.get().startswith('Stopped.'))

    def test_error_keeps_partial_progress(self):
        def job(*, guard, emit):
            emit('progress', u.ProgressUpdate(7, 40818, 'Reading...'))
            raise u.MailboxError('Simulated server failure')
        self.app.active_task = 'scan'
        with patch.object(u.messagebox, 'showerror'):
            self.app._start_worker(job, (), '')
            self.pump(lambda: not self.app.is_running)
        self.assertTrue(self.app.progress_text_var.get().startswith('Error'))
        self.assertEqual(float(self.app.progress_bar['value']), 7)
        self.assertTrue(self.app.status_var.get().startswith('Error.'))

    def test_cancelled_exception_is_not_reported_as_complete(self):
        def job(*, guard, emit):
            raise u.Cancelled('Cancelled')
        self.app._start_worker(job, (), '')
        self.pump(lambda: not self.app.is_running)
        self.assertTrue(self.app.progress_text_var.get().startswith('Stopped'))

    def test_nearly_finished_scan_does_not_round_up_to_100_percent(self):
        self.start_paused(completed=40817)
        self.assertIn('99.9%', self.app.progress_text_var.get())
        self.app.stop_process()
        self.release.set()
        self.pump(lambda: not self.app.is_running)
        self.assertIn('99.9%', self.app.progress_text_var.get())
        self.assertNotIn('100%', self.app.progress_text_var.get())

    def test_empty_inbox_finishes_with_full_bar(self):
        def job(*, guard, emit):
            emit('progress', u.ProgressUpdate(0, 0, 'Empty inbox'))
        self.app.active_task = 'scan'
        self.app._start_worker(job, (), '')
        self.pump(lambda: not self.app.is_running)
        self.assertIn('Complete', self.app.progress_text_var.get())
        self.assertIn('0 / 0 messages', self.app.progress_text_var.get())
        self.assertEqual(float(self.app.progress_bar['value']), float(self.app.progress_bar['maximum']))

    def test_starting_again_resets_full_bar(self):
        self.app._progress = u.ProgressUpdate(100, 100, 'Done')
        self.app._finish_progress('Complete')
        def job(*, guard, emit):
            self.release.wait(10)
        self.app._start_worker(job, (), '')
        self.assertEqual(str(self.app.progress_bar['mode']), 'indeterminate')
        self.assertNotIn('Complete', self.app.progress_text_var.get())
        self.assertIsNone(self.app._progress)

    def test_selected_mode_uses_entry_counts(self):
        self.start_paused(completed=2, total=4, unit='entries')
        self.assertIn('2 / 4 entries', self.app.progress_text_var.get())

    def test_small_window_keeps_progress_and_status_visible(self):
        self.root.geometry('880x650')
        self.app._progress = u.ProgressUpdate(40818, 40818, 'Done')
        self.app._finish_progress('Complete')
        self.root.update()
        for widget in (self.app.progress_bar, self.app.progress_label, self.app.status_label):
            self.assertLessEqual(widget.winfo_rootx() + widget.winfo_width(), self.root.winfo_rootx() + self.root.winfo_width())
            self.assertLessEqual(widget.winfo_rooty() + widget.winfo_height(), self.root.winfo_rooty() + self.root.winfo_height())
            self.assertGreater(widget.winfo_height(), 0)


class ReadmeTests(unittest.TestCase):
    def test_kofi_precedes_patreon(self):
        readme = Path(__file__).with_name('README.md').read_text(encoding='utf-8')
        support = readme.split('## Support', 1)[1]
        self.assertLess(support.index('https://ko-fi.com/haytamelbouhmidi'),
                        support.index('https://www.patreon.com/c/HaytamElbouhmidi'))

    def test_no_em_dashes_in_project_text(self):
        root = Path(__file__).parent
        for path in root.rglob('*'):
            if path.is_file() and path.suffix in {'.py', '.pyw', '.cmd', '.md', '.txt'}:
                self.assertNotIn(chr(0x2014), path.read_text(encoding='utf-8'), str(path.name))


if __name__ == '__main__':
    unittest.main()
