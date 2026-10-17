"""Tests for startup flags, scan amounts, UAC, and the setup window.

Windows APIs, installers, and child processes are mocked.
"""
import ctypes
import os
import runpy
from pathlib import Path
import subprocess
import tempfile
import time
import types
import unittest
from unittest.mock import MagicMock, patch

import desktop_launcher as launcher
import gmail_unsubscriber as app
from test_gmail_unsubscriber import ACCOUNT, PASSWORD, candidate, OfflineCase


class ScanLimitTests(unittest.TestCase):
    def test_all_presets_map_to_backend(self):
        for choice, result in (("Entire inbox", 0), ("250", 250), ("500", 500), ("1000", 1000)):
            with self.subTest(choice=choice):
                self.assertEqual(app.parse_scan_limit(choice), result)

    def test_custom_whole_number(self):
        self.assertEqual(app.parse_scan_limit("Custom", "1500"), 1500)

    def test_custom_thousands_separators(self):
        self.assertEqual(app.parse_scan_limit("Custom", " 1,250,500 "), 1250500)

    def test_bad_custom_values_are_rejected(self):
        for value in ("", "0", "-3", "2.5", "1e3", "abc", "1,2", "1,,000", "1_000", "+1", "1 000", "9" * 10000):
            with self.subTest(value=value[:30]), self.assertRaises(ValueError):
                app.parse_scan_limit("Custom", value)

    def test_unicode_digits_not_misparsed(self):
        with self.assertRaises(ValueError):
            app.parse_scan_limit("Custom", "１２３")

    def test_custom_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            app.parse_scan_limit("Custom", "2147483648")

    def test_unknown_choice_rejected(self):
        with self.assertRaises(ValueError):
            app.parse_scan_limit("All Mail")

    def test_labels(self):
        self.assertEqual(app.scan_limit_label(0), "Entire inbox")
        self.assertEqual(app.scan_limit_label(2500), "Newest 2,500 messages")


class ElevationTests(unittest.TestCase):
    def setUp(self):
        self.root = MagicMock()
        self.addCleanup(patch.stopall)
        patch.object(launcher, "IS_WINDOWS", True).start()
        self.admin = patch.object(launcher, "is_windows_admin", return_value=False).start()
        self.request = patch.object(launcher, "request_elevation", return_value=42).start()
        self.question = patch.object(launcher.messagebox, "askyesno", return_value=False).start()

    def test_requests_admin_by_default_and_parent_exits(self):
        self.assertFalse(launcher.ensure_admin(self.root, []))
        self.request.assert_called_once_with([])
        self.question.assert_not_called()

    def test_already_admin_does_not_relaunch(self):
        self.admin.return_value = True
        self.assertTrue(launcher.ensure_admin(self.root, []))
        self.request.assert_not_called()

    def test_no_admin_flag_avoids_prompt(self):
        self.assertTrue(launcher.ensure_admin(self.root, ["--no-admin"]))
        self.request.assert_not_called()

    def test_non_windows_does_not_elevate(self):
        with patch.object(launcher, "IS_WINDOWS", False):
            self.assertTrue(launcher.ensure_admin(self.root, []))
        self.request.assert_not_called()

    def test_cancellation_can_continue_standard(self):
        self.request.return_value = 5
        self.question.return_value = True
        self.assertTrue(launcher.ensure_admin(self.root, []))
        self.question.assert_called_once()

    def test_cancellation_can_close(self):
        self.request.return_value = 5
        self.assertFalse(launcher.ensure_admin(self.root, []))

    def test_failed_elevated_child_does_not_loop(self):
        self.assertFalse(launcher.ensure_admin(self.root, ["--elevated"]))
        self.request.assert_not_called()
        self.question.assert_called_once()

    def test_windows_error_is_visible_and_can_continue(self):
        self.request.side_effect = OSError("test failure")
        self.question.return_value = True
        self.assertTrue(launcher.ensure_admin(self.root, []))
        self.question.assert_called_once()

    def test_boundary_return_code_not_success(self):
        self.request.return_value = 32
        self.assertFalse(launcher.ensure_admin(self.root, []))
        self.question.assert_called_once()


class ProcessTests(unittest.TestCase):
    def test_flags_cannot_forward_credentials_or_arbitrary_arguments(self):
        self.assertEqual(launcher.launch_flags(["password=secret", "--no-admin", "--no-admin", "a&b", "--runtime-ready"]),
                         ["--no-admin", "--runtime-ready"])

    def test_interpreter_stays_in_same_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            console = Path(directory) / "python.exe"
            windowed = Path(directory) / "pythonw.exe"
            console.touch()
            windowed.touch()
            with patch.object(launcher, "IS_WINDOWS", True):
                self.assertEqual(launcher.python_executable(windowed=True, executable=str(console)), str(windowed))
                self.assertEqual(launcher.python_executable(windowed=False, executable=str(windowed)), str(console))

    def test_non_windows_interpreter_is_preserved(self):
        with patch.object(launcher, "IS_WINDOWS", False):
            self.assertEqual(launcher.python_executable(windowed=True, executable="/tmp/env/bin/python"), "/tmp/env/bin/python")

    def test_request_elevation_quotes_path_and_uses_pointer_sized_result(self):
        shell = MagicMock(return_value=2**40)
        windll = types.SimpleNamespace(shell32=types.SimpleNamespace(ShellExecuteW=shell))
        with patch.object(launcher, "IS_WINDOWS", True), patch.object(ctypes, "windll", windll, create=True), \
                patch.object(launcher, "python_executable", return_value="C:\\Python Space\\pythonw.exe"):
            self.assertEqual(launcher.request_elevation(["--runtime-ready", "secret"]), 2**40)
        args = shell.call_args.args
        self.assertEqual(args[1], "runas")
        self.assertEqual(args[2], "C:\\Python Space\\pythonw.exe")
        self.assertEqual(args[3], subprocess.list2cmdline([str(launcher.GUI_SCRIPT), "--runtime-ready", "--elevated"]))
        self.assertEqual(shell.restype, ctypes.c_void_p)
        self.assertEqual(args[-1], 1)

    def test_admin_check_uses_windows_api(self):
        check = MagicMock(return_value=1)
        windll = types.SimpleNamespace(shell32=types.SimpleNamespace(IsUserAnAdmin=check))
        with patch.object(launcher, "IS_WINDOWS", True), patch.object(ctypes, "windll", windll, create=True):
            self.assertTrue(launcher.is_windows_admin())
        self.assertEqual(check.restype, ctypes.c_int)

    def test_relaunch_uses_list_arguments_not_shell(self):
        with patch.object(launcher.subprocess, "Popen") as popen:
            launcher.relaunch_with("/tmp/python with spaces", ["--no-admin", "private-password"])
        args, kwargs = popen.call_args
        self.assertEqual(args[0], ["/tmp/python with spaces", str(launcher.GUI_SCRIPT), "--no-admin"])
        self.assertFalse(kwargs.get("shell", False))
        self.assertEqual(kwargs["cwd"], str(launcher.BASE_DIR))

    def test_missing_runtime_is_not_executed(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(launcher.subprocess, "run") as run:
            self.assertFalse(launcher.runtime_works(Path(directory)))
        run.assert_not_called()

    def test_dependency_import_failures_are_reported(self):
        with patch.object(launcher.importlib, "import_module", side_effect=ImportError):
            self.assertEqual(launcher.missing_dependencies(), list(launcher.REQUIRED_IMPORTS))

    def test_existing_dependency_imports_are_accepted(self):
        with patch.object(launcher.importlib, "import_module"):
            self.assertEqual(launcher.missing_dependencies(), [])

    def test_windowless_subprocess_flag_is_present_on_windows(self):
        with patch.object(launcher, "IS_WINDOWS", True), patch.object(subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True):
            self.assertEqual(launcher.process_options()["creationflags"], 0x08000000)


GUI_AVAILABLE = bool(os.environ.get("DISPLAY")) or os.name == "nt"


@unittest.skipUnless(GUI_AVAILABLE, "GUI tests need a desktop display.")
class InlineScanTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.root = app.tk.Tk()
        self.gui = app.UnsubscribeApp(self.root)
        self.root.update()

    def tearDown(self):
        self.gui._destroy()

    def test_default_is_1000_and_custom_hidden(self):
        self.assertEqual(self.gui.current_scan_limit(), 1000)
        self.assertFalse(self.gui.custom_frame.winfo_ismapped())

    def test_every_preset_maps_to_count(self):
        for choice, count in (("250", 250), ("500", 500), ("1,000", 1000), ("Entire inbox", 0)):
            self.gui.scan_choice_var.set(choice)
            self.assertEqual(self.gui.current_scan_limit(), count)

    def test_custom_selection_shows_inline_field(self):
        self.gui.scan_choice_var.set("Custom")
        self.root.update()
        self.assertTrue(self.gui.custom_entry.winfo_viewable())

    def test_custom_comma_value_is_accepted(self):
        self.gui.scan_choice_var.set("Custom")
        self.gui.custom_limit_var.set("2,500")
        self.assertEqual(self.gui.current_scan_limit(), 2500)

    def test_invalid_custom_never_starts(self):
        self.gui.scan_choice_var.set("Custom")
        self.gui.custom_limit_var.set("0")
        with patch.object(app.messagebox, "showwarning") as warning, patch.object(self.gui, "_start_worker") as worker:
            self.gui.start_scan()
        warning.assert_called_once()
        worker.assert_not_called()

    def test_custom_value_survives_preset_switch(self):
        self.gui.scan_choice_var.set("Custom")
        self.gui.custom_limit_var.set("1700")
        self.gui.scan_choice_var.set("250")
        self.gui.scan_choice_var.set("Custom")
        self.assertEqual(self.gui.current_scan_limit(), 1700)

    def test_choosing_entire_inbox_does_not_open_amount_picker(self):
        with patch.object(app.messagebox, "askyesno") as question:
            self.gui.scan_choice_var.set("Entire inbox")
        question.assert_not_called()
        self.assertFalse(hasattr(app, "ScanScopeDialog"))


@unittest.skipUnless(GUI_AVAILABLE, "GUI tests need a Windows desktop or Xvfb DISPLAY.")
class AppChoiceTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.root = app.tk.Tk()
        self.gui = app.UnsubscribeApp(self.root)
        self.root.update()
        patch.object(self.gui, "credentials", return_value=(ACCOUNT, PASSWORD)).start()
        self.worker = patch.object(self.gui, "_start_worker").start()

    def tearDown(self):
        self.gui._destroy()

    def test_cancelling_scan_preserves_previous_results(self):
        c = candidate()
        self.gui._add_candidate(c)
        self.gui._refresh_results()
        self.gui.scan_choice_var.set("Entire inbox")
        with patch.object(app.messagebox, "askyesno", return_value=False):
            self.gui.start_scan()
        self.worker.assert_not_called()
        self.assertIn(c.key, self.gui.candidates)
        self.assertEqual(len(self.gui.tree.get_children()), 1)

    def test_scan_passes_chosen_limit_and_mode_to_backend(self):
        for automatic in (False, True):
            self.gui.auto_var.set(automatic)
            for choice, limit in (("Entire inbox", 0), ("250", 250), ("500", 500), ("1,000", 1000), ("Custom", 3500)):
                self.gui.scan_choice_var.set(choice)
                self.gui.custom_limit_var.set("3,500")
                with patch.object(app.messagebox, "askyesno", return_value=True) as question:
                    self.gui.start_scan()
                self.assertEqual(question.call_count, 1 if limit == 0 else 0)
                target, args, password = self.worker.call_args.args
                self.assertEqual(args, (ACCOUNT, PASSWORD, limit))
                self.assertEqual(password, PASSWORD)
                with patch.object(app, "scan_and_unsubscribe") as scan:
                    guard, emit = app.NetworkGuard(), MagicMock()
                    target(*args, guard=guard, emit=emit)
                scan.assert_called_once()
                self.assertEqual(scan.call_args.args,
                                 (ACCOUNT, PASSWORD, limit, guard, self.gui.ledger, emit))
                self.assertEqual(scan.call_args.kwargs["automatic"], automatic)
                self.assertFalse(scan.call_args.kwargs["include_spam"])
                self.assertFalse(scan.call_args.kwargs["request_fallback"])
                self.assertTrue(scan.call_args.kwargs["resume"])
                self.assertIsNotNone(scan.call_args.kwargs["history"])

    def test_change_amount_updates_inline_setting(self):
        self.gui.scan_choice_var.set("Custom")
        self.gui.custom_limit_var.set("2500")
        self.assertEqual(self.gui.current_scan_limit(), 2500)

    def test_cancel_entire_confirmation_preserves_choice(self):
        self.gui.scan_choice_var.set("Entire inbox")
        with patch.object(app.messagebox, "askyesno", return_value=False):
            self.gui.start_scan()
        self.assertEqual(self.gui.current_scan_limit(), 0)

    def test_scan_controls_disabled_while_busy(self):
        self.gui.is_running = True
        self.gui.update_controls()
        self.assertEqual(str(self.gui.scan_amount["state"]), "disabled")
        self.assertEqual(str(self.gui.auto_cb["state"]), "disabled")
        self.gui.start_scan()
        self.worker.assert_not_called()

    def test_short_window_keeps_controls_and_status_visible(self):
        self.root.geometry("880x650")
        self.root.update()
        bottom = self.root.winfo_rooty() + self.root.winfo_height()
        for widget in (self.gui.start_btn, self.gui.scan_amount, self.gui.export_btn,
                       self.gui.progress_bar, self.gui.status_label):
            self.assertTrue(widget.winfo_viewable())
            self.assertLessEqual(widget.winfo_rooty() + widget.winfo_height(), bottom)
        self.assertGreater(self.gui.tree.winfo_height(), 50)

    def test_details_and_log_tabs_are_accessible(self):
        self.gui._add_candidate(candidate())
        self.gui._refresh_results()
        self.gui.tree.selection_set(self.gui.visible_keys[0])
        self.root.update()
        self.gui.details_btn.invoke()
        self.root.update()
        self.assertTrue(self.gui.details.winfo_viewable())
        self.gui.workspace.select(self.gui.log_tab)
        self.root.update()
        self.assertTrue(self.gui.log_box.winfo_viewable())

    def test_highlighting_is_not_checking_or_sending(self):
        c = candidate()
        self.gui._add_candidate(c)
        self.gui._refresh_results()
        self.gui.tree.selection_set(self.gui.visible_keys[0])
        self.root.update()
        self.assertFalse(self.gui.checked_senders)
        self.assertEqual(str(self.gui.action_btn["state"]), "disabled")
        self.assertIn("1 of 1 senders", self.gui.review_count_var.get())
        self.assertIn("Sender:", self.gui.details.get("1.0", "end"))


@unittest.skipUnless(GUI_AVAILABLE, "GUI tests need a Windows desktop or Xvfb DISPLAY.")
class SetupTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.temp = tempfile.TemporaryDirectory()
        self.root = app.tk.Tk()
        self.root.withdraw()
        self.dialog = launcher.SetupDialog(self.root, Path(self.temp.name) / "runtime")
        self.root.update()

    def tearDown(self):
        if self.dialog.worker is not None:
            self.dialog.worker.join(2)
        if self.dialog.winfo_exists():
            self.dialog.close()
        self.root.destroy()
        self.temp.cleanup()

    def pump_until_closed(self):
        deadline = time.monotonic() + 3
        while self.dialog.winfo_exists() and time.monotonic() < deadline:
            self.root.update()
            time.sleep(0.01)
        self.assertFalse(self.dialog.winfo_exists())

    def test_nothing_installed_before_consent(self):
        self.assertFalse(self.dialog.running)
        self.assertIsNone(self.dialog.process)
        self.assertFalse(self.dialog.directory.exists())

    def test_cancel_before_install(self):
        self.dialog.after(30, self.dialog.cancel)
        self.assertFalse(self.dialog.show())
        self.assertFalse(self.dialog.directory.exists())

    def test_install_runs_venv_pip_and_import_check(self):
        def fake_command(command, description):
            if "venv" in command:
                directory = Path(command[-1])
                (directory / "pyvenv.cfg").write_text("home = test\n")
                for windowed in (False, True):
                    executable = launcher.runtime_python(directory, windowed=windowed)
                    executable.parent.mkdir(parents=True, exist_ok=True)
                    executable.touch()
        with patch.object(self.dialog, "run_command", side_effect=fake_command) as command:
            self.dialog.install()
            self.pump_until_closed()
        self.assertTrue(self.dialog.success)
        self.assertEqual(command.call_count, 6 if launcher.IS_WINDOWS else 5)
        calls = [call.args[0] for call in command.call_args_list]
        self.assertIn("--without-pip", calls[0])
        self.assertIn(launcher.RUNTIME_PROBE, calls[1])
        self.assertIn("ensurepip", calls[2])
        pip_command = calls[3]
        self.assertIn("--isolated", pip_command)
        self.assertIn("https://pypi.org/simple", pip_command)
        self.assertEqual(pip_command[-1], str(launcher.REQUIREMENTS))

    def test_command_failure_is_not_success(self):
        child = MagicMock(returncode=1)
        child.communicate.return_value = ("test install failure", None)
        with patch.object(launcher.subprocess, "Popen", return_value=child), self.assertRaises(RuntimeError):
            self.dialog.run_command(["fake-python"], "Test install")
        self.assertIsNone(self.dialog.process)

    def test_timeout_terminates_child_and_reports_failure(self):
        child = MagicMock(returncode=1)
        child.communicate.side_effect = [subprocess.TimeoutExpired("test", 300), ("timed out", None)]
        with patch.object(launcher.subprocess, "Popen", return_value=child), self.assertRaises(RuntimeError):
            self.dialog.run_command(["fake-python"], "Test install")
        child.kill.assert_called_once()

    def test_cancelled_setup_does_not_start_process(self):
        self.dialog.cancelled.set()
        with patch.object(launcher.subprocess, "Popen") as popen, self.assertRaises(InterruptedError):
            self.dialog.run_command(["fake-python"], "Test install")
        popen.assert_not_called()

    def test_setup_failure_allows_retry(self):
        with patch.object(self.dialog, "run_command", side_effect=RuntimeError("test failure")):
            self.dialog.install()
            deadline = time.monotonic() + 3
            while self.dialog.running and time.monotonic() < deadline:
                self.root.update()
                time.sleep(0.01)
        self.assertFalse(self.dialog.success)
        self.assertFalse(self.dialog.running)
        self.assertEqual(self.dialog.install_btn["text"], "Retry setup")
        self.assertIn("test failure", self.dialog.status.get())


class LaunchFlowTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        self.root = MagicMock()
        patch.object(launcher.tk, "Tk", return_value=self.root).start()
        patch.object(launcher, "enable_dpi_awareness").start()
        self.missing = patch.object(launcher, "missing_dependencies", return_value=[]).start()
        self.admin = patch.object(launcher, "ensure_admin", return_value=True).start()
        patch.object(launcher, "is_windows_admin", return_value=False).start()
        self.gui = patch.object(app, "UnsubscribeApp").start()
        self.relaunch = patch.object(launcher, "relaunch_with").start()
        self.error = patch.object(launcher.messagebox, "showerror").start()

    def test_ready_launch_constructs_gui_after_elevation(self):
        launcher.launch([])
        self.admin.assert_called_once_with(self.root, [])
        self.gui.assert_called_once_with(self.root, administrator=False)
        self.root.mainloop.assert_called_once()
        self.relaunch.assert_not_called()

    def test_successful_elevation_does_not_create_duplicate_gui(self):
        self.admin.return_value = False
        launcher.launch([])
        self.gui.assert_not_called()
        self.root.mainloop.assert_not_called()
        self.root.destroy.assert_called_once()

    def test_reuses_installed_private_environment(self):
        self.missing.return_value = ["dkim"]
        with patch.object(launcher, "runtime_works", return_value=True):
            launcher.launch(["--no-admin"])
        self.relaunch.assert_called_once()
        self.assertEqual(self.relaunch.call_args.args[1], ["--no-admin", "--runtime-ready"])
        self.admin.assert_not_called()

    def test_setup_requires_consent_before_admin(self):
        self.missing.return_value = ["dkim"]
        dialog = MagicMock()
        dialog.show.return_value = False
        with patch.object(launcher, "runtime_works", return_value=False), \
                patch.object(launcher, "SetupDialog", return_value=dialog):
            launcher.launch([])
        dialog.show.assert_called_once()
        self.admin.assert_not_called()
        self.relaunch.assert_not_called()
        self.gui.assert_not_called()

    def test_completed_setup_relaunches_environment(self):
        self.missing.return_value = ["dkim"]
        dialog = MagicMock()
        dialog.show.return_value = True
        dialog.directory = Path(tempfile.gettempdir()) / "gmail-test-runtime"
        with patch.object(launcher, "runtime_works", return_value=False), \
                patch.object(launcher, "SetupDialog", return_value=dialog):
            launcher.launch([])
        self.relaunch.assert_called_once()
        self.admin.assert_not_called()

    def test_broken_runtime_cannot_loop_setup(self):
        self.missing.return_value = ["dkim"]
        launcher.launch(["--runtime-ready"])
        self.error.assert_called_once()
        self.relaunch.assert_not_called()
        self.gui.assert_not_called()

    def test_main_pyw_delegates_to_gui_launcher(self):
        with patch.object(launcher, "launch") as start:
            runpy.run_path(str(launcher.GUI_SCRIPT), run_name="__main__")
        start.assert_called_once_with()

    def test_standard_pyw_sets_explicit_flag(self):
        with patch.object(launcher, "launch") as start, patch("sys.argv", ["test"]):
            runpy.run_path(str(launcher.BASE_DIR / "Gmail Unsubscriber (Standard Mode).pyw"), run_name="__main__")
        start.assert_called_once_with(["--no-admin"])


if __name__ == "__main__":
    unittest.main()
