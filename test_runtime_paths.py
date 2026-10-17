"""Tests for runtime paths and venv repair.

Windows behavior and package installation are mocked. The integration tests
create temporary venvs with the local interpreter. No packages are downloaded.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

import desktop_launcher as launcher
import gmail_unsubscriber as app
from test_gmail_unsubscriber import OfflineCase


def create_fake_runtime(directory):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "pyvenv.cfg").write_text("home = fake-base-python\n", encoding="utf-8")
    for windowed in (False, True):
        executable = launcher.runtime_python(directory, windowed=windowed)
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.touch()


class RuntimePathTests(unittest.TestCase):
    def test_windows_uses_profile_instead_of_redirected_localappdata(self):
        with tempfile.TemporaryDirectory() as home, patch.object(launcher, "IS_WINDOWS", True), \
                patch.object(launcher.Path, "home", return_value=Path(home)), \
                patch.dict(os.environ, {"LOCALAPPDATA": str(Path(home) / "AppData" / "Local")}):
            directory = launcher.runtime_directory()
            self.assertEqual(directory.parent, Path(home) / ".gmail-unsubscriber")
            self.assertNotEqual(directory.parent, Path(os.environ["LOCALAPPDATA"]) / ".gmail-unsubscriber")
            self.assertFalse(directory.exists())

    def test_unix_retains_xdg_data_home(self):
        with tempfile.TemporaryDirectory() as home, patch.object(launcher, "IS_WINDOWS", False), \
                patch.dict(os.environ, {"XDG_DATA_HOME": home}):
            self.assertEqual(launcher.runtime_directory().parent, Path(home) / "GmailUnsubscriber")

    def test_runtime_tag_separates_python_minor_and_architecture(self):
        name = launcher.runtime_directory().name
        self.assertIn(sys.implementation.cache_tag, name)
        self.assertTrue(name.endswith(("-32", "-64")))

    def test_resolution_performs_no_creation(self):
        with tempfile.TemporaryDirectory() as home:
            directory = Path(home) / "not-created"
            self.assertEqual(launcher.canonical_runtime_directory(directory), directory.resolve())
            self.assertFalse(directory.exists())

    def test_canonical_directory_uses_actual_redirected_path(self):
        with patch.object(launcher.os.path, "realpath", return_value="/real/GmailUnsubscriber/runtime") as resolve:
            result = launcher.canonical_runtime_directory(Path("/requested/runtime"))
        self.assertEqual(result, Path("/real/GmailUnsubscriber/runtime"))
        resolve.assert_called_once_with(Path("/requested/runtime"))

    def test_orphan_executable_without_cfg_is_not_run(self):
        with tempfile.TemporaryDirectory() as home:
            directory = Path(home)
            exe = launcher.runtime_python(directory)
            exe.parent.mkdir(parents=True, exist_ok=True)
            exe.touch()
            with patch.object(launcher.subprocess, "run") as run:
                self.assertFalse(launcher.runtime_works(directory))
                self.assertFalse(launcher.runtime_interpreter_works(directory))
            run.assert_not_called()

    def test_missing_pythonw_rejects_windows_environment(self):
        with tempfile.TemporaryDirectory() as home, patch.object(launcher, "IS_WINDOWS", True):
            directory = Path(home)
            create_fake_runtime(directory)
            launcher.runtime_python(directory, windowed=True).unlink()
            with patch.object(launcher.subprocess, "run") as run:
                self.assertFalse(launcher.runtime_works(directory))
            run.assert_not_called()

    def test_exit_106_is_an_unhealthy_runtime(self):
        with tempfile.TemporaryDirectory() as home:
            directory = Path(home)
            create_fake_runtime(directory)
            with patch.object(launcher.subprocess, "run", return_value=MagicMock(returncode=106)):
                self.assertFalse(launcher.runtime_interpreter_works(directory))

    def test_probe_checks_prefix_and_not_just_imports(self):
        with tempfile.TemporaryDirectory() as home:
            command = launcher.runtime_check_command(Path(home), dependencies=True)
            self.assertEqual(command[-1], home)
            self.assertIn("sys.prefix == sys.base_prefix", command[-2])
            self.assertIn("actual != expected", command[-2])
            self.assertIn("import dns.resolver, dkim, nacl.signing", command[-2])
            self.assertIn("-I", command)

    def test_core_probe_does_not_require_downloaded_modules(self):
        command = launcher.runtime_check_command(Path("/test/runtime"))
        self.assertNotIn("dns.resolver", command[-2])
        self.assertIn("tkinter", command[-2])

    def test_windowed_probe_uses_pythonw(self):
        with patch.object(launcher, "IS_WINDOWS", True):
            command = launcher.runtime_check_command(Path("/test/runtime"), windowed=True)
        self.assertTrue(command[0].endswith("pythonw.exe"))

    def test_child_timeout_is_an_unhealthy_runtime(self):
        with tempfile.TemporaryDirectory() as home:
            directory = Path(home)
            create_fake_runtime(directory)
            with patch.object(launcher.subprocess, "run", side_effect=subprocess.TimeoutExpired("python", 15)):
                self.assertFalse(launcher.runtime_works(directory))


GUI_AVAILABLE = bool(os.environ.get("DISPLAY")) or os.name == "nt"


@unittest.skipUnless(GUI_AVAILABLE, "Requires a desktop or Xvfb DISPLAY.")
class SetupRepairTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.temp = tempfile.TemporaryDirectory()
        self.root = app.tk.Tk()
        self.root.withdraw()
        self.dialog = launcher.SetupDialog(self.root, Path(self.temp.name) / "runtime")
        self.root.update()

    def tearDown(self):
        if self.dialog.worker is not None:
            self.dialog.worker.join(3)
        if self.dialog.winfo_exists():
            self.dialog.close()
        self.root.destroy()
        self.temp.cleanup()

    def wait_for_job(self):
        deadline = time.monotonic() + 4
        while self.dialog.running and time.monotonic() < deadline:
            self.root.update()
            time.sleep(0.01)
        self.assertFalse(self.dialog.running)

    def fake_command(self, command, description):
        if "venv" in command:
            create_fake_runtime(Path(command[-1]))

    def test_missing_cfg_repairs_even_when_python_exe_exists(self):
        exe = launcher.runtime_python(self.dialog.directory)
        exe.parent.mkdir(parents=True, exist_ok=True)
        exe.touch()
        sentinel = self.dialog.directory / "unrelated-file.txt"
        sentinel.write_text("leave this file alone")
        with patch.object(self.dialog, "run_command", side_effect=self.fake_command) as command:
            self.dialog.install()
            self.wait_for_job()
        self.assertTrue(self.dialog.success)
        first, description = command.call_args_list[0].args
        self.assertIn("venv", first)
        self.assertIn("Repairing", description)
        self.assertNotIn("--clear", first)
        self.assertEqual(sentinel.read_text(), "leave this file alone")

    def test_incomplete_creation_blocks_pip(self):
        with patch.object(self.dialog, "run_command") as command:
            self.dialog.install()
            self.wait_for_job()
        self.assertFalse(self.dialog.success)
        self.assertEqual(command.call_count, 1)
        self.assertIn("pyvenv.cfg", self.dialog.status.get())
        self.assertIn("No package installation was attempted", self.dialog.status.get())

    def test_failed_prefix_check_blocks_pip(self):
        def fake(command, description):
            self.fake_command(command, description)
            if description.startswith("Checking the private"):
                raise RuntimeError("Python did not start inside the requested private environment.")
        with patch.object(self.dialog, "run_command", side_effect=fake) as command:
            self.dialog.install()
            self.wait_for_job()
        self.assertFalse(self.dialog.success)
        self.assertEqual(command.call_count, 2)
        self.assertFalse(any("pip" in call.args[0] or "ensurepip" in call.args[0]
                             for call in command.call_args_list))

    def test_post_creation_redirect_used_for_every_remaining_command(self):
        requested = self.dialog.directory
        actual = Path(self.temp.name) / "actual runtime"
        def fake(command, description):
            if "venv" in command:
                create_fake_runtime(actual)
        with patch.object(launcher, "runtime_interpreter_works", return_value=False), \
                patch.object(launcher, "canonical_runtime_directory", side_effect=[requested, actual]), \
                patch.object(self.dialog, "run_command", side_effect=fake) as command:
            self.dialog.install()
            self.wait_for_job()
        self.assertTrue(self.dialog.success)
        self.assertEqual(self.dialog.directory, actual)
        for call in command.call_args_list[1:]:
            self.assertEqual(Path(call.args[0][0]).parent, launcher.runtime_python(actual).parent)

    def test_healthy_interpreter_is_not_recreated(self):
        create_fake_runtime(self.dialog.directory)
        with patch.object(launcher, "runtime_interpreter_works", return_value=True), \
                patch.object(self.dialog, "run_command") as command:
            self.dialog.install()
            self.wait_for_job()
        self.assertTrue(self.dialog.success)
        self.assertFalse(any("venv" in call.args[0] for call in command.call_args_list))
        self.assertTrue(any("ensurepip" in call.args[0] for call in command.call_args_list))

    def test_windows_windowed_interpreter_is_checked(self):
        with patch.object(launcher, "IS_WINDOWS", True), \
                patch.object(launcher, "runtime_interpreter_works", return_value=False), \
                patch.object(self.dialog, "run_command", side_effect=self.fake_command) as command:
            self.dialog.install()
            self.wait_for_job()
        self.assertTrue(self.dialog.success)
        self.assertEqual(len(command.call_args_list), 6)
        self.assertTrue(command.call_args_list[-1].args[0][0].endswith("pythonw.exe"))

    def test_setup_buttons_stay_visible_in_small_window_and_on_error(self):
        for width, height, status in (
                (670, 500, "Ready to install."),
                (570, 420, "Ready to install."),
                (570, 420, "Python could not locate its virtual-environment configuration. " * 4)):
            self.dialog.geometry(f"{width}x{height}")
            self.dialog.status.set(status)
            self.root.update()
            bottom = self.dialog.winfo_rooty() + self.dialog.winfo_height()
            for button in (self.dialog.install_btn, self.dialog.cancel_btn):
                self.assertTrue(button.winfo_viewable())
                self.assertLessEqual(button.winfo_rooty() + button.winfo_height(), bottom)

    def test_exit_106_produces_specific_repair_message(self):
        child = MagicMock(returncode=106)
        child.communicate.return_value = ("failed to locate pyvenv.cfg: not found", None)
        with patch.object(launcher.subprocess, "Popen", return_value=child):
            with self.assertRaisesRegex(RuntimeError, "check and repair"):
                self.dialog.run_command(["fake-python"], "Checking the environment")
        self.assertIsNone(self.dialog.process)

    def test_retry_after_partial_failure_can_complete(self):
        with patch.object(self.dialog, "run_command"):
            self.dialog.install()
            self.wait_for_job()
        self.assertFalse(self.dialog.success)
        with patch.object(self.dialog, "run_command", side_effect=self.fake_command):
            self.dialog.install()
            self.wait_for_job()
        self.assertTrue(self.dialog.success)


class ResolvedRelaunchTests(unittest.TestCase):
    def test_launch_uses_directory_returned_by_setup_not_requested_path(self):
        with tempfile.TemporaryDirectory() as home:
            actual = Path(home) / "actual runtime"
            requested = Path(home) / "requested runtime"
            root, dialog = MagicMock(), MagicMock()
            dialog.show.return_value = True
            dialog.directory = actual
            with patch.object(launcher.tk, "Tk", return_value=root), \
                    patch.object(launcher, "enable_dpi_awareness"), \
                    patch.object(launcher, "missing_dependencies", return_value=["dkim"]), \
                    patch.object(launcher, "runtime_directory", return_value=requested), \
                    patch.object(launcher, "runtime_works", return_value=False), \
                    patch.object(launcher, "SetupDialog", return_value=dialog), \
                    patch.object(launcher, "relaunch_with") as relaunch, \
                    patch.object(launcher.messagebox, "showerror") as error:
                launcher.launch(["--no-admin"])
            error.assert_not_called()
            relaunch.assert_called_once_with(str(launcher.runtime_python(actual, windowed=True)),
                                             ["--no-admin", "--runtime-ready"])


class RealInterpreterTests(unittest.TestCase):
    """Create and repair temporary venvs with the local Python interpreter."""
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="gmail-runtime-tests-")
        cls.directory = Path(cls.temp.name) / "runtime with spaces"
        cls.directory.mkdir()
        cls.directory = launcher.canonical_runtime_directory(cls.directory)
        command = [launcher.python_executable(windowed=False), "-I", "-m", "venv", "--without-pip", str(cls.directory)]
        cls.create_command = command
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if result.returncode:
            cls.temp.cleanup()
            raise AssertionError(f"Local venv creation failed: {result.stdout}\n{result.stderr}")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_real_environment_starts_and_matches_prefix(self):
        self.assertTrue(launcher.runtime_files_exist(self.directory))
        self.assertTrue(launcher.runtime_interpreter_works(self.directory))

    def test_real_probe_rejects_the_base_interpreter(self):
        command = launcher.runtime_check_command(self.directory)
        command[0] = launcher.python_executable(windowed=False)
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requested private environment", result.stderr)

    def test_real_probe_rejects_a_different_environment(self):
        command = launcher.runtime_check_command(self.directory)
        command[-1] = str(self.directory / "wrong-location")
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requested private environment", result.stderr)

    def test_real_missing_cfg_is_detected_then_recreated_without_deleting_files(self):
        cfg = self.directory / "pyvenv.cfg"
        original = cfg.read_bytes()
        sentinel = self.directory / "keep-me.txt"
        sentinel.write_text("preserved")
        try:
            cfg.unlink()
            self.assertFalse(launcher.runtime_interpreter_works(self.directory))
            result = subprocess.run(self.create_command, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(launcher.runtime_interpreter_works(self.directory))
            self.assertEqual(sentinel.read_text(), "preserved")
        finally:
            if not cfg.exists():
                cfg.write_bytes(original)

    def test_real_ensurepip_bootstraps_locally_without_downloads(self):
        python = str(launcher.runtime_python(self.directory))
        result = subprocess.run([python, "-I", "-m", "ensurepip", "--upgrade", "--default-pip"],
                                capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = subprocess.run([python, "-I", "-m", "pip", "--version"],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(self.directory), result.stdout)


if __name__ == "__main__":
    unittest.main()
