"""Start the GUI, install missing dependencies, and handle Windows elevation.

Setup uses a private virtual environment and leaves system Python alone.
This module uses the standard library and doesn't handle Gmail credentials.
"""
from __future__ import annotations

import ctypes
import importlib
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from typing import Sequence

BASE_DIR = Path(__file__).resolve().parent
GUI_SCRIPT = BASE_DIR / "Gmail Unsubscriber.pyw"
REQUIREMENTS = BASE_DIR / "requirements.txt"
IS_WINDOWS = sys.platform == "win32"
ALLOWED_FLAGS = {"--no-admin", "--elevated", "--runtime-ready"}
REQUIRED_IMPORTS = ("dns.resolver", "dkim", "nacl.signing")
# Check sys.prefix as well as the executable.
# A broken venv can fall back to the base Python installation.
RUNTIME_PROBE = """import os, sys, tkinter
expected = os.path.normcase(os.path.realpath(sys.argv[1]))
actual = os.path.normcase(os.path.realpath(sys.prefix))
if sys.prefix == sys.base_prefix or actual != expected:
    raise RuntimeError('Python did not start inside the requested private environment.')
"""


def launch_flags(arguments: Sequence[str]) -> list[str]:
    """Forward known startup flags only, never credentials."""
    return list(dict.fromkeys(arg for arg in arguments if arg in ALLOWED_FLAGS))


def python_executable(*, windowed: bool, executable: str | None = None) -> str:
    """Find python or pythonw in the current environment."""
    if not IS_WINDOWS and executable is not None:
        return executable
    current = Path(executable or sys.executable).absolute()
    if IS_WINDOWS:
        name = "pythonw.exe" if windowed else "python.exe"
        sibling = current.with_name(name)
        if sibling.is_file():
            return str(sibling)
        # pythonw can run pip with captured output if python.exe is missing.
    return str(current)


def process_options() -> dict:
    options: dict = {"stdin": subprocess.DEVNULL}
    if IS_WINDOWS:
        options["creationflags"] = subprocess.CREATE_NO_WINDOW
    return options


def runtime_directory() -> Path:
    """Choose the runtime path without creating it yet.

    Keep Windows runtimes under the user profile. Store Python redirects
    AppData writes, which can leave child processes using the wrong path.
    Leave older AppData runtimes alone.
    """
    if IS_WINDOWS:
        home = Path.home() / ".gmail-unsubscriber"
    else:
        data_home = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share"))
        home = data_home / "GmailUnsubscriber"
    # Keep separate runtimes for each Python version and architecture.
    tag = f"{sys.implementation.cache_tag}-{ctypes.sizeof(ctypes.c_void_p) * 8}"
    return home / ("runtime-" + tag)


def canonical_runtime_directory(directory: Path) -> Path:
    """Resolve the venv folder, not the interpreter symlink inside it.

    Call again after creating the folder so Windows can resolve any junctions.
    This only resolves the path; it doesn't create anything.
    """
    return Path(os.path.realpath(directory))


def runtime_python(directory: Path, *, windowed: bool = False) -> Path:
    if IS_WINDOWS:
        return directory / "Scripts" / ("pythonw.exe" if windowed else "python.exe")
    return directory / "bin" / "python"


def missing_dependencies() -> list[str]:
    missing = []
    for name in REQUIRED_IMPORTS:
        try:
            importlib.import_module(name)
        except Exception:
            missing.append(name)
    return missing


def runtime_check_command(directory: Path, *, dependencies: bool = False,
                          windowed: bool = False) -> list[str]:
    code = RUNTIME_PROBE
    if dependencies:
        code += "import dns.resolver, dkim, nacl.signing\n"
    return [str(runtime_python(directory, windowed=windowed)), "-I", "-X", "utf8",
            "-c", code, str(directory)]


def runtime_files_exist(directory: Path) -> bool:
    # python.exe alone isn't enough; pyvenv.cfg must be there too.
    return ((directory / "pyvenv.cfg").is_file()
            and runtime_python(directory).is_file()
            and (not IS_WINDOWS or runtime_python(directory, windowed=True).is_file()))


def _runtime_works(directory: Path, *, dependencies: bool) -> bool:
    directory = canonical_runtime_directory(directory)
    if not runtime_files_exist(directory):
        return False
    try:
        check = subprocess.run(
            runtime_check_command(directory, dependencies=dependencies),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, **process_options(),
        )
        return check.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def runtime_interpreter_works(directory: Path) -> bool:
    return _runtime_works(directory, dependencies=False)


def runtime_works(directory: Path) -> bool:
    return _runtime_works(directory, dependencies=True)


def relaunch_with(python: str, flags: Sequence[str]) -> None:
    if not GUI_SCRIPT.is_file():
        raise FileNotFoundError("The GUI launcher is missing. Extract the complete ZIP into one folder.")
    # Pass an argument list so paths with spaces don't need shell quoting.
    subprocess.Popen([python, str(GUI_SCRIPT), *launch_flags(flags)], cwd=str(BASE_DIR),
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **process_options())


def is_windows_admin() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        check = ctypes.windll.shell32.IsUserAnAdmin
        check.argtypes = []
        check.restype = ctypes.c_int
        return bool(check())
    except (AttributeError, OSError):
        return False


def request_elevation(flags: Sequence[str]) -> int:
    """Request administrator access through the Windows UAC prompt."""
    if not IS_WINDOWS:
        return 33
    shell_execute = ctypes.windll.shell32.ShellExecuteW
    shell_execute.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                             ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int]
    # Use a pointer-sized return type for 64-bit Windows.
    shell_execute.restype = ctypes.c_void_p
    arguments = [str(GUI_SCRIPT), *launch_flags(flags)]
    if "--elevated" not in arguments:
        arguments.append("--elevated")
    params = subprocess.list2cmdline(arguments)
    result = shell_execute(None, "runas", python_executable(windowed=True), params, str(BASE_DIR), 1)
    return int(result or 0)


def ensure_admin(root: tk.Tk, flags: Sequence[str]) -> bool:
    """Return True to continue here, or False to exit after relaunch or cancellation."""
    if not IS_WINDOWS or "--no-admin" in flags or is_windows_admin():
        return True
    if "--elevated" in flags:
        detail = "Windows did not start the app with administrator privileges."
    else:
        try:
            result = request_elevation(flags)
            if result > 32:
                return False
            detail = f"Administrator access was cancelled or could not be granted (Windows code {result})."
        except OSError as exc:
            detail = f"Windows could not request administrator access: {exc}"
    # Ask before falling back to standard mode.
    return messagebox.askyesno(
        "Continue without administrator access?",
        detail + "\n\nGmail scanning and unsubscribing do not require administrator privileges. "
        "Continue in standard mode?\n\nChoose No to close the app.",
        parent=root, default=messagebox.NO,
    )


class SetupDialog(tk.Toplevel):
    """Install dependencies after approval, with progress and a Cancel button."""
    def __init__(self, parent: tk.Tk, directory: Path) -> None:
        super().__init__(parent)
        self.title("Gmail Unsubscriber - Setup and repair")
        self.resizable(True, True)
        self.geometry("670x500")
        self.minsize(570, 420)
        self.directory = directory
        self.success = False
        self.running = False
        self.done_received = False
        self.cancelled = threading.Event()
        self.events: queue.Queue[tuple[str, str]] = queue.Queue()
        self.worker: threading.Thread | None = None
        self.process: subprocess.Popen | None = None
        self.lock = threading.Lock()
        self.poll_id: str | None = None
        body = ttk.Frame(self, padding=18)
        body.pack(fill=tk.BOTH, expand=True)
        ttk.Label(body, text="One-time setup", font=("Segoe UI", 16, "bold")).pack(anchor=tk.W)
        ttk.Label(body, text="Install the libraries needed to check safe destinations and verify unsubscribe signatures. "
                  "Nothing will be installed until you choose Install and continue.", wraplength=615).pack(fill=tk.X, pady=10)
        ttk.Label(body, text="Downloads from PyPI: dnspython, dkimpy, PyNaCl, and their dependencies.\n"
                  "A private Python environment will be created here:", wraplength=615).pack(fill=tk.X)
        self.location_var = tk.StringVar(self, value=str(directory))
        location = ttk.Entry(body, textvariable=self.location_var, state="readonly")
        location.pack(fill=tk.X, pady=8)
        ttk.Label(body, text="System Python is not modified. Incomplete setup here will be repaired. "
                  "Old AppData runtimes are left untouched. Internet access is needed for downloads.",
                  wraplength=615).pack(anchor=tk.W)
        self.status = tk.StringVar(self, value="Ready to install. You can cancel without opening your Gmail account.")
        ttk.Label(body, textvariable=self.status, wraplength=615).pack(fill=tk.X, pady=(12, 5))
        self.progress = ttk.Progressbar(body, mode="indeterminate")
        self.progress.pack(fill=tk.X)
        self.output = scrolledtext.ScrolledText(body, height=8, state=tk.DISABLED, wrap=tk.WORD)
        self.output.pack(fill=tk.BOTH, expand=True, pady=10)
        buttons = ttk.Frame(body)
        # Keep the buttons visible when the setup window is small.
        buttons.pack(side=tk.BOTTOM, fill=tk.X, before=body.winfo_children()[0])
        self.cancel_btn = ttk.Button(buttons, text="Cancel", command=self.cancel)
        self.cancel_btn.pack(side=tk.RIGHT)
        self.install_btn = ttk.Button(buttons, text="Install and continue", command=self.install)
        self.install_btn.pack(side=tk.RIGHT, padx=8)
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.poll_id = self.after(80, self.poll)

    def append(self, text: str) -> None:
        self.output.configure(state=tk.NORMAL)
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)
        self.output.configure(state=tk.DISABLED)

    def run_command(self, command: list[str], description: str) -> None:
        if self.cancelled.is_set():
            raise InterruptedError("Setup cancelled.")
        self.events.put(("status", description))
        with self.lock:
            if self.cancelled.is_set():
                raise InterruptedError("Setup cancelled.")
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            text=True, encoding="utf-8", errors="replace", **process_options())
            child = self.process
        try:
            try:
                output, _ = child.communicate(timeout=300)
            except subprocess.TimeoutExpired:
                child.kill()
                output, _ = child.communicate()
                self.events.put(("log", output[-12000:]))
                raise RuntimeError("Setup timed out. Check your internet connection, then try again.")
            self.events.put(("log", output[-12000:]))
            if self.cancelled.is_set():
                raise InterruptedError("Setup cancelled.")
            if child.returncode != 0:
                detail = f"{description} failed (exit code {child.returncode}). See the setup output above."
                if child.returncode == 106 or "failed to locate pyvenv.cfg" in output.lower():
                    detail += ("\n\nPython could not locate its virtual-environment configuration. "
                               "Setup has stopped before continuing. The next attempt will check and repair "
                               "the private environment shown above. Do not copy python.exe on its own.")
                raise RuntimeError(detail)
        finally:
            with self.lock:
                self.process = None

    def resolve_directory(self) -> None:
        requested = self.directory
        self.directory = canonical_runtime_directory(requested)
        self.events.put(("location", str(self.directory)))
        if self.directory != requested:
            self.events.put(("log", f"Using the actual environment location: {self.directory}"))

    def install(self) -> None:
        if self.running:
            return
        if not REQUIREMENTS.is_file():
            messagebox.showerror("Missing setup file", "Extract the complete ZIP first. requirements.txt is missing.", parent=self)
            return
        self.running = True
        self.done_received = False
        self.cancelled.clear()
        self.install_btn.configure(state=tk.DISABLED)
        self.progress.start(12)

        def job() -> None:
            try:
                if self.cancelled.is_set():
                    raise InterruptedError("Setup cancelled.")
                self.directory.mkdir(parents=True, exist_ok=True)
                self.resolve_directory()
                if not runtime_interpreter_works(self.directory):
                    description = ("Repairing the private Python environment..." if
                                   ((self.directory / "pyvenv.cfg").exists() or
                                    runtime_python(self.directory).exists()) else
                                   "Creating the private Python environment...")
                    # Repair in place. Don't clear this folder or remove older AppData runtimes.
                    self.run_command([python_executable(windowed=False), "-I", "-X", "utf8",
                                      "-m", "venv", "--without-pip", str(self.directory)], description)
                self.resolve_directory()
                if not runtime_files_exist(self.directory):
                    raise RuntimeError("Python did not create a complete virtual environment at "
                                       + str(self.directory) + ". pyvenv.cfg and the Python launchers "
                                       "must exist together. No package installation was attempted.")
                # Check the interpreter's venv before installing packages.
                self.run_command(runtime_check_command(self.directory), "Checking the private Python environment...")
                self.run_command([str(runtime_python(self.directory)), "-I", "-X", "utf8", "-m",
                                  "ensurepip", "--upgrade", "--default-pip"], "Preparing the package installer...")
                self.run_command([str(runtime_python(self.directory)), "-I", "-X", "utf8", "-m", "pip", "--isolated", "install",
                                  "--disable-pip-version-check", "--no-input", "--index-url", "https://pypi.org/simple",
                                  "--timeout", "20", "--retries", "2", "-r", str(REQUIREMENTS)],
                                 "Installing the required libraries...")
                self.run_command(runtime_check_command(self.directory, dependencies=True), "Checking the installation...")
                if IS_WINDOWS:
                    # Test pythonw too; a working python.exe doesn't guarantee it will launch.
                    self.run_command(runtime_check_command(self.directory, dependencies=True, windowed=True),
                                     "Checking window-only startup...")
                self.events.put(("success", "Setup complete."))
            except Exception as exc:
                self.events.put(("error", str(exc)))
            finally:
                self.events.put(("done", ""))

        self.worker = threading.Thread(target=job, name="gmail-setup", daemon=False)
        self.worker.start()

    def poll(self) -> None:
        self.poll_id = None
        while True:
            try:
                kind, text = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "status":
                self.status.set(text)
                self.append(text)
            elif kind == "location":
                self.location_var.set(text)
            elif kind == "log":
                self.append(text)
            elif kind == "success":
                self.success = True
            elif kind == "done":
                self.done_received = True
            elif kind == "error":
                self.success = False
                self.status.set(text)
                self.append(text)
        if self.running and self.done_received and self.worker is not None and not self.worker.is_alive():
            self.worker.join()
            self.running = False
            self.progress.stop()
            if self.success or self.cancelled.is_set():
                self.close()
                return
            self.install_btn.configure(state=tk.NORMAL, text="Retry setup")
            self.cancel_btn.configure(state=tk.NORMAL)
        self.poll_id = self.after(80, self.poll)

    def cancel(self) -> None:
        if not self.running:
            self.close()
            return
        self.cancelled.set()
        self.status.set("Stopping setup...")
        self.cancel_btn.configure(state=tk.DISABLED)
        with self.lock:
            if self.process is not None:
                try:
                    self.process.terminate()
                except OSError:
                    pass

    def close(self) -> None:
        if self.poll_id is not None:
            self.after_cancel(self.poll_id)
            self.poll_id = None
        self.destroy()

    def show(self) -> bool:
        if not self.winfo_viewable():
            self.wait_visibility()
        self.grab_set()
        self.wait_window()
        return self.success and not self.cancelled.is_set()


def enable_dpi_awareness() -> None:
    if IS_WINDOWS:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except (AttributeError, OSError):
                pass


def launch(arguments: Sequence[str] | None = None) -> None:
    flags = launch_flags(sys.argv[1:] if arguments is None else arguments)
    enable_dpi_awareness()
    root = tk.Tk()
    root.withdraw()
    try:
        if missing_dependencies():
            directory = runtime_directory()
            if "--runtime-ready" in flags:
                messagebox.showerror("Python environment problem", "The setup environment could not load its libraries. "
                                     "Close the app and reopen it without command-line flags to retry setup.", parent=root)
                return
            directory = canonical_runtime_directory(directory)
            if not runtime_works(directory):
                setup = SetupDialog(root, directory)
                if not setup.show():
                    return
                # Use the resolved setup path, which may differ after Windows redirection.
                directory = setup.directory
            directory = canonical_runtime_directory(directory)
            relaunch_with(str(runtime_python(directory, windowed=True)), [*flags, "--runtime-ready"])
            return
        if not ensure_admin(root, flags):
            return
        # Load the app after setup and elevation have finished.
        from gmail_unsubscriber import UnsubscribeApp
        app = UnsubscribeApp(root, administrator=is_windows_admin())

        def report_callback_exception(exc_type, exc_value, traceback_object):
            # Show callback errors in a popup, without saving credentials or locals.
            message = f"A window action failed ({exc_type.__name__}). No automatic retry will be made."
            if not app.destroyed:
                app.log(message)
                if app.is_running:
                    app.stop_process()
                messagebox.showerror("Application error", message + "\n\nReview the recorded outcomes before retrying.", parent=root)

        root.report_callback_exception = report_callback_exception
        root.deiconify()
        root.lift()
        app.email_entry.focus_set()
        root.mainloop()
    except Exception as exc:
        messagebox.showerror("Could not start Gmail Unsubscriber",
                             f"{type(exc).__name__}: {exc}\n\nKeep all files from the ZIP together in one extracted folder.", parent=root)
    finally:
        try:
            if root.winfo_exists():
                root.destroy()
        except tk.TclError:
            pass


if __name__ == "__main__":
    launch()
