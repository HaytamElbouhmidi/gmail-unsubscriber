"""Windows launcher. Requests administrator access before opening the app."""
import sys


def show_startup_error(message):
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Gmail Unsubscriber", message, parent=root)
        root.destroy()
    except Exception:
        if sys.platform == "win32":
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, message, "Gmail Unsubscriber", 0x10)
        elif sys.stderr is not None:
            sys.stderr.write(message + "\n")


if __name__ == "__main__":
    if sys.version_info < (3, 10):
        show_startup_error("Python 3.10 or newer is required. Install a current Python version with Tcl/Tk support.")
    else:
        try:
            from desktop_launcher import launch
            launch()
        except Exception as exc:
            show_startup_error("Could not start the application. Extract the entire ZIP and keep its files together.\n\n"
                               + type(exc).__name__ + ": " + str(exc))
