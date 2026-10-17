#!/usr/bin/env python3
"""Capture sample-data screenshots from the installed v3.1.0 interface.

Run from a desktop with Pillow installed. Gmail credentials are not required.
"""
from __future__ import annotations

import tkinter as tk
from pathlib import Path
from PIL import ImageGrab

import gmail_unsubscriber as app

VERSION = "3.1.0"
HERE = Path(__file__).resolve().parent
SCREENSHOTS = HERE / "docs" / "images"


def sample(uid: int, name: str, sender: str, subject: str, list_id: str,
           link: str, date: str) -> app.Candidate:
    raw = (f"From: {name} <{sender}>\r\n"
           f"Subject: {subject}\r\nDate: {date}\r\n"
           f"List-ID: <{list_id}>\r\n"
           f"List-Unsubscribe: <{link}>\r\n\r\n").encode("utf-8")
    return app.parse_candidate(raw, str(uid), "123")


def capture(root: tk.Tk, destination: str) -> None:
    root.update_idletasks()
    root.update()
    x, y = root.winfo_rootx(), root.winfo_rooty()
    ImageGrab.grab(bbox=(x, y, x + root.winfo_width(), y + root.winfo_height())).save(
        SCREENSHOTS / destination)


def main() -> None:
    if app.APP_VERSION != VERSION:
        raise RuntimeError("Apply the 3.1.0 update before capturing screenshots.")
    SCREENSHOTS.mkdir(parents=True, exist_ok=True)
    root = tk.Tk()
    root.geometry("1180x850+30+30")
    gui = app.UnsubscribeApp(root)
    try:
        gui.email_var.set("demo@gmail.com")
        gui.pass_var.set("")
        gui.scan_choice_var.set("1,000")
        gui.spam_var.set(True)
        gui.resume_var.set(True)
        gui.fallback_var.set(True)
        rows = [
            ("Engineering Digest", "digest@engineering.example.com", "Weekly engineering digest",
             "engineering.example.com", "mailto:unsubscribe@engineering.example.com", "Fri, 16 Oct 2026 13:15:00 +0000", "Email submitted"),
            ("Product Updates", "updates@products.example.com", "Your update is ready",
             "products.example.com", "mailto:unsubscribe@products.example.com", "Thu, 15 Oct 2026 17:22:00 +0000", "Failed"),
            ("Microfluidics Weekly", "news@microfluidics.example.com", "October issue",
             "microfluidics.example.com", "mailto:unsubscribe@microfluidics.example.com", "Tue, 13 Oct 2026 10:06:00 +0000", "Request accepted"),
            ("Conference Brief", "conference@events.example.com", "Reserve your seat",
             "events.example.com", "https://events.example.com/unsubscribe", "Mon, 12 Oct 2026 18:40:00 +0000", "Manual action required"),
        ]
        for index, (name, sender, subject, list_id, link, date, status) in enumerate(rows, 1):
            c = sample(100 + index, name, sender, subject, list_id, link, date)
            gui._add_candidate(c)
            if status != "Manual action required":
                gui._record_result(app.Result(c, "demo@gmail.com", "MAILTO", link, status, "Sample result"))
        gui._refresh_results()
        gui.progress_bar.configure(mode="determinate", maximum=1000, value=1000)
        gui.progress_text_var.set("Complete | 1,000 / 1,000 messages (100%)")
        gui.status_var.set("Complete. Sample scan results. No network requests were made.")
        capture(root, "v3.1-overview.png")

        gui.sort_var.set("Outcome")
        gui.outcome_filter_var.set("Failed")
        gui._refresh_results()
        capture(root, "v3.1-outcomes.png")

        gui.outcome_filter_var.set("All")
        gui._refresh_results()
        gui.progress_bar.configure(maximum=1000, value=648)
        gui.progress_text_var.set("Stopped | 648 / 1,000 messages (64.8%)")
        gui.status_var.set("Stopped. Saved progress can be resumed on the next scan.")
        capture(root, "v3.1-resume.png")
    finally:
        gui._destroy()
    print(f"Saved sample-data UI screenshots to {SCREENSHOTS}")


if __name__ == "__main__":
    main()
