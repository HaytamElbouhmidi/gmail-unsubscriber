#!/usr/bin/env python3
"""Capture the original Tkinter interface with synthetic records for README screenshots.

Version 3.1.0. No credentials, Gmail queries, or unsubscribe operations.
"""
from __future__ import annotations

import tkinter as tk
from pathlib import Path
from PIL import ImageGrab

import gmail_unsubscriber as app

VERSION = "3.1.0"
HERE = Path(__file__).resolve().parent
IMAGES = HERE / "docs" / "images"


def sample(uid: int, name: str, sender: str, subject: str, list_id: str,
           link: str, date: str) -> app.Candidate:
    raw = (f"From: {name} <{sender}>\r\n"
           f"Subject: {subject}\r\nDate: {date}\r\n"
           f"List-ID: <{list_id}>\r\n"
           f"List-Unsubscribe: <{link}>\r\n\r\n").encode("utf-8")
    result = app.parse_candidate(raw, str(uid), "123")
    if result is None:
        raise ValueError("Sample list could not be parsed")
    return result


def capture(root: tk.Tk, filename: str) -> None:
    root.lift()
    root.update_idletasks()
    root.update()
    x, y = root.winfo_rootx(), root.winfo_rooty()
    width, height = root.winfo_width(), root.winfo_height()
    if width < 500 or height < 400:
        raise RuntimeError("Screenshot window was not fully displayed")
    ImageGrab.grab(bbox=(x, y, x + width, y + height)).convert("RGB").save(IMAGES / filename)


def main() -> None:
    if getattr(app, "APP_VERSION", None) != VERSION:
        raise RuntimeError("Install Gmail Unsubscriber v3.1.0 before capturing screenshots")
    IMAGES.mkdir(parents=True, exist_ok=True)
    root = tk.Tk()
    gui = app.UnsubscribeApp(root)
    root.geometry("1180x830+55+55")
    try:
        gui.email_var.set("demo@example.com")
        gui.pass_var.set("")
        gui.spam_var.set(True)
        gui.resume_var.set(True)
        gui.fallback_var.set(True)
        gui._mode_changed()
        records = [
            ("Engineering Digest", "digest@engineering.example.com", "Weekly engineering digest",
             "engineering.example.com", "mailto:unsubscribe@engineering.example.com",
             "Fri, 16 Oct 2026 13:15:00 +0000", "Email submitted"),
            ("Product Updates", "updates@products.example.com", "New release available",
             "products.example.com", "mailto:unsubscribe@products.example.com",
             "Thu, 15 Oct 2026 17:22:00 +0000", "Failed"),
            ("Microfluidics Weekly", "news@microfluidics.example.com", "October issue",
             "microfluidics.example.com", "mailto:unsubscribe@microfluidics.example.com",
             "Tue, 13 Oct 2026 10:06:00 +0000", "Request accepted"),
            ("Conference Brief", "conference@events.example.com", "Upcoming seminar",
             "events.example.com", "https://events.example.com/unsubscribe",
             "Mon, 12 Oct 2026 18:40:00 +0000", "Manual action required"),
        ]
        for index, (name, sender, subject, list_id, link, date, status) in enumerate(records, 1):
            candidate = sample(200 + index, name, sender, subject, list_id, link, date)
            gui._add_candidate(candidate)
            if status != "Manual action required":
                method = "POST" if status == "Request accepted" else "MAILTO"
                gui._record_result(app.Result(candidate, "demo@example.com", method, link,
                                              status, "Synthetic result. No email was sent."))
        gui._refresh_results()
        gui.progress_bar.configure(mode="determinate", maximum=1000, value=1000)
        gui.progress_text_var.set("Complete | 1,000 / 1,000 messages (100%)")
        gui.status_var.set("Complete. Sample data only. No Gmail connection was made.")
        capture(root, "overview.png")

        gui.scan_choice_var.set("Custom")
        gui.custom_limit_var.set("2500")
        capture(root, "scan-amounts.png")

        gui.auto_var.set(True)
        gui._mode_changed()
        capture(root, "auto-unsubscribe.png")
        gui.auto_var.set(False)
        gui._mode_changed()
        gui.scan_choice_var.set("1,000")

        gui.sort_var.set("Outcome")
        gui.descending_var.set(False)
        gui._sort_label()
        gui._refresh_results()
        capture(root, "search-and-sort.png")

        gui.progress_bar.configure(maximum=1000, value=648)
        gui.progress_text_var.set("648 / 1,000 messages (64.8%)")
        gui.status_var.set("Reading sample email headers. Results and progress remain visible.")
        capture(root, "scan-progress.png")
        gui.progress_text_var.set("Stopped | 648 / 1,000 messages (64.8%)")
        gui.status_var.set("Stopped. Restart with the same settings to resume the saved scan.")
        capture(root, "resume.png")
        gui.progress_bar.configure(maximum=1000, value=1000)
        gui.progress_text_var.set("Complete | 1,000 / 1,000 messages (100%)")
        gui.status_var.set("Complete. Accepted requests are not confirmation of removal.")
        capture(root, "scan-complete.png")
    finally:
        gui._destroy()
    print("Updated 7 README screenshots using the original Tkinter interface and sample data")


if __name__ == "__main__":
    main()
