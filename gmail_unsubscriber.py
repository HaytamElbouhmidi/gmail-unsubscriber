#!/usr/bin/env python3
"""Gmail inbox scanner and unsubscribe GUI.

Scan first and choose senders, or turn on auto unsubscribe.
One-click requests require DKIM checks. Passwords and message bodies stay in memory.
"""
from __future__ import annotations

import csv
import hashlib
import http.client
import imaplib
import ipaddress
import os
import queue
import re
import smtplib
import socket
import ssl
import sys
import tempfile
import threading
import time
import tkinter as tk
import webbrowser
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.header import decode_header
from email.message import EmailMessage
from email.parser import BytesHeaderParser
from email.utils import formatdate, make_msgid, parseaddr, parsedate_to_datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any, Callable, Iterator
from urllib.parse import unquote, urlsplit, urlunsplit

IMAP_HOST = "imap.gmail.com"
SMTP_HOST = "smtp.gmail.com"
IO_TIMEOUT = 10.0
OPERATION_TIMEOUT = 30.0
DNS_TIMEOUT = 5.0
SYSTEM_DNS_TIMEOUT = 8.0
# Limit pending lookups. A timed-out system DNS call can still be running.
_SYSTEM_DNS_SLOTS = threading.BoundedSemaphore(2)
SEND_INTERVAL = 3.0
MAX_HEADERS = 128 * 1024
MAX_MESSAGE = 10 * 1024 * 1024
MAX_URI = 8192
MAX_BODY = 64 * 1024
POST_VALUE = "List-Unsubscribe=One-Click"
POST_BODY = POST_VALUE.encode("ascii")
HEADER_FIELDS = "FROM SUBJECT DATE LIST-ID LIST-UNSUBSCRIBE LIST-UNSUBSCRIBE-POST DKIM-SIGNATURE"
# Use a plain header fetch. The IMAP reader enforces the size limit.
FETCH_HEADERS = f"(BODY.PEEK[HEADER.FIELDS ({HEADER_FIELDS})])"
FETCH_HEADER_ALTERNATIVES = (FETCH_HEADERS, "(BODY.PEEK[HEADER])", "(RFC822.HEADER)")
IMAP_READ_ATTEMPTS = 2
IMAP_RETRY_DELAY = 1.0
MAX_CONSECUTIVE_FETCH_FAILURES = 5
SUCCESS_STATUSES = {"Request accepted", "Email submitted"}
UNCERTAIN_STATUSES = {"Outcome unknown", "Partial email submission"}
CSV_COLUMNS = (
    "Timestamp UTC", "Account", "Message UID", "List ID", "Sender Name",
    "Sender Email", "Sample Subject", "Method", "Status", "Details", "Unsubscribe Target",
)


@dataclass(frozen=True)
class ProgressUpdate:
    completed: int
    total: int | None
    activity: str
    unit: str = "messages"


class UiEventQueue(queue.Queue):
    """Keep every result, but only the newest progress update."""
    def __init__(self) -> None:
        super().__init__()
        self._latest_progress: ProgressUpdate | None = None
        self._latest_activity: str | None = None

    def put(self, item: tuple[str, Any], block: bool = True, timeout: float | None = None) -> None:
        kind, payload = item
        if kind in {"progress", "activity"}:
            with self.mutex:
                if isinstance(payload, ProgressUpdate):
                    self._latest_progress = payload
                    self._latest_activity = payload.activity
                else:
                    self._latest_activity = str(payload)
            return
        super().put(item, block, timeout)

    def take_progress(self) -> tuple[ProgressUpdate | None, str | None]:
        with self.mutex:
            progress, activity = self._latest_progress, self._latest_activity
            self._latest_progress = None
            self._latest_activity = None
        return progress, activity


def elapsed_text(seconds: float) -> str:
    minutes, seconds = divmod(max(0, int(seconds)), 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours}:{minutes:02d}:{seconds:02d}" if hours else f"{minutes:02d}:{seconds:02d}"


class Cancelled(Exception):
    """The user stopped the current operation."""


class SafetyError(ValueError):
    """Input failed a safety check."""


class DNSResolutionError(ConnectionError):
    """DNS lookup failed."""


class OversizedLiteral(SafetyError):
    """The IMAP response exceeds the download limit."""


class AuthenticationError(Exception):
    """Gmail rejected the login."""


class MailboxError(Exception):
    """A mailbox command failed."""


class MessageFetchError(MailboxError):
    """A message couldn't be read after retrying."""


class MailboxLimitError(MailboxError):
    """Gmail reported a quota or rate limit."""


class StaleScanError(MailboxError):
    """The mailbox UID generation changed after the scan."""


def display_text(value: Any) -> str:
    """Remove control characters and keep displayed text on one line."""
    text = str(value)
    return " ".join("".join(
        c if (c.isprintable() and c not in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069") else " "
        for c in text
    ).split())


def decode_mime_header(value: Any) -> str:
    if not value:
        return "Unknown"
    try:
        pieces = []
        for content, encoding in decode_header(str(value)):
            if isinstance(content, bytes):
                try:
                    content = content.decode(encoding or "utf-8", errors="replace")
                except (LookupError, UnicodeError):
                    content = content.decode("utf-8", errors="replace")
            pieces.append(content)
        return display_text("".join(pieces))
    except (ValueError, TypeError):
        return display_text(value)


def normalize_domain(host: str) -> str:
    if not host or host.endswith(".."):
        raise SafetyError("Missing or malformed hostname.")
    host = host.rstrip(".")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise SafetyError("Invalid hostname.") from exc
    if len(host) > 253 or "." not in host or host.rsplit(".", 1)[-1].isdigit():
        raise SafetyError("A public DNS hostname is required; IP literals are not allowed.")
    for label in host.split("."):
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
            raise SafetyError("Invalid hostname label.")
    if any(host == suffix or host.endswith("." + suffix) for suffix in (
        "localhost", "local", "localdomain", "internal", "intranet", "home", "home.arpa",
        "lan", "test", "invalid", "onion",
    )):
        raise SafetyError("Local or special-use hostnames are not allowed.")
    return host


@dataclass(frozen=True)
class WebTarget:
    url: str
    host: str
    port: int
    path: str


def parse_web_url(raw: str, *, https_only: bool = True) -> WebTarget:
    # Reject control characters before urlsplit can strip them.
    if not raw or len(raw) > MAX_URI or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in raw):
        raise SafetyError("URL is empty, too long, or contains whitespace/control characters.")
    if "\\" in raw or not raw.isascii() or re.search(r"%(?![0-9A-Fa-f]{2})", raw):
        raise SafetyError("Use an ASCII URL with valid percent encoding and no backslashes.")
    try:
        parts = urlsplit(raw)
        scheme = parts.scheme.lower()
        if scheme not in ({"https"} if https_only else {"http", "https"}):
            raise SafetyError("Automatic requests require HTTPS.")
        if "@" in parts.netloc or parts.fragment or "#" in raw:
            raise SafetyError("URL credentials and fragments are not allowed.")
        if not parts.hostname or ":" in parts.hostname or "[" in parts.netloc:
            raise SafetyError("IP literals and missing hostnames are not allowed.")
        host = normalize_domain(parts.hostname)
        if parts.netloc.endswith(":"):
            raise SafetyError("Empty URL port is not allowed.")
        port = parts.port if parts.port is not None else (443 if scheme == "https" else 80)
        if port != (443 if scheme == "https" else 80):
            raise SafetyError("Only the standard HTTP/HTTPS port is allowed.")
    except ValueError as exc:
        if isinstance(exc, SafetyError):
            raise
        raise SafetyError("Malformed URL or port.") from exc
    path = parts.path or "/"
    path += ("?" + parts.query) if parts.query else ""
    normalized = urlunsplit((scheme, host, parts.path or "/", parts.query, ""))
    return WebTarget(normalized, host, port, path)


def decode_uri_part(value: str) -> str:
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise SafetyError("Invalid percent encoding in mailto URL.")
    try:
        # Keep literal '+' characters intact, as required by RFC 6068.
        return unquote(value, encoding="utf-8", errors="strict")
    except UnicodeError as exc:
        raise SafetyError("Invalid UTF-8 in mailto URL.") from exc


def validate_address(address: str) -> str:
    if not address or len(address) > 254 or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in address):
        raise SafetyError("Invalid email address or header-injection characters.")
    if address.count("@") != 1:
        raise SafetyError("A plain email address is required.")
    local, domain = address.rsplit("@", 1)
    atom = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
    if len(local) > 64 or not re.fullmatch(atom + r"(?:\." + atom + r")*", local):
        raise SafetyError("Quoted or internationalized local parts require manual handling.")
    return local + "@" + normalize_domain(domain)


@dataclass(frozen=True)
class MailtoTarget:
    recipients: tuple[str, ...]
    subject: str
    body: str


def parse_mailto(raw: str) -> MailtoTarget:
    if len(raw) > MAX_URI or any(ord(c) < 32 or ord(c) == 127 for c in raw):
        raise SafetyError("Invalid mailto URL length/control characters.")
    parts = urlsplit(raw)
    if parts.scheme.lower() != "mailto" or parts.netloc or "#" in raw:
        raise SafetyError("Malformed mailto URL.")
    recipients = tuple(validate_address(a.strip()) for a in decode_uri_part(parts.path).split(","))
    recipients = tuple(dict.fromkeys(recipients))
    if not 1 <= len(recipients) <= 5:
        raise SafetyError("Mailto requests must contain between one and five recipients.")
    fields: dict[str, str] = {}
    for item in parts.query.split("&") if parts.query else ():
        key, sep, value = item.partition("=")
        key = decode_uri_part(key).lower()
        if not sep or key not in {"subject", "body"} or key in fields:
            raise SafetyError("Only one subject and one body parameter are supported; no CC/BCC or extra headers.")
        fields[key] = decode_uri_part(value)
    subject = fields.get("subject", "Unsubscribe")
    body = fields.get("body", "Please unsubscribe me from this mailing list. Thank you.")
    if len(subject.encode("utf-8")) > 998 or any(ord(c) < 32 or ord(c) == 127 for c in subject):
        raise SafetyError("Subject contains control characters or is too long.")
    if len(body.encode("utf-8")) > MAX_BODY or any((ord(c) < 32 and c not in "\t\r\n") or ord(c) == 127 for c in body):
        raise SafetyError("Mailto body contains invalid controls or is too long.")
    return MailtoTarget(recipients, subject, body)


def is_public_ip(text: str) -> bool:
    address = ipaddress.ip_address(text)
    if not address.is_global or address.is_multicast or address.is_reserved:
        return False
    # Cover special-use addresses classified differently across Python versions.
    if isinstance(address, ipaddress.IPv4Address) and address in ipaddress.ip_network("192.0.0.0/24"):
        return False
    if isinstance(address, ipaddress.IPv6Address) and address in ipaddress.ip_network("2001::/23"):
        return False
    if isinstance(address, ipaddress.IPv6Address):
        # Don't trust IPv6 transition addresses with an embedded IPv4 address.
        if address.ipv4_mapped or address.sixtofour or address.teredo:
            return False
        if address in ipaddress.ip_network("64:ff9b::/96") or address in ipaddress.ip_network("64:ff9b:1::/48"):
            return False
    return True


class NetworkGuard:
    """Track sockets so Stop and timeouts can close them.

    Use one guard per worker. The GUI calls cancel(); the worker owns the rest.
    DNS lookups have their own timeout.
    """
    def __init__(self) -> None:
        self.stop_event = threading.Event()
        self._lock = threading.Lock()
        self._sockets: set[Any] = set()
        self._expired: threading.Event | None = None

    def check(self) -> None:
        if self.stop_event.is_set():
            raise Cancelled("Stopped by user.")
        if self._expired is not None and self._expired.is_set():
            raise TimeoutError("Operation deadline exceeded.")

    def watch(self, sock: Any) -> Any:
        with self._lock:
            self._sockets.add(sock)
        try:
            self.check()
        except Exception:
            self.release(sock)
            raise
        return sock

    def release(self, sock: Any) -> None:
        with self._lock:
            self._sockets.discard(sock)
        try:
            sock.close()
        except OSError:
            pass

    def abort_sockets(self) -> None:
        with self._lock:
            sockets = tuple(self._sockets)
            self._sockets.clear()
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def cancel(self) -> None:
        self.stop_event.set()
        self.abort_sockets()

    @contextmanager
    def operation(self, seconds: float = OPERATION_TIMEOUT) -> Iterator[None]:
        self.check()
        if self._expired is not None:
            raise RuntimeError("Network operation scopes must not be nested.")
        expired = threading.Event()
        self._expired = expired

        def expire() -> None:
            expired.set()
            self.abort_sockets()

        timer = threading.Timer(seconds, expire)
        timer.daemon = True
        timer.start()
        try:
            yield
            if expired.is_set():
                raise TimeoutError("Operation deadline exceeded.")
        finally:
            timer.cancel()
            timer.join()
            self._expired = None


def _system_addresses(host: str, guard: NetworkGuard) -> tuple[str, ...]:
    """Run a system DNS lookup with a timeout.

    A lookup can outlive its timeout, but its late result is ignored.
    The semaphore limits pending lookups to two.
    """
    guard.check()
    slots = _SYSTEM_DNS_SLOTS
    if not slots.acquire(blocking=False):
        raise TimeoutError("Previous system DNS lookups are still finishing.")
    result: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)
    lookup = socket.getaddrinfo

    def resolve() -> None:
        try:
            # The trailing dot prevents local search domains from being appended.
            value = lookup(host + ".", 0, socket.AF_UNSPEC,
                           socket.SOCK_STREAM, socket.IPPROTO_TCP)
            result.put((True, value))
        except Exception as exc:
            result.put((False, exc))
        finally:
            slots.release()

    thread = threading.Thread(target=resolve, name="gmail-system-dns", daemon=True)
    try:
        thread.start()
    except BaseException:
        slots.release()
        raise
    deadline = time.monotonic() + SYSTEM_DNS_TIMEOUT
    while True:
        guard.check()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("System DNS lookup timed out.")
        try:
            succeeded, value = result.get(timeout=min(0.05, remaining))
        except queue.Empty:
            continue
        guard.check()
        if not succeeded:
            raise value
        addresses = tuple(info[4][0] for info in value
                          if info[0] in (socket.AF_INET, socket.AF_INET6))
        if not addresses:
            raise OSError("System resolver returned no IPv4 or IPv6 addresses.")
        return addresses


def _dns_error_detail(exc: Exception) -> str:
    return f"{type(exc).__name__}: {display_text(exc)[:350]}"


def _validated_addresses(host: str, addresses: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Reject the DNS response if any address is unsafe."""
    try:
        if not addresses or any("%" in address or not is_public_ip(address) for address in addresses):
            raise ValueError("Non-public address")
        return tuple(dict.fromkeys(str(ipaddress.ip_address(address)) for address in addresses))
    except (ValueError, TypeError) as exc:
        raise SafetyError(
            f"{host} resolved to a local, private, reserved, or invalid address. "
            "The connection was blocked; destination checks were not bypassed."
        ) from exc


def _configured_dns_addresses(host: str, guard: NetworkGuard) -> tuple[str, ...]:
    """Try the configured DNS servers when the system lookup fails.

    Keep a valid IPv4 answer if IPv6 fails, and vice versa.
    Validate every returned address before connecting.
    """
    import dns.exception
    import dns.resolver
    guard.check()
    try:
        resolver = dns.resolver.Resolver()
    except (dns.exception.DNSException, OSError) as exc:
        guard.check()
        raise DNSResolutionError("Configured DNS could not initialize: " + _dns_error_detail(exc)) from exc
    resolver.timeout = min(2.0, DNS_TIMEOUT)
    addresses: list[str] = []
    failures: list[str] = []
    for record_type in ("A", "AAAA"):
        guard.check()
        try:
            answer = resolver.resolve(host + ".", record_type, search=False, lifetime=DNS_TIMEOUT)
            addresses.extend(record.address for record in answer)
        except dns.resolver.NoAnswer:
            failures.append(f"{record_type}: no records")
        except (dns.exception.DNSException, OSError) as exc:
            failures.append(f"{record_type}: {_dns_error_detail(exc)}")
        guard.check()
    if not addresses:
        raise DNSResolutionError("Configured DNS returned no addresses. " + "; ".join(failures))
    return _validated_addresses(host, addresses)


def resolve_public_addresses(host: str, guard: NetworkGuard) -> tuple[str, ...]:
    host = normalize_domain(host)
    guard.check()
    try:
        addresses = _system_addresses(host, guard)
    except OSError as exc:
        # Don't start another lookup after Stop or the overall timeout.
        guard.check()
        system_error = _dns_error_detail(exc)
    else:
        guard.check()
        # An unsafe DNS answer stays blocked; don't try another resolver.
        return _validated_addresses(host, addresses)
    try:
        return _configured_dns_addresses(host, guard)
    except (OSError, ImportError) as exc:
        guard.check()
        raise DNSResolutionError(
            f"Could not look up {host}. System DNS: {system_error}. "
            f"Fallback DNS: {_dns_error_detail(exc)}. "
            "This attempt stopped before connecting to that host. "
            "Check internet access and your network/VPN DNS settings, then use Test connection. "
            "This error is not a Gmail password rejection."
        ) from exc


def connect_tls(host: str, port: int, context: ssl.SSLContext, guard: NetworkGuard) -> ssl.SSLSocket:
    # Connect to the checked IP, but use the hostname for TLS verification.
    # Resolving again here could return a different, unchecked address.
    addresses = resolve_public_addresses(host, guard)
    last_error: Exception = OSError("No usable network address.")
    for address in addresses:
        guard.check()
        raw = guard.watch(socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM))
        wrapped = None
        try:
            raw.settimeout(IO_TIMEOUT)
            raw.connect((address, port))
            guard.check()
            wrapped = context.wrap_socket(raw, server_hostname=host, do_handshake_on_connect=False)
            guard.release(raw)  # The TLS socket now owns the file descriptor.
            guard.watch(wrapped)
            wrapped.settimeout(IO_TIMEOUT)
            wrapped.do_handshake()
            guard.check()
            return wrapped
        except Exception as exc:
            guard.release(wrapped if wrapped is not None else raw)
            # Try the next checked address unless Stop or the overall deadline has fired.
            guard.check()
            if isinstance(exc, (Cancelled, ssl.SSLCertVerificationError)):
                raise
            last_error = exc
    raise last_error


class VerifiedIMAP(imaplib.IMAP4_SSL):
    def __init__(self, guard: NetworkGuard) -> None:
        self.guard = guard
        self._literal_limit = MAX_MESSAGE + 1
        try:
            super().__init__(IMAP_HOST, 993, ssl_context=ssl.create_default_context(), timeout=IO_TIMEOUT)
        except Exception:
            sock = getattr(self, "sock", None)
            try:
                self.shutdown()
            except Exception:
                pass
            if sock is not None:
                guard.release(sock)
            raise

    def _create_socket(self, timeout: float | None) -> ssl.SSLSocket:
        return connect_tls(self.host, self.port, self.ssl_context, self.guard)

    def read(self, size: int) -> bytes:
        # Check the literal size before imaplib reads it.
        # An oversized reply leaves unread bytes, so this connection can't be reused.
        if size > self._literal_limit:
            raise OversizedLiteral(
                f"IMAP literal advertises {size:,} bytes; limit is {self._literal_limit:,} bytes.")
        return super().read(size)


class VerifiedSMTP(smtplib.SMTP_SSL):
    def __init__(self, guard: NetworkGuard) -> None:
        self.guard = guard
        # Use TLS from the start. A fixed EHLO name avoids another DNS lookup.
        try:
            super().__init__(SMTP_HOST, 465, local_hostname="[127.0.0.1]",
                             context=ssl.create_default_context(), timeout=IO_TIMEOUT)
        except Exception:
            sock = getattr(self, "sock", None)
            try:
                self.close()
            except Exception:
                pass
            if sock is not None:
                guard.release(sock)
            raise

    def _get_socket(self, host: str, port: int, timeout: float | None) -> ssl.SSLSocket:
        return connect_tls(host, port, self.context, self.guard)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, target: WebTarget, guard: NetworkGuard) -> None:
        self.guard = guard
        super().__init__(target.host, target.port, context=ssl.create_default_context(), timeout=IO_TIMEOUT)

    def connect(self) -> None:
        self.sock = connect_tls(self.host, self.port, self._context, self.guard)


def test_gmail_connection(*, guard: NetworkGuard, emit: Callable[[str, Any], None]) -> None:
    """Check DNS, TCP, and TLS without logging in or sending requests."""
    emit("log", "Connection test: no login, mailbox access, or unsubscribe requests.")
    report: list[str] = []
    endpoints = (("Inbox (IMAP)", IMAP_HOST, 993), ("Outgoing email (SMTP)", SMTP_HOST, 465))
    for index, (label, host, port) in enumerate(endpoints, 1):
        guard.check()
        emit("progress", ProgressUpdate(index - 1, len(endpoints), f"Testing {label}: {host}:{port}...", "checks"))
        sock = None
        try:
            with guard.operation():
                sock = connect_tls(host, port, ssl.create_default_context(), guard)
                line = f"PASS: {label} {host}:{port}. DNS, TCP, and TLS verification succeeded."
        except Cancelled:
            raise
        except (OSError, SafetyError) as exc:
            guard.check()
            line = f"FAIL: {label} {host}:{port}. {_dns_error_detail(exc)}"
        finally:
            if sock is not None:
                guard.release(sock)
        report.append(line)
        emit("log", line)
        emit("progress", ProgressUpdate(index, len(endpoints), f"Checked {label}.", "checks"))
    report.append("No login was attempted. A PASS does not verify your app password, DKIM, or unsubscribe delivery.")
    emit("connection_report", "\n\n".join(report))


def require_ok(status: str, operation: str, data: Any = None) -> None:
    if status != "OK":
        detail = " ".join(item.decode("utf-8", "replace") for item in (data or ()) if isinstance(item, bytes))
        detail = display_text(detail)[:500]
        text = f"{operation} failed (IMAP status {display_text(status)})." + (f" Server: {detail}" if detail else "")
        if re.search(r"overquota|rate.?limit|too many (?:requests|connections)|bandwidth|daily.*limit", detail, re.I):
            raise MailboxLimitError(text)
        raise MailboxError(text)


def uidvalidity(mail: Any) -> str:
    _, data = mail.response("UIDVALIDITY")
    if not data or not isinstance(data[0], bytes) or not data[0].isdigit():
        raise MailboxError("Server did not supply a valid UIDVALIDITY value.")
    return data[0].decode("ascii")



@contextmanager
def gmail_inbox(account: str, password: str, guard: NetworkGuard) -> Iterator[tuple[Any, str]]:
    mail = None
    try:
        with guard.operation():
            mail = VerifiedIMAP(guard)
            try:
                status, _ = mail.login(account, password)
                if status != "OK":
                    raise AuthenticationError("Gmail authentication failed. Check your address and app password.")
            except imaplib.IMAP4.abort:
                raise  # A dropped connection doesn't mean the password was rejected.
            except imaplib.IMAP4.error as exc:
                raise AuthenticationError("Gmail authentication failed. Check your address and app password.") from exc
            status, data = mail.select("INBOX", readonly=True)
            require_ok(status, "Read-only INBOX selection", data)
            validity = uidvalidity(mail)
        yield mail, validity
    finally:
        if mail is not None:
            sock = getattr(mail, "sock", None)
            try:
                if not guard.stop_event.is_set():
                    with guard.operation(2.0):
                        mail.logout()
            except Exception:
                pass  # Don't let a logout error hide the original result.
            finally:
                try:
                    mail.shutdown()
                except Exception:
                    pass
                if sock is not None:
                    guard.release(sock)


def fetch_literal(mail: Any, uid: str, query: str, guard: NetworkGuard) -> bytes | None:
    maximum = MAX_MESSAGE if "BODY.PEEK[]" in query.upper() else MAX_HEADERS
    previous = getattr(mail, "_literal_limit", MAX_MESSAGE + 1)
    mail._literal_limit = maximum
    try:
        with guard.operation():
            status, data = mail.uid("fetch", uid, query)
            require_ok(status, f"UID {uid} fetch", data)
    except OversizedLiteral:
        # Unread bytes remain on this connection. Close it without logging out.
        sock = getattr(mail, "sock", None)
        try:
            mail.shutdown()
        except Exception:
            pass
        if sock is not None:
            guard.release(sock)
        raise
    finally:
        mail._literal_limit = previous
    literals = []
    for part in data or ():
        if not (isinstance(part, tuple) and len(part) >= 2 and isinstance(part[1], bytes)):
            continue
        envelope = part[0] if isinstance(part[0], bytes) else b""
        match = re.search(rb"\bUID\s+(\d+)\b", envelope, flags=re.I)
        if not match or match.group(1).decode("ascii") != uid:
            raise MailboxError(f"UID {uid} fetch returned a literal without the matching UID; not processed.")
        if len(part[1]) > maximum:
            raise OversizedLiteral(f"UID {uid}: message data exceeds the {maximum:,}-byte limit.")
        literals.append(part[1])
    if not literals:
        return None  # The message may have been deleted since the search.
    if len(literals) != 1:
        raise MailboxError("Unexpected multiple message literals in a single-UID fetch.")
    return literals[0]


@dataclass(frozen=True)
class Target:
    method: str
    uri: str
    note: str = ""


@dataclass(frozen=True)
class Candidate:
    uid: str
    validity: str
    sender_name: str
    sender_email: str
    subject: str
    list_id: str
    targets: tuple[Target, ...]
    header_fingerprint: str
    sent_at: datetime | None = None

    @property
    def key(self) -> str:
        # Different unsubscribe URLs stay separate, even for the same sender or list.
        value = repr((self.sender_email.casefold(), self.list_id, sorted((t.method, t.uri, t.note) for t in self.targets)))
        return hashlib.sha256(value.encode("utf-8")).hexdigest()


def header_values(message: Any, name: str) -> list[str]:
    return [re.sub(r"\r?\n[ \t]+", " ", str(v)).strip() for v in message.get_all(name, [])]


def parse_candidate(raw: bytes, uid: str, validity: str) -> Candidate | None:
    message = BytesHeaderParser(policy=policy.compat32).parsebytes(raw)
    unsubscribe = header_values(message, "List-Unsubscribe")
    if not unsubscribe:
        return None
    post = header_values(message, "List-Unsubscribe-Post")
    links = list(dict.fromkeys(re.findall(r"<([^<>]+)>", " ".join(unsubscribe))))
    name, address = parseaddr(decode_mime_header(message.get("From")))
    name = display_text(name or address or "Unknown sender")
    address = display_text(address)
    list_id = display_text(message.get("List-ID", ""))
    malformed_headers = (len(unsubscribe) != 1 or len(post) > 1 or len(links) > 16
                         or len(message.get_all("From", [])) != 1)
    web_schemes = [link.split(":", 1)[0].lower() for link in links if ":" in link]
    one_click = (not malformed_headers and post == [POST_VALUE]
                 and web_schemes.count("https") == 1 and "http" not in web_schemes)
    targets = []
    if not links:
        targets.append(Target("BLOCKED", "", "No supported angle-bracketed unsubscribe target."))
    for link in links[:16]:
        try:
            if malformed_headers:
                raise SafetyError("Missing/duplicate From, duplicate unsubscribe headers, or too many targets; manual inspection required.")
            scheme = link.split(":", 1)[0].lower()
            if scheme in {"https", "http"}:
                parsed = parse_web_url(link, https_only=False)
                if one_click and scheme == "https":
                    targets.append(Target("POST", parsed.url, "DKIM verification required before sending."))
                else:
                    targets.append(Target("MANUAL", parsed.url, "No verified one-click action; review the website manually."))
            elif scheme == "mailto":
                parse_mailto(link)
                targets.append(Target("MAILTO", link, "Sends an email; no DKIM authentication is required for this fallback."))
            else:
                raise SafetyError("Unsupported unsubscribe scheme.")
        except (ValueError, UnicodeError) as exc:
            targets.append(Target("BLOCKED", link, display_text(exc)))
    targets.sort(key=lambda target: {"POST": 0, "MAILTO": 1, "MANUAL": 2, "BLOCKED": 3}[target.method])
    # Check that the full message still has the same unsubscribe headers.
    fingerprint = hashlib.sha256(repr((unsubscribe, post)).encode("utf-8")).hexdigest()
    return Candidate(uid, validity, name, address, decode_mime_header(message.get("Subject")),
                     list_id, tuple(targets), fingerprint, parse_sent_date(message))


def scan_mailbox(account: str, password: str, limit: int, guard: NetworkGuard,
                 emit: Callable[[str, Any], None]) -> None:
    """Scan with read retries, without sending unsubscribe requests."""
    scan_and_unsubscribe(account, password, limit, guard, {}, emit, automatic=False)


def fetch_for_verification(mail: Any, candidate: Candidate, guard: NetworkGuard) -> bytes:
    with guard.operation():
        status, data = mail.uid("fetch", candidate.uid, "(RFC822.SIZE)")
        require_ok(status, "Message-size check", data)
    metadata = b" ".join(item for item in (data or ()) if isinstance(item, bytes))
    match = re.search(rb"\bRFC822\.SIZE\s+(\d+)", metadata, flags=re.I)
    if not match:
        raise MailboxError("Message size is unavailable; scan again if the message was moved.")
    size = int(match.group(1))
    if not 0 < size <= MAX_MESSAGE:
        raise SafetyError("Message exceeds the 10 MiB DKIM-verification limit; use manual review.")
    raw = fetch_literal(mail, candidate.uid, "(BODY.PEEK[])", guard)
    if raw is None or len(raw) != size:
        raise MailboxError("Full message is missing or incomplete; no POST was sent.")
    fresh = parse_candidate(raw, candidate.uid, candidate.validity)
    if not fresh or fresh.header_fingerprint != candidate.header_fingerprint:
        raise SafetyError("Unsubscribe headers changed during processing; no POST sent.")
    return raw


def verify_one_click_dkim(raw: bytes, guard: NetworkGuard) -> tuple[bool, str]:
    """Verify the message signature, not its Authentication-Results header."""
    try:
        import dkim
        import dns.exception
        import dns.resolver
    except ImportError:
        return False, "DKIM dependencies are missing. Install requirements.txt; automatic POST is disabled."
    message = BytesHeaderParser(policy=policy.compat32).parsebytes(raw)
    if (len(message.get_all("From", [])) != 1 or len(message.get_all("List-Unsubscribe", [])) != 1
            or header_values(message, "List-Unsubscribe-Post") != [POST_VALUE]):
        return False, "Missing, duplicate, or invalid one-click headers."
    signatures = message.get_all("DKIM-Signature", [])
    if not signatures or len(signatures) > 10:
        return False, "Missing DKIM signature or excessive signatures."

    def dnsfunc(name: bytes, timeout: float = DNS_TIMEOUT) -> bytes | None:
        guard.check()
        resolver = dns.resolver.Resolver()
        resolver.timeout = min(2.0, DNS_TIMEOUT)
        try:
            answer = resolver.resolve(name.decode("ascii").rstrip(".") + ".", "TXT",
                                      search=False, lifetime=min(float(timeout), DNS_TIMEOUT))
            values = [b"".join(record.strings) for record in answer]
            guard.check()
            return values[0] if len(values) == 1 else None
        except dns.exception.DNSException:
            return None

    last_reason = "No valid DKIM signature covering both unsubscribe headers."
    with guard.operation():
        for index, signature in enumerate(signatures):
            guard.check()
            tags: dict[str, str] = {}
            valid_tags = True
            for item in str(signature).split(";"):
                if not item.strip():
                    continue
                key, sep, value = item.strip().partition("=")
                key = key.strip().lower()
                if not sep or key in tags:
                    valid_tags = False
                    break
                tags[key] = value.strip()
            covered = {name.strip().lower() for name in tags.get("h", "").split(":")}
            if (not valid_tags or not {"from", "list-unsubscribe", "list-unsubscribe-post"} <= covered
                    or tags.get("a", "").lower() not in {"rsa-sha256", "ed25519-sha256"}):
                continue
            try:
                verifier = dkim.DKIM(raw, minkey=1024, timeout=DNS_TIMEOUT)
                if verifier.verify(idx=index, dnsfunc=dnsfunc):
                    guard.check()
                    return True, f"DKIM verified; signing domain: {display_text(tags.get('d', 'unknown'))}."
            except (Cancelled, TimeoutError):
                raise
            except Exception:
                last_reason = "DKIM verification failed or the signing key is unavailable."
    return False, last_reason


@dataclass(frozen=True)
class Result:
    candidate: Candidate
    account: str
    method: str
    target: str
    status: str
    detail: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def submit_one_click(url: str, guard: NetworkGuard) -> tuple[str, str]:
    target = parse_web_url(url)
    connection = PinnedHTTPSConnection(target, guard)
    response = None
    sock = None
    may_have_sent = False
    try:
        with guard.operation():
            connection.connect()
            sock = connection.sock
            guard.check()
            may_have_sent = True  # request() can raise after it has already sent data.
            connection.request("POST", target.path, body=POST_BODY, headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(POST_BODY)),
                "User-Agent": "Gmail-Auto-Unsubscriber/3.0",
                "Connection": "close",
            })
            response = connection.getresponse()
            status = response.status
            # Only read the status. No redirects, cookies, or HTTP authentication.
            if 200 <= status < 300:
                return "Request accepted", f"HTTP {status}. Removal is not independently confirmed."
            if 300 <= status < 400:
                return "Failed", f"HTTP {status} redirect blocked; review the link manually."
            return "Failed", f"HTTP {status}; the endpoint did not accept the request."
    except Cancelled:
        if may_have_sent:
            return "Outcome unknown", "Stopped after sending may have started; do not assume failure or immediately retry."
        raise
    except (OSError, http.client.HTTPException) as exc:
        if may_have_sent:
            return "Outcome unknown", f"No definitive response ({type(exc).__name__}); the request may have reached the server."
        return "Failed", f"Connection failed before sending ({type(exc).__name__})."
    finally:
        if response is not None:
            response.close()
        connection.close()
        if sock is not None:
            guard.release(sock)


def send_mailto(uri: str, account: str, password: str, guard: NetworkGuard) -> tuple[str, str]:
    target = parse_mailto(uri)
    account = validate_address(account)
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = account
    message["To"] = ", ".join(target.recipients)
    message["Subject"] = target.subject
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = make_msgid(domain=account.rsplit("@", 1)[1])
    message.set_content(target.body)
    smtp = None
    sock = None
    may_have_sent = False
    try:
        with guard.operation():
            smtp = VerifiedSMTP(guard)
            sock = smtp.sock
            code, _ = smtp.ehlo()
            if code != 250:
                raise smtplib.SMTPHeloError(code, b"EHLO rejected")
            smtp.login(account, password)
            guard.check()
            may_have_sent = True
            refused = smtp.send_message(message, from_addr=account, to_addrs=list(target.recipients))
            if refused:
                return "Partial email submission", "SMTP refused some recipients; other recipients may have received the request."
            return "Email submitted", "SMTP accepted the email. Mailing-list removal is not independently confirmed."
    except smtplib.SMTPAuthenticationError as exc:
        raise AuthenticationError("SMTP authentication failed. Check the Gmail app password.") from exc
    except (smtplib.SMTPRecipientsRefused, smtplib.SMTPDataError, smtplib.SMTPSenderRefused) as exc:
        return "Failed", f"SMTP rejected the email ({type(exc).__name__})."
    except Cancelled:
        if may_have_sent:
            return "Outcome unknown", "Stopped during submission; the email may have been accepted."
        raise
    except (OSError, smtplib.SMTPException) as exc:
        if may_have_sent:
            return "Outcome unknown", f"No definitive SMTP result ({type(exc).__name__}); do not immediately retry."
        return "Failed", f"SMTP connection failed before submission ({type(exc).__name__})."
    finally:
        if smtp is not None:
            try:
                smtp.close()
            except OSError:
                pass
        if sock is not None:
            guard.release(sock)


def execute_candidate(candidate: Candidate, account: str, password: str, guard: NetworkGuard,
                      fetch_raw: Callable[[Candidate], bytes], attempted: set[tuple[str, str]],
                      ledger: dict[tuple[str, str, str], str], emit: Callable[[str, Any], None]) -> None:
    def record(target: Target, status: str, detail: str) -> None:
        emit("result", Result(candidate, account, target.method, target.uri, status, detail))

    entry_key = (account.casefold(), "ENTRY", candidate.key)
    entry_status = ledger.get(entry_key)
    if entry_status in SUCCESS_STATUSES | UNCERTAIN_STATUSES:
        guard.check()
        status = "Already submitted" if entry_status in SUCCESS_STATUSES else "Outcome unknown"
        emit("result", Result(candidate, account, "ENTRY", "", status,
                              "This exact target set was already processed during this app session; no request repeated."))
        return

    for target in candidate.targets:
        guard.check()
        target_key = (target.method, target.uri)
        ledger_key = (account.casefold(), target.method, target.uri)
        if target.method == "BLOCKED":
            record(target, "Blocked", target.note)
            continue
        if target.method == "MANUAL":
            record(target, "Manual action required", target.note)
            continue
        previous = ledger.get(ledger_key)
        if previous in UNCERTAIN_STATUSES:
            record(target, "Outcome unknown", "This target has an uncertain prior submission. Automatic retry/fallback is disabled for this entry.")
            return
        if previous in SUCCESS_STATUSES:
            record(target, "Already submitted", "This exact method/target was already submitted during this app session.")
            continue  # Try any remaining targets for this entry.
        if target_key in attempted:
            record(target, "Skipped this run", "This exact target failed earlier in this batch; checking remaining alternatives.")
            continue
        if target.method == "POST":
            emit("activity", f"Verifying one-click unsubscribe for {candidate.sender_name}...")
            try:
                raw = fetch_raw(candidate)
                verified, detail = verify_one_click_dkim(raw, guard)
                del raw
            except (AuthenticationError, Cancelled, StaleScanError):
                raise
            except MailboxLimitError:
                raise
            except (SafetyError, MailboxError, OSError, imaplib.IMAP4.error) as exc:
                verified, detail = False, f"Message verification unavailable: {display_text(exc)}"
            if not verified:
                record(target, "Manual action required", detail + " No automatic POST was sent.")
                continue  # A valid mailto alternative can still be used.
            emit("log", f"{candidate.sender_name}: {detail}")
        guard.check()
        attempted.add(target_key)
        emit("activity", f"Sending {'one-click request' if target.method == 'POST' else 'unsubscribe email'} for {candidate.sender_name}...")
        try:
            status, detail = (submit_one_click(target.uri, guard) if target.method == "POST"
                              else send_mailto(target.uri, account, password, guard))
        except (AuthenticationError, Cancelled):
            raise
        except (SafetyError, ValueError) as exc:
            status, detail = "Blocked", display_text(exc)
        record(target, status, detail)
        if status in SUCCESS_STATUSES | UNCERTAIN_STATUSES:
            ledger[ledger_key] = status
            ledger[entry_key] = status
            # Use an event wait so Stop works during the delay.
            emit("activity", "Pausing before the next unsubscribe request...")
            guard.stop_event.wait(SEND_INTERVAL)
            return
        emit("activity", "Pausing before the next unsubscribe attempt...")
        if guard.stop_event.wait(SEND_INTERVAL):
            raise Cancelled("Stopped by user.")


def process_selected(candidates: tuple[Candidate, ...], account: str, password: str,
                     guard: NetworkGuard, ledger: dict[tuple[str, str, str], str],
                     emit: Callable[[str, Any], None]) -> None:
    """Send requests only for the checked entries captured at the start."""
    attempted: set[tuple[str, str]] = set()
    seen: set[str] = set()
    completed_lists: set[str] = set()
    with RecoveringInbox(account, password, guard, emit) as inbox:
        def load(candidate: Candidate) -> bytes:
            inbox._open()
            if any(item.validity != inbox.validity for item in candidates):
                raise StaleScanError("INBOX UIDVALIDITY changed. Run a new scan before sending.")
            return inbox.verification_message(candidate)

        completed = 0
        emit("progress", ProgressUpdate(0, len(candidates), "Preparing checked senders...", "entries"))
        for index, candidate in enumerate(candidates, 1):
            guard.check()
            emit("progress", ProgressUpdate(completed, len(candidates),
                 f"Processing checked entry {index:,}/{len(candidates):,}: {candidate.sender_name}", "entries"))
            try:
                list_key = subscription_key(candidate)
                ledger_key = (account.casefold(), "LIST", list_key) if list_key else None
                previous = ledger.get(ledger_key) if ledger_key else None
                if candidate.key in seen or previous in SUCCESS_STATUSES | UNCERTAIN_STATUSES:
                    if previous and list_key not in completed_lists:
                        completed_lists.add(list_key)
                        emit("result", Result(candidate, account, "ENTRY", "",
                             "Outcome unknown" if previous in UNCERTAIN_STATUSES else "Already submitted",
                             "This mailing list was already processed during this app session; no request repeated."))
                    completed = index
                    continue
                outcomes: list[Result] = []

                def report(kind: str, payload: Any) -> None:
                    if kind == "result":
                        outcomes.append(payload)
                        if ledger_key and payload.status in SUCCESS_STATUSES | UNCERTAIN_STATUSES:
                            ledger[ledger_key] = payload.status
                            completed_lists.add(list_key)
                    emit(kind, payload)

                execute_candidate(candidate, account, password, guard, load, attempted, ledger, report)
                states = {r.status for r in outcomes}
                unverified_post = any(r.method == "POST" and r.status == "Manual action required" for r in outcomes)
                if not unverified_post or states & (SUCCESS_STATUSES | UNCERTAIN_STATUSES):
                    seen.add(candidate.key)
                completed = index
            finally:
                emit("progress", ProgressUpdate(completed, len(candidates), "Updating checked-sender results...", "entries"))
    emit("log", "Checked senders processed. Accepted requests are not proof of completed removal.")


class RecoveringInbox:
    """Read-only IMAP connection with bounded retries.

    Check UIDVALIDITY after reconnecting. Retry mailbox reads only:
    an HTTP or SMTP timeout can happen after a request was sent.
    """
    def __init__(self, account: str, password: str, guard: NetworkGuard,
                 emit: Callable[[str, Any], None]) -> None:
        self.account, self.password, self.guard, self.emit = account, password, guard, emit
        self.mail: Any = None
        self.context: Any = None
        self.validity: str | None = None
        self.header_query = FETCH_HEADERS

    def __enter__(self) -> RecoveringInbox:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def close(self) -> None:
        context, self.context, self.mail = self.context, None, None
        if context is not None:
            context.__exit__(None, None, None)

    def _open(self) -> None:
        if self.mail is not None:
            return
        context = gmail_inbox(self.account, self.password, self.guard)
        mail, validity = context.__enter__()
        if self.validity is not None and validity != self.validity:
            context.__exit__(None, None, None)
            raise StaleScanError("INBOX UIDVALIDITY changed after reconnecting. Stopped to avoid processing the wrong messages.")
        self.mail, self.context, self.validity = mail, context, validity

    def read(self, description: str, action: Callable[[Any], Any]) -> Any:
        last_error: Exception | None = None
        for attempt in range(1, IMAP_READ_ATTEMPTS + 1):
            self.guard.check()
            opening = self.mail is None
            try:
                self._open()
                opening = False
                return action(self.mail)
            except (AuthenticationError, StaleScanError, MailboxLimitError, Cancelled,
                    ssl.SSLCertVerificationError, SafetyError):
                self.close()
                raise
            except (imaplib.IMAP4.error, MailboxError, OSError) as exc:
                self.guard.check()  # Don't reconnect after the user presses Stop.
                last_error = exc
                detail = display_text(exc)
                if self.password:
                    detail = detail.replace(self.password, "[redacted]")
                self.emit("log", f"{description}, attempt {attempt}/{IMAP_READ_ATTEMPTS}: "
                          f"{type(exc).__name__}: {detail}")
                self.close()
                if attempt == IMAP_READ_ATTEMPTS:
                    if opening:
                        raise MailboxError(f"Could not restore the Gmail connection. {detail}") from exc
                    break
                self.emit("activity", f"Reconnecting to Gmail: {description}...")
                self.emit("log", "Reconnecting to Gmail and retrying the read. Unsubscribe requests are not replayed.")
                if self.guard.stop_event.wait(IMAP_RETRY_DELAY):
                    raise Cancelled("Stopped during reconnect delay.")
        detail = display_text(last_error)
        if self.password:
            detail = detail.replace(self.password, "[redacted]")
        raise MessageFetchError(f"{description} failed after {IMAP_READ_ATTEMPTS} attempts: {detail}") from last_error

    def message_ids(self, limit: int) -> list[str]:
        def search(mail: Any) -> list[str]:
            with self.guard.operation():
                status, data = mail.uid("search", None, "ALL")
                require_ok(status, "Message search", data)
            if not data or not isinstance(data[0], bytes):
                raise MailboxError("Malformed SEARCH response.")
            values = data[0].split()
            if any(not uid.isdigit() or int(uid) < 1 for uid in values):
                raise MailboxError("SEARCH returned a malformed UID.")
            # Sort UIDs numerically, newest first, then take the requested count.
            result = sorted({int(uid) for uid in values}, reverse=True)
            return [str(uid) for uid in (result[:limit] if limit else result)]
        return self.read("List INBOX messages", search)

    def headers(self, uid: str) -> bytes | None:
        queries = tuple(dict.fromkeys((self.header_query, *FETCH_HEADER_ALTERNATIVES)))
        failures = []
        for index, query in enumerate(queries):
            try:
                raw = self.read(f"UID {uid} headers using {query}",
                                lambda mail: fetch_literal(mail, uid, query, self.guard))
                self.header_query = query  # Keep using the header format that worked.
                return raw
            except MessageFetchError as exc:
                failures.append(str(exc))
                if index + 1 < len(queries):
                    self.emit("log", f"UID {uid}: trying another read-only header format.")
        raise MessageFetchError(f"UID {uid}: all header formats failed. {failures[-1]}")

    def verification_message(self, candidate: Candidate) -> bytes:
        if candidate.validity != self.validity:
            raise StaleScanError("Candidate does not belong to the current INBOX generation.")
        return self.read(f"UID {candidate.uid} full-message verification fetch",
                         lambda mail: fetch_for_verification(mail, candidate, self.guard))


def subscription_key(candidate: Candidate) -> str | None:
    """Identify a list after an accepted or uncertain submission.

    Keep different List-IDs separate, even for the same sender.
    Without a usable List-ID, use exact entries and targets instead.
    """
    match = re.fullmatch(r"[^<>]*<([^<>\s@]+)>", candidate.list_id.strip())
    if not match or not candidate.sender_email:
        return None
    return hashlib.sha256(repr((candidate.sender_email.casefold(), match.group(1).casefold())).encode()).hexdigest()


def run_summary(stats: dict[str, int]) -> str:
    if not stats.get("automatic", 1):
        return (f"Checked {stats['checked']:,}/{stats['total']:,} messages; "
                f"{stats.get('found', 0):,} unique unsubscribe entries; "
                f"{stats['unreadable']:,} unreadable/missing. No requests sent.")
    return (f"Checked {stats['checked']:,}/{stats['total']:,} messages; "
            f"{stats['accepted']:,} requests accepted/submitted; "
            f"{stats['unknown']:,} uncertain; {stats['manual']:,} manual; "
            f"{stats['failed']:,} failed/blocked; {stats['duplicates']:,} duplicates skipped; "
            f"{stats['unreadable']:,} unreadable/missing.")


def scan_and_unsubscribe(account: str, password: str, limit: int, guard: NetworkGuard,
                         ledger: dict[tuple[str, str, str], str],
                         emit: Callable[[str, Any], None], *, automatic: bool = True) -> None:
    """Scan newest first and optionally unsubscribe as each list is found.

    The mode is fixed when the scan starts. Scan-only mode reads headers;
    it doesn't fetch full messages or contact unsubscribe endpoints.
    """
    if not isinstance(limit, int) or limit < 0:
        raise ValueError("The message limit must be a nonnegative integer; zero means all INBOX.")
    seen: set[str] = set()
    attempted: set[tuple[str, str]] = set()
    consecutive_failures = 0
    stats = dict(total=0, checked=0, accepted=0, unknown=0, manual=0,
                 failed=0, duplicates=0, unreadable=0, found=0, automatic=int(automatic))
    emit("progress", ProgressUpdate(0, None, "Connecting to Gmail and listing INBOX messages..."))
    try:
        with RecoveringInbox(account, password, guard, emit) as inbox:
            ids = inbox.message_ids(limit)
            stats['total'] = len(ids)
            emit("progress", ProgressUpdate(0, len(ids), "Message list loaded. Starting scan..."))
            if automatic:
                emit("log", f"Scanning and automatically unsubscribing from {len(ids):,} newest INBOX messages. "
                     "Requests are sent as supported lists are found.")
            else:
                emit("log", f"Scanning {len(ids):,} newest INBOX messages. No unsubscribe requests will be sent.")
            emit("log", "Mailbox access is read-only. Existing messages are not deleted or marked as read. "
                 "Ordinary confirmation webpages require manual action.")
            for index, uid in enumerate(ids, 1):
                guard.check()
                emit("progress", ProgressUpdate(stats['checked'], len(ids),
                     f"Reading message {index:,}/{len(ids):,} (UID {uid})..."))
                try:
                    try:
                        raw = inbox.headers(uid)
                    except (MessageFetchError, OversizedLiteral) as exc:
                        stats['checked'] = index
                        stats['unreadable'] += 1
                        consecutive_failures += 1
                        emit("log", f"SKIPPED message UID {uid}: {display_text(exc)}")
                        if consecutive_failures >= MAX_CONSECUTIVE_FETCH_FAILURES:
                            raise MailboxError(
                                f"{consecutive_failures} consecutive messages could not be read. "
                                "Stopped instead of silently skipping the rest of the inbox. "
                                "Earlier request outcomes are preserved in Results and export.") from exc
                        continue
                    stats['checked'] = index
                    consecutive_failures = 0
                    if raw is None:
                        stats['unreadable'] += 1
                        emit("log", f"UID {uid} is no longer in INBOX; skipped.")
                        continue
                    try:
                        emit("message", parse_message_info(raw, uid))
                        candidate = parse_candidate(raw, uid, str(inbox.validity))
                    except (ValueError, UnicodeError) as exc:
                        stats['unreadable'] += 1
                        emit("log", f"UID {uid}: malformed headers; skipped. {display_text(exc)}")
                        continue
                    if candidate is None:
                        continue
                    if not automatic:
                        # Keep older subjects for search and alternate copies for DKIM checks.
                        emit("candidate", candidate)
                        if candidate.key in seen:
                            stats['duplicates'] += 1
                        else:
                            seen.add(candidate.key)
                            stats['found'] += 1
                        continue
                    list_key = subscription_key(candidate)
                    list_ledger_key = (account.casefold(), "LIST", list_key) if list_key else None
                    prior_list = ledger.get(list_ledger_key) if list_ledger_key else None
                    emit("candidate", candidate)
                    if candidate.key in seen or prior_list in SUCCESS_STATUSES | UNCERTAIN_STATUSES:
                        stats['duplicates'] += 1
                        if prior_list:
                            emit("entry_status", (candidate, "Outcome unknown" if prior_list in UNCERTAIN_STATUSES else "Already submitted"))
                        continue
                    stats['found'] += 1
                    emit("log", f"UID {uid}: processing {candidate.sender_name} <{candidate.sender_email}>.")
                    outcomes: list[Result] = []

                    def report(kind: str, payload: Any) -> None:
                        if kind == "result":
                            outcomes.append(payload)
                            if list_ledger_key and payload.status in SUCCESS_STATUSES | UNCERTAIN_STATUSES:
                                # Save the outcome now. Stop may prevent another loop iteration.
                                ledger[list_ledger_key] = payload.status
                        emit(kind, payload)

                    try:
                        execute_candidate(candidate, account, password, guard, inbox.verification_message,
                                          attempted, ledger, report)
                    finally:
                        states = {result.status for result in outcomes}
                        # Another copy may pass DKIM, so don't rule it out after this one fails.
                        unverified_post = any(r.method == "POST" and r.status == "Manual action required" for r in outcomes)
                        if not unverified_post or states & (SUCCESS_STATUSES | UNCERTAIN_STATUSES):
                            seen.add(candidate.key)
                        if states & SUCCESS_STATUSES:
                            stats['accepted'] += 1
                        elif states & UNCERTAIN_STATUSES:
                            stats['unknown'] += 1
                        elif "Already submitted" in states:
                            stats['duplicates'] += 1
                        elif "Manual action required" in states:
                            stats['manual'] += 1
                        elif states:
                            stats['failed'] += 1
                finally:
                    emit("progress", ProgressUpdate(stats['checked'], len(ids),
                         f"Checked {stats['checked']:,} messages; {stats['found']:,} unsubscribe entries found."))
            emit("progress", ProgressUpdate(stats['checked'], len(ids), "Finishing scan and updating results..."))
            emit("log", "Finished. Accepted/submitted requests do not independently confirm removal." if automatic else
                 "Scan finished. Check the senders you want to unsubscribe from, then click Unsubscribe checked.")
    finally:
        emit("summary", stats.copy())
        emit("log", "Run summary: " + run_summary(stats))


def csv_text(value: Any) -> str:
    # Treat every cell as text, even with leading spaces or newlines.
    # CSV quoting alone doesn't stop spreadsheet formulas.
    text = str(value).replace("\x00", "")
    return "'" + text if text else ""


def export_results(path: str | Path, results: list[Result]) -> None:
    """Write a CSV snapshot without changing request outcomes.

    Confirm overwrites before calling. A failed write leaves the old file
    and in-memory results intact.
    """
    destination = Path(path).expanduser()
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8-sig", newline="",
                                         dir=destination.parent, prefix=".unsubscribe-", suffix=".tmp",
                                         delete=False) as stream:
            temp_path = Path(stream.name)
            writer = csv.writer(stream, quoting=csv.QUOTE_ALL)
            writer.writerow(CSV_COLUMNS)
            for result in results:
                c = result.candidate
                writer.writerow([csv_text(value) for value in (
                    result.timestamp, result.account, c.uid, c.list_id, c.sender_name,
                    c.sender_email, c.subject, result.method, result.status, result.detail, result.target,
                )])
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, destination)
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


SCAN_CHOICES = ("Entire inbox", "250", "500", "1000", "Custom")


def parse_scan_limit(choice: str, custom: str = "") -> int:
    """Parse the scan amount. Zero means the entire inbox."""
    if choice == "Entire inbox":
        return 0
    if choice in {"250", "500", "1000"}:
        return int(choice)
    if choice != "Custom":
        raise ValueError("Choose one of the available scan amounts.")
    value = custom.strip()
    if not re.fullmatch(r"(?:[0-9]+|[0-9]{1,3}(?:,[0-9]{3})+)", value) or len(value) > 20:
        raise ValueError("Enter a positive whole number, such as 1500 or 1,500.")
    amount = int(value.replace(",", ""))
    if not 1 <= amount <= 2_147_483_647:
        raise ValueError("Enter a number from 1 to 2,147,483,647. Choose Entire inbox to scan everything.")
    return amount


def scan_limit_label(limit: int) -> str:
    return "Entire inbox" if limit == 0 else f"Newest {limit:,} messages"


SORT_CHOICES = ("Sender", "Subject", "Latest email")
UTC_MIN = datetime.min.replace(tzinfo=timezone.utc)


def parse_sent_date(message: Any) -> datetime | None:
    """Parse the Date header, leaving missing or invalid dates unknown."""
    dates = message.get_all("Date", [])
    if len(dates) != 1:
        return None
    try:
        date = parsedate_to_datetime(str(dates[0]))
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        return date.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError, IndexError):
        return None


@dataclass(frozen=True)
class MessageInfo:
    uid: str
    sender_name: str
    sender_email: str
    subject: str
    sent_at: datetime | None

    @property
    def sender_key(self) -> str:
        # Don't group unrelated messages just because both lack a From address.
        identity = self.sender_email.casefold() or f"unknown:{self.uid}"
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()

    @property
    def latest_key(self) -> tuple[bool, datetime, int]:
        return (self.sent_at is not None, self.sent_at or UTC_MIN,
                int(self.uid) if self.uid.isdigit() else 0)


def parse_message_info(raw: bytes, uid: str) -> MessageInfo:
    message = BytesHeaderParser(policy=policy.compat32).parsebytes(raw)
    name, address = parseaddr(decode_mime_header(message.get("From")))
    return MessageInfo(uid, display_text(name or address or "Unknown sender"),
                       display_text(address), decode_mime_header(message.get("Subject")),
                       parse_sent_date(message))


def candidate_info(candidate: Candidate) -> MessageInfo:
    return MessageInfo(candidate.uid, candidate.sender_name, candidate.sender_email,
                       candidate.subject, candidate.sent_at)


def display_date(date: datetime | None) -> str:
    if date is None:
        return "Unknown"
    try:
        return date.astimezone().strftime("%Y-%m-%d %H:%M")
    except (OSError, OverflowError, ValueError):
        return date.strftime("%Y-%m-%d %H:%M UTC")


@dataclass
class SenderRow:
    latest: MessageInfo
    entries: dict[str, Candidate] = field(default_factory=dict)
    terms: set[str] = field(default_factory=set)
    groups: set[str] = field(default_factory=set)
    states: dict[str, str] = field(default_factory=dict)
    state_groups: dict[str, str] = field(default_factory=dict)
    group_states: dict[str, Counter[str]] = field(default_factory=dict)
    message_uids: set[str] = field(default_factory=set)
    _search_text: str = ""
    _search_dirty: bool = True

    @property
    def key(self) -> str:
        return self.latest.sender_key

    def add_message(self, info: MessageInfo) -> None:
        self.message_uids.add(info.uid)
        if info.latest_key > self.latest.latest_key:
            self.latest = info
        self.terms.update((info.sender_name.casefold(), info.sender_email.casefold(), info.subject.casefold()))
        self._search_dirty = True

    def add_candidate(self, candidate: Candidate) -> None:
        self.add_message(candidate_info(candidate))
        self.entries[f"{candidate.validity}:{candidate.uid}"] = candidate
        self.groups.add(subscription_key(candidate) or candidate.key)
        self.terms.add(candidate.list_id.casefold())
        self._search_dirty = True

    def matches(self, query: str) -> bool:
        if not query.strip():
            return True
        if self._search_dirty:
            self._search_text = "\n".join(self.terms)
            self._search_dirty = False
        return all(word in self._search_text for word in query.casefold().split())

    def set_status(self, candidate: Candidate, status: str) -> None:
        key = candidate.key
        self.state_groups[key] = subscription_key(candidate) or key
        self.set_entry_status(key, status)

    def set_entry_status(self, key: str, status: str) -> None:
        previous = self.states.get(key)
        if previous == status:
            return
        counts = self.group_states.setdefault(self.state_groups[key], Counter())
        if previous is not None:
            counts[previous] -= 1
            if not counts[previous]:
                del counts[previous]
        counts[status] += 1
        self.states[key] = status

    @property
    def list_count(self) -> int:
        return len(self.groups)


def sorted_sender_rows(rows: list[SenderRow], sort_by: str, descending: bool) -> list[SenderRow]:
    def text_key(row: SenderRow) -> tuple[str, str, str]:
        primary = row.latest.subject if sort_by == "Subject" else row.latest.sender_name
        return primary.casefold(), row.latest.sender_email.casefold(), row.key

    if sort_by != "Latest email":
        return sorted(rows, key=text_key, reverse=descending)
    dated = [row for row in rows if row.latest.sent_at is not None]
    unknown = [row for row in rows if row.latest.sent_at is None]
    # Break ties consistently and keep unknown dates last.
    dated.sort(key=lambda row: (row.latest.sender_name.casefold(), row.key))
    dated.sort(key=lambda row: row.latest.sent_at, reverse=descending)
    return dated + sorted(unknown, key=text_key)


class UnsubscribeApp:
    def __init__(self, root: tk.Tk, *, administrator: bool = False) -> None:
        self.root = root
        self.administrator = administrator
        self.root.title("Gmail Unsubscriber - Live Progress" + (" - Administrator" if administrator else ""))
        width = min(1180, max(760, self.root.winfo_screenwidth() - 80))
        height = min(850, max(620, self.root.winfo_screenheight() - 90))
        self.root.geometry(f"{width}x{height}+{max(0, (self.root.winfo_screenwidth() - width) // 2)}+30")
        self.root.minsize(min(880, width), min(650, height))
        self.root.option_add("*Font", ("Segoe UI", 10) if sys.platform == "win32" else ("DejaVu Sans", 10))
        style = ttk.Style(self.root)
        if sys.platform == "win32" and "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Treeview", rowheight=28)
        style.configure("TButton", padding=(8, 4))
        self.events = UiEventQueue()
        self._progress: ProgressUpdate | None = None
        self._activity = ""
        self._task_started = 0.0
        self._activity_started = 0.0
        self.worker: threading.Thread | None = None
        self.guard = NetworkGuard()
        self.is_running = False
        self.closing = False
        self.destroyed = False
        self.done_received = False
        self._poll_id: str | None = None
        self._refresh_id: str | None = None
        self._auto_export_path: str | None = None
        self._batch_start_count = 0
        self.active_task = ""
        self.task_had_error = False
        self.last_summary: dict[str, int] | None = None
        self.scan_account = ""
        self.candidates: dict[str, Candidate] = {}
        self.senders: dict[str, SenderRow] = {}
        self.checked_senders: set[str] = set()
        self.visible_keys: tuple[str, ...] = ()
        self._all_tree_keys: set[str] = set()
        self._dirty_rows: set[str] = set()
        self.results: list[Result] = []
        self.row_results: dict[str, list[Result]] = {}
        self.entry_statuses: dict[str, str] = {}
        self.ledger: dict[tuple[str, str, str], str] = {}
        self.last_export_count = 0
        self._last_sort = "Latest email"
        self.build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._poll_id = self.root.after(80, self._poll_events)

    def build_ui(self) -> None:
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill=tk.BOTH, expand=True)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(4, weight=1)
        header = ttk.Frame(main)
        header.grid(row=0, column=0, sticky=tk.EW, pady=(0, 7))
        ttk.Label(header, text="Gmail Unsubscriber", font=("Segoe UI", 17, "bold")).pack(side=tk.LEFT)
        ttk.Label(header, text="Administrator mode" if self.administrator else "Standard mode").pack(side=tk.RIGHT)

        credentials = ttk.LabelFrame(main, text="Account", padding=9)
        credentials.grid(row=1, column=0, sticky=tk.EW, pady=(0, 7))
        credentials.columnconfigure(1, weight=1)
        self.email_var = tk.StringVar()
        self.pass_var = tk.StringVar()
        self.show_pass_var = tk.BooleanVar(value=False)
        ttk.Label(credentials, text="Gmail address:").grid(row=0, column=0, sticky=tk.W, pady=3)
        self.email_entry = ttk.Entry(credentials, textvariable=self.email_var)
        self.email_entry.grid(row=0, column=1, sticky=tk.EW, padx=10)
        ttk.Label(credentials, text="App password:").grid(row=1, column=0, sticky=tk.W, pady=3)
        self.pass_entry = ttk.Entry(credentials, textvariable=self.pass_var, show="*")
        self.pass_entry.grid(row=1, column=1, sticky=tk.EW, padx=10)
        account_actions = ttk.Frame(credentials)
        account_actions.grid(row=1, column=2, sticky=tk.E)
        self.show_pass_cb = ttk.Checkbutton(account_actions, text="Show", variable=self.show_pass_var,
            command=lambda: self.pass_entry.configure(show="" if self.show_pass_var.get() else "*"))
        self.show_pass_cb.pack(side=tk.LEFT, padx=(0, 7))
        ttk.Button(credentials, text="Google app passwords", command=lambda: webbrowser.open(
            "https://myaccount.google.com/apppasswords")).grid(row=0, column=2)
        self.connection_btn = ttk.Button(account_actions, text="Test connection", command=self.start_connection_test)
        self.connection_btn.pack(side=tk.LEFT)

        options = ttk.LabelFrame(main, text="Scan settings", padding=9)
        options.grid(row=2, column=0, sticky=tk.EW, pady=(0, 7))
        options.columnconfigure(1, weight=1)
        ttk.Label(options, text="Scan amount:").grid(row=0, column=0, sticky=tk.W)
        amounts = ttk.Frame(options)
        amounts.grid(row=0, column=1, columnspan=2, sticky=tk.W, padx=(10, 0))
        self.scan_choice_var = tk.StringVar(value="1,000")
        self.custom_limit_var = tk.StringVar(value="2500")
        self.scan_amount = ttk.Combobox(amounts, textvariable=self.scan_choice_var,
            values=("250", "500", "1,000", "Custom", "Entire inbox"), state="readonly", width=15)
        self.scan_amount.pack(side=tk.LEFT)
        self.custom_frame = ttk.Frame(amounts)
        self.custom_entry = ttk.Entry(self.custom_frame, textvariable=self.custom_limit_var, width=12)
        self.custom_entry.pack(side=tk.LEFT, padx=(10, 5))
        ttk.Label(self.custom_frame, text="messages").pack(side=tk.LEFT)
        ttk.Label(amounts, text="  Newest messages first").pack(side=tk.RIGHT)
        self.auto_var = tk.BooleanVar(value=False)
        self.auto_cb = ttk.Checkbutton(options, text="Auto unsubscribe while scanning", variable=self.auto_var)
        self.auto_cb.grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=(7, 2))
        self.mode_hint = ttk.Label(options, text="", wraplength=1040)
        self.mode_hint.grid(row=2, column=0, columnspan=3, sticky=tk.W, pady=(0, 6))
        export_row = ttk.Frame(options)
        export_row.grid(row=3, column=0, columnspan=3, sticky=tk.EW)
        export_row.columnconfigure(1, weight=1)
        self.save_csv_var = tk.BooleanVar(value=False)
        self.save_cb = ttk.Checkbutton(export_row, text="Export outcomes to CSV", variable=self.save_csv_var,
                                       command=self.update_controls)
        self.save_cb.grid(row=0, column=0, sticky=tk.W)
        desktop = Path.home() / "Desktop"
        self.file_path_var = tk.StringVar(value=str((desktop if desktop.is_dir() else Path.home()) / "unsubscribe_results.csv"))
        self.file_entry = ttk.Entry(export_row, textvariable=self.file_path_var)
        self.file_entry.grid(row=0, column=1, sticky=tk.EW, padx=9)
        self.browse_btn = ttk.Button(export_row, text="Browse...", command=self.browse_file)
        self.browse_btn.grid(row=0, column=2)

        controls = ttk.Frame(main)
        controls.grid(row=3, column=0, sticky=tk.EW, pady=(0, 7))
        self.start_btn = ttk.Button(controls, text="Scan inbox", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT)
        self.action_btn = ttk.Button(controls, text="Unsubscribe checked (0)", command=self.start_selected)
        self.action_btn.pack(side=tk.LEFT, padx=6)
        self.stop_btn = ttk.Button(controls, text="Stop", command=self.stop_process)
        self.stop_btn.pack(side=tk.LEFT)
        self.export_btn = ttk.Button(controls, text="Export results...", command=self.manual_export)
        self.export_btn.pack(side=tk.RIGHT)

        self.workspace = ttk.Notebook(main)
        self.workspace.grid(row=4, column=0, sticky=tk.NSEW)
        self.results_tab = ttk.Frame(self.workspace, padding=7)
        self.details_tab = ttk.Frame(self.workspace, padding=7)
        self.log_tab = ttk.Frame(self.workspace, padding=7)
        self.workspace.add(self.results_tab, text="Senders")
        self.workspace.add(self.details_tab, text="Entry details")
        self.workspace.add(self.log_tab, text="Activity log")
        self.results_tab.columnconfigure(0, weight=1)
        self.results_tab.rowconfigure(1, weight=1)

        filters = ttk.Frame(self.results_tab)
        filters.grid(row=0, column=0, sticky=tk.EW, pady=(0, 6))
        filters.columnconfigure(1, weight=1)
        ttk.Label(filters, text="Search:").grid(row=0, column=0)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(filters, textvariable=self.search_var)
        self.search_entry.grid(row=0, column=1, sticky=tk.EW, padx=(6, 4))
        ttk.Button(filters, text="Clear", command=lambda: self.search_var.set("")).grid(row=0, column=2)
        ttk.Label(filters, text="Sort by:").grid(row=0, column=3, padx=(12, 5))
        self.sort_var = tk.StringVar(value="Latest email")
        self.sort_combo = ttk.Combobox(filters, textvariable=self.sort_var, values=SORT_CHOICES,
                                       state="readonly", width=13)
        self.sort_combo.grid(row=0, column=4)
        self.descending_var = tk.BooleanVar(value=True)
        self.sort_direction_btn = ttk.Button(filters, text="Newest first", width=12, command=self.reverse_sort)
        self.sort_direction_btn.grid(row=0, column=5, padx=(5, 0))
        table = ttk.Frame(self.results_tab)
        table.grid(row=1, column=0, sticky=tk.NSEW)
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(table, columns=("checked", "sender", "subject", "date", "lists", "status"),
                                 show="headings", selectmode="browse", height=7)
        for name, title, width, minimum in (
            ("checked", "Select", 56, 56), ("sender", "Sender", 245, 175),
            ("subject", "Latest subject", 305, 180), ("date", "Latest email", 158, 150),
            ("lists", "Lists", 50, 45), ("status", "Outcome", 195, 175)):
            self.tree.heading(name, text=title)
            self.tree.column(name, width=width, minwidth=minimum,
                             stretch=name in {"sender", "subject", "status"},
                             anchor=tk.CENTER if name in {"checked", "lists"} else tk.W)
        self.tree.heading("checked", command=self.toggle_visible)
        for column, sort in (("sender", "Sender"), ("subject", "Subject"), ("date", "Latest email")):
            self.tree.heading(column, command=lambda by=sort: self.sort_by_heading(by))
        self.tree.grid(row=0, column=0, sticky=tk.NSEW)
        vertical = ttk.Scrollbar(table, orient=tk.VERTICAL, command=self.tree.yview)
        vertical.grid(row=0, column=1, sticky=tk.NS)
        horizontal = ttk.Scrollbar(table, orient=tk.HORIZONTAL, command=self.tree.xview)
        horizontal.grid(row=1, column=0, sticky=tk.EW)
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.tree.bind("<<TreeviewSelect>>", self.show_details)
        self.tree.bind("<Button-1>", self._on_tree_click)
        self.tree.bind("<Double-1>", self._on_tree_double_click)
        self.tree.bind("<space>", self._on_tree_space)
        toolbar = ttk.Frame(self.results_tab)
        toolbar.grid(row=2, column=0, sticky=tk.EW, pady=(5, 0))
        toolbar.columnconfigure(3, weight=1)
        self.check_visible_btn = ttk.Button(toolbar, text="Check shown", command=self.check_visible)
        self.check_visible_btn.grid(row=0, column=0)
        self.clear_checks_btn = ttk.Button(toolbar, text="Clear checks", command=self.clear_checks)
        self.clear_checks_btn.grid(row=0, column=1, padx=5)
        self.details_btn = ttk.Button(toolbar, text="View details", command=lambda: self.workspace.select(self.details_tab))
        self.details_btn.grid(row=0, column=2)
        self.review_count_var = tk.StringVar(value="No senders found yet.")
        self.count_label = ttk.Label(toolbar, textvariable=self.review_count_var, wraplength=700)
        self.count_label.grid(row=0, column=3, sticky=tk.E, padx=(8, 0))
        self.copy_btn = ttk.Button(self.details_tab, text="Copy first web link", command=self.copy_web_link)
        self.copy_btn.pack(anchor=tk.W, pady=(0, 6))
        self.details = scrolledtext.ScrolledText(self.details_tab, state=tk.DISABLED, wrap=tk.WORD,
                                                font=("Consolas", 10), height=6)
        self.details.pack(fill=tk.BOTH, expand=True)
        self.log_box = scrolledtext.ScrolledText(self.log_tab, state=tk.DISABLED, wrap=tk.WORD,
                                                font=("Consolas", 10), height=6)
        self.log_box.pack(fill=tk.BOTH, expand=True)
        footer = ttk.Frame(main)
        footer.grid(row=5, column=0, sticky=tk.EW, pady=(7, 0))
        progress_row = ttk.Frame(footer)
        progress_row.pack(fill=tk.X)
        self.progress_bar = ttk.Progressbar(progress_row, mode="determinate", maximum=100, value=0)
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.progress_text_var = tk.StringVar(value="Ready")
        self.progress_label = ttk.Label(progress_row, textvariable=self.progress_text_var)
        self.progress_label.pack(side=tk.RIGHT, padx=(10, 0))
        self.status_var = tk.StringVar(value="Ready. Set the amount, then scan. Auto unsubscribe is off.")
        self.status_label = ttk.Label(footer, textvariable=self.status_var, wraplength=1090)
        self.status_label.pack(fill=tk.X, pady=(5, 0))
        self.root.bind("<Configure>", self._resize_status, add="+")
        self.search_var.trace_add("write", lambda *_: self.schedule_refresh())
        self.scan_choice_var.trace_add("write", lambda *_: self._amount_changed())
        self.auto_var.trace_add("write", lambda *_: self._mode_changed())
        self.sort_var.trace_add("write", lambda *_: self._sort_changed())
        self._amount_changed()
        self._mode_changed()
        self.show_details()

    def _resize_status(self, event: Any) -> None:
        if event.widget is self.root:
            self.status_label.configure(wraplength=max(400, event.width - 35))
            self.mode_hint.configure(wraplength=max(400, event.width - 65))
            self.count_label.configure(wraplength=max(280, event.width - 405))

    def _amount_changed(self) -> None:
        if self.scan_choice_var.get() == "Custom":
            self.custom_frame.pack(side=tk.LEFT)
        else:
            self.custom_frame.pack_forget()
        self.update_controls()

    def current_scan_limit(self) -> int:
        choice = self.scan_choice_var.get()
        return parse_scan_limit("1000" if choice == "1,000" else choice, self.custom_limit_var.get())

    def _mode_changed(self) -> None:
        auto = self.auto_var.get()
        if auto:
            self.checked_senders.clear()
        self.mode_hint.configure(text=(
            "On: Start sends requests as lists are found, including unsubscribe emails. No per-sender approval." if auto else
            "Off: scan only. Check senders below, then click Unsubscribe checked."))
        self.start_btn.configure(text="Scan + auto unsubscribe" if auto else "Scan inbox")
        self._dirty_rows.update(self.senders)
        self.schedule_refresh()
        self.update_controls()

    def _sort_changed(self) -> None:
        if self.sort_var.get() != self._last_sort:
            self._last_sort = self.sort_var.get()
            self.descending_var.set(self._last_sort == "Latest email")
        self._sort_label()
        self.schedule_refresh()

    def _sort_label(self) -> None:
        if self.sort_var.get() == "Latest email":
            text = "Newest first" if self.descending_var.get() else "Oldest first"
        else:
            text = "Z to A" if self.descending_var.get() else "A to Z"
        self.sort_direction_btn.configure(text=text)

    def reverse_sort(self) -> None:
        self.descending_var.set(not self.descending_var.get())
        self._sort_label()
        self.schedule_refresh()

    def sort_by_heading(self, sort_by: str) -> None:
        if sort_by == self.sort_var.get():
            self.reverse_sort()
        else:
            self.sort_var.set(sort_by)

    def _can_check(self) -> bool:
        # Allow checking rows during a scan, but wait until it stops before sending.
        return (not self.closing and not self.auto_var.get()
                and (not self.is_running or self.active_task == "scan"))

    def update_controls(self) -> None:
        idle = not self.is_running and not self.closing
        state = tk.NORMAL if idle else tk.DISABLED
        for widget in (self.email_entry, self.pass_entry, self.show_pass_cb, self.auto_cb, self.save_cb,
                       self.start_btn, self.connection_btn):
            widget.configure(state=state)
        self.scan_amount.configure(state="readonly" if idle else tk.DISABLED)
        self.custom_entry.configure(state=tk.NORMAL if idle and self.scan_choice_var.get() == "Custom" else tk.DISABLED)
        self.action_btn.configure(text=f"Unsubscribe checked ({len(self.checked_senders):,})",
            state=tk.NORMAL if idle and self.checked_senders and not self.auto_var.get() else tk.DISABLED)
        self.export_btn.configure(state=tk.NORMAL if idle and self.results else tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL if self.is_running and not self.guard.stop_event.is_set() else tk.DISABLED)
        export_state = tk.NORMAL if idle and self.save_csv_var.get() else tk.DISABLED
        self.file_entry.configure(state=export_state)
        self.browse_btn.configure(state=export_state)
        self.check_visible_btn.configure(state=tk.NORMAL if self._can_check() and self.visible_keys else tk.DISABLED)
        self.clear_checks_btn.configure(state=tk.NORMAL if self._can_check() and self.checked_senders else tk.DISABLED)
        focused = self.tree.selection()
        self.details_btn.configure(state=tk.NORMAL if focused else tk.DISABLED)
        self.copy_btn.configure(state=tk.NORMAL if focused else tk.DISABLED)
        total = len(self._all_tree_keys)
        hidden = len(self.checked_senders.difference(self.visible_keys))
        text = f"{len(self.visible_keys):,} of {total:,} senders shown | {len(self.checked_senders):,} checked"
        if hidden:
            text += f" ({hidden:,} hidden by search)"
        self.review_count_var.set(text)

    def _sender_for(self, info: MessageInfo) -> SenderRow:
        row = self.senders.get(info.sender_key)
        if row is None:
            row = self.senders[info.sender_key] = SenderRow(info)
        row.add_message(info)
        if row.entries:
            self._dirty_rows.add(row.key)
        return row

    def _add_candidate(self, candidate: Candidate) -> None:
        previous = self.candidates.get(candidate.key)
        if previous is None or candidate_info(candidate).latest_key > candidate_info(previous).latest_key:
            self.candidates[candidate.key] = candidate
        row = self._sender_for(candidate_info(candidate))
        row.add_candidate(candidate)
        row.set_status(candidate, self._entry_status(candidate))
        self._dirty_rows.add(row.key)

    def _entry_status(self, candidate: Candidate) -> str:
        results = self.row_results.get(candidate.key, ())
        if results:
            priorities = {"Request accepted": 9, "Email submitted": 9, "Partial email submission": 8,
                "Outcome unknown": 8, "Already submitted": 7, "Manual action required": 5,
                "Failed": 4, "Blocked": 3, "Skipped this run": 2}
            return max(results, key=lambda r: priorities.get(r.status, 0)).status
        if candidate.key in self.entry_statuses:
            return self.entry_statuses[candidate.key]
        methods = {target.method for target in candidate.targets}
        if not methods.intersection({"POST", "MAILTO"}):
            return "Manual action required" if "MANUAL" in methods else "Blocked"
        return "Processing" if self.active_task == "auto" and self.is_running else "Not submitted"

    def _sender_status(self, row: SenderRow) -> str:
        summary: set[str] = set()
        for counts in row.group_states.values():
            states = set(counts)
            successful = states.intersection(SUCCESS_STATUSES | {"Already submitted"})
            if successful:
                summary.add(next(iter(successful)) if len(successful) == 1 else "Submitted")
            elif states.intersection(UNCERTAIN_STATUSES):
                summary.add("Outcome unknown")
            elif "Not submitted" in states or "Processing" in states:
                summary.add("Processing" if "Processing" in states else "Not submitted")
            elif len(states) == 1:
                summary.update(states)
            else:
                summary.add("Needs attention")
        if len(summary) == 1:
            return next(iter(summary))
        if summary and summary.issubset(SUCCESS_STATUSES | {"Already submitted", "Submitted"}):
            return "Submitted"
        return "Mixed outcomes; see details"

    def schedule_refresh(self) -> None:
        if self.destroyed or self._refresh_id is not None:
            return
        # Group rapid updates into one refresh. Filtering stays local.
        self._refresh_id = self.root.after(100, lambda: self._refresh_results(budgeted=True))

    def _refresh_results(self, *, budgeted: bool = False) -> None:
        if self._refresh_id is not None:
            self.root.after_cancel(self._refresh_id)
            self._refresh_id = None
        if self.destroyed:
            return
        deadline = time.monotonic() + 0.015 if budgeted else float("inf")
        for key in tuple(self._dirty_rows):
            self._dirty_rows.discard(key)
            row = self.senders.get(key)
            if row is None or not row.entries:
                continue
            info = row.latest
            name = f"{info.sender_name} <{info.sender_email}>" if info.sender_name != info.sender_email else info.sender_email
            checkbox = "" if self.auto_var.get() else "☑" if key in self.checked_senders else "☐"
            values = (checkbox, name, info.subject, display_date(info.sent_at), row.list_count, self._sender_status(row))
            if self.tree.exists(key):
                self.tree.item(key, values=values)
            else:
                self.tree.insert("", tk.END, iid=key, values=values)
                self._all_tree_keys.add(key)
            if time.monotonic() >= deadline:
                break
        query = self.search_var.get()
        rows = [self.senders[key] for key in self._all_tree_keys if self.senders[key].matches(query)]
        ordered = sorted_sender_rows(rows, self.sort_var.get(), self.descending_var.get())
        self.visible_keys = tuple(row.key for row in ordered)
        # Keep row IDs and checkbox state when sorting or hiding rows.
        self.tree.set_children("", *self.visible_keys)
        self.update_controls()
        if self._dirty_rows:
            self.schedule_refresh()

    def toggle_checked(self, key: str) -> None:
        if not self._can_check() or key not in self.senders or not self.senders[key].entries:
            return
        if key in self.checked_senders:
            self.checked_senders.remove(key)
        else:
            self.checked_senders.add(key)
        self._dirty_rows.add(key)
        self._refresh_results()

    def check_visible(self) -> None:
        if not self._can_check():
            return
        self._refresh_results()
        self.checked_senders.update(self.visible_keys)
        self._dirty_rows.update(self.visible_keys)
        self._refresh_results()

    def clear_checks(self) -> None:
        if not self._can_check():
            return
        self._dirty_rows.update(self.checked_senders)
        self.checked_senders.clear()
        self._refresh_results()

    def toggle_visible(self) -> None:
        if not self._can_check():
            return
        self._refresh_results()
        if self.visible_keys and set(self.visible_keys).issubset(self.checked_senders):
            self.checked_senders.difference_update(self.visible_keys)
            self._dirty_rows.update(self.visible_keys)
            self._refresh_results()
        else:
            self.check_visible()

    def _on_tree_click(self, event: Any) -> str | None:
        key = self.tree.identify_row(event.y)
        if key and self.tree.identify_column(event.x) == "#1":
            self.tree.focus(key)
            self.tree.selection_set(key)
            self.toggle_checked(key)
            return "break"
        return None

    def _on_tree_double_click(self, event: Any) -> str | None:
        if self.tree.identify_column(event.x) == "#1":
            return "break"
        if self.tree.identify_row(event.y):
            self.workspace.select(self.details_tab)
        return None

    def _on_tree_space(self, _event: Any) -> str:
        for key in self.tree.selection():
            self.toggle_checked(key)
        return "break"

    def log(self, message: str) -> None:
        self.log_box.configure(state=tk.NORMAL)
        self.log_box.insert(tk.END, display_text(message) + "\n")
        if int(self.log_box.index("end-1c").split(".")[0]) > 1500:
            self.log_box.delete("1.0", "251.0")
        self.log_box.see(tk.END)
        self.log_box.configure(state=tk.DISABLED)

    def browse_file(self) -> None:
        path = filedialog.asksaveasfilename(parent=self.root, title="Save unsubscribe results",
            defaultextension=".csv", initialfile="unsubscribe_results.csv", filetypes=[("CSV files", "*.csv")])
        if path:
            self.file_path_var.set(path)

    def credentials(self) -> tuple[str, str] | None:
        try:
            account = validate_address(self.email_var.get().strip())
            password = "".join(self.pass_var.get().split())
            if not password:
                raise SafetyError("Enter your Google app password, not your normal account password.")
            import dns.resolver
            return account, password
        except ImportError:
            messagebox.showerror("Missing dependency", "Install the libraries first:\n\npython -m pip install -r requirements.txt", parent=self.root)
        except SafetyError as exc:
            messagebox.showwarning("Account details", str(exc), parent=self.root)
        return None

    def _prepare_export(self) -> tuple[bool, str | None]:
        if not self.save_csv_var.get():
            return True, None
        path = self.file_path_var.get().strip()
        if not path or not Path(path).expanduser().parent.is_dir():
            messagebox.showwarning("CSV location", "Choose a filename in an existing folder.", parent=self.root)
            return False, None
        if Path(path).expanduser().exists() and not messagebox.askyesno(
            "Replace CSV?", "Replace the existing CSV with this app session's outcomes after processing?",
            parent=self.root, default=messagebox.NO):
            return False, None
        return True, path

    def start_connection_test(self) -> None:
        if self.is_running or self.closing:
            return
        self.active_task = "connection_test"
        self._auto_export_path = None
        self.workspace.select(self.log_tab)
        self.status_var.set("Testing Gmail connections. No account details are needed...")
        self._start_worker(test_gmail_connection, (), "")

    def start_scan(self) -> None:
        if self.is_running or self.closing:
            return
        try:
            limit = self.current_scan_limit()
        except ValueError as exc:
            messagebox.showwarning("Scan amount", str(exc), parent=self.root)
            return
        credentials = self.credentials()
        if not credentials:
            return
        automatic = bool(self.auto_var.get())
        if limit == 0:
            detail = ("Auto unsubscribe is ON. Supported lists will receive requests as they are found, "
                      "including emails from your account. Sent requests cannot be recalled." if automatic else
                      "Auto unsubscribe is OFF. No unsubscribe requests will be sent during this scan.")
            if not messagebox.askyesno("Scan entire inbox?",
                "Scan every message currently in INBOX?\n\nThis can take longer than a limited scan. "
                "Archived mail, Spam, and Trash are not included.\n\n" + detail,
                parent=self.root, default=messagebox.NO):
                return
        allowed, export_path = self._prepare_export() if automatic else (True, None)
        if not allowed:
            return
        self.active_task = "auto" if automatic else "scan"
        self.scan_account = credentials[0]
        self.candidates.clear()
        self.senders.clear()
        self.checked_senders.clear()
        self.row_results.clear()
        self.entry_statuses.clear()
        self._dirty_rows.clear()
        self.visible_keys = ()
        # Also remove hidden rows left over from the last scan.
        for key in self._all_tree_keys:
            if self.tree.exists(key):
                self.tree.delete(key)
        self._all_tree_keys.clear()
        self._auto_export_path = export_path
        self._batch_start_count = len(self.results)
        self.last_summary = None
        self.search_var.set("")
        self.workspace.select(self.results_tab)
        self.status_var.set("Connecting. Requests will be sent as lists are found..." if automatic else
                            "Connecting. Scanning only; no unsubscribe requests will be sent...")

        def job(account: str, password: str, amount: int,
                *, guard: NetworkGuard, emit: Callable[[str, Any], None]) -> None:
            scan_and_unsubscribe(account, password, amount, guard, self.ledger, emit, automatic=automatic)

        self._start_worker(job, (*credentials, limit), credentials[1])

    def start_selected(self) -> None:
        if self.is_running or self.closing or self.auto_var.get() or not self.checked_senders:
            return
        credentials = self.credentials()
        if not credentials:
            return
        if credentials[0].casefold() != self.scan_account.casefold():
            messagebox.showwarning("Account changed", "Scan this account before sending requests. These results belong to a different account.", parent=self.root)
            return
        self._refresh_results()
        rows = [self.senders[key] for key in sorted(self.checked_senders) if key in self.senders and self.senders[key].entries]
        candidates = tuple(sorted((c for row in rows for c in row.entries.values()),
                                  key=lambda c: int(c.uid), reverse=True))
        if not candidates:
            return
        hidden = len(self.checked_senders.difference(self.visible_keys))
        notice = f"Send unsubscribe requests for {len(rows):,} checked senders?\n\n"
        notice += "All distinct mailing lists found for these senders are included. Requests may send email from your account."
        if hidden:
            notice += f"\n\n{hidden:,} checked senders are hidden by the current search and WILL be included."
        if not messagebox.askyesno("Unsubscribe checked senders?", notice, parent=self.root, default=messagebox.NO):
            return
        allowed, export_path = self._prepare_export()
        if not allowed:
            return
        self.active_task = "selected"
        self._auto_export_path = export_path
        self._batch_start_count = len(self.results)
        self.workspace.select(self.results_tab)
        self.status_var.set(f"Processing {len(rows):,} checked senders...")

        def job(account: str, password: str, selected: tuple[Candidate, ...],
                *, guard: NetworkGuard, emit: Callable[[str, Any], None]) -> None:
            process_selected(selected, account, password, guard, self.ledger, emit)

        self._start_worker(job, (*credentials, candidates), credentials[1])

    def stop_process(self) -> None:
        if self.is_running:
            self.guard.cancel()
            self.status_var.set("Stopping active operations. Sent requests may still complete.")
            self.update_controls()

    def _record_result(self, result: Result) -> None:
        self.results.append(result)
        self.row_results.setdefault(result.candidate.key, []).append(result)
        sender_key = candidate_info(result.candidate).sender_key
        row = self.senders.get(sender_key)
        if row is not None:
            row.set_status(result.candidate, self._entry_status(result.candidate))
        self._dirty_rows.add(sender_key)
        self.log(f"{result.candidate.sender_name}: {result.status} [{result.method}]. {result.detail}")

    def _consume_progress(self) -> None:
        progress, activity = self.events.take_progress()
        if progress is not None:
            self._progress = progress
            if progress.total is not None:
                if str(self.progress_bar.cget("mode")) != "determinate":
                    self.progress_bar.stop()
                self.progress_bar.configure(mode="determinate", maximum=max(1, progress.total),
                    value=min(max(0, progress.completed), progress.total))
        if activity is not None and activity != self._activity:
            self._activity = display_text(activity)
            self._activity_started = time.monotonic()

    def _render_progress(self) -> None:
        if not self.is_running or self.closing or self.task_had_error:
            return
        progress = self._progress
        stopping = self.guard.stop_event.is_set()
        if progress is not None and progress.total is not None:
            total, completed = progress.total, min(progress.completed, progress.total)
            percent = (1000 * completed // total) / 10 if total else 0
            label = f"{completed:,} / {total:,} {progress.unit} ({percent:.1f}%)"
            if completed == total:
                label = "Finalizing | " + label
            if stopping:
                label = "Stopping | " + label
        else:
            label = "Stopping..." if stopping else "Connecting..."
        self.progress_text_var.set(label)
        now = time.monotonic()
        activity = "Stopping active operations. Sent requests may still complete." if stopping else self._activity
        status = f"{activity} | Elapsed {elapsed_text(now - self._task_started)}"
        if not stopping and now - self._activity_started >= 2:
            status += f" | Current step {elapsed_text(now - self._activity_started)}"
        if status != self.status_var.get():
            self.status_var.set(status)

    def _finish_progress(self, label: str) -> None:
        self.progress_bar.stop()
        progress = self._progress
        known = progress is not None and progress.total is not None
        total = progress.total if known else 0
        completed = min(progress.completed, total) if known else 0
        if label == "Complete":
            completed = total
        self.progress_bar.configure(mode="determinate", maximum=max(1, total),
            value=max(1, total) if label == "Complete" else completed)
        if known:
            percent = (1000 * completed // total) / 10 if total else (100 if label == "Complete" else 0)
            detail = f" | {completed:,} / {total:,} {progress.unit} ({percent:g}%)"
        else:
            detail = ""
        self.progress_text_var.set(label + detail)

    def _poll_events(self) -> None:
        if self._poll_id is not None:
            self.root.after_cancel(self._poll_id)
            self._poll_id = None
        self._consume_progress()
        changed = False
        # Limit each pass so a large inbox doesn't freeze the window.
        deadline = time.monotonic() + 0.025
        for _ in range(200):
            try:
                kind, payload = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "message":
                self._sender_for(payload)
                changed = True
            elif kind == "candidate":
                self._add_candidate(payload)
                changed = True
            elif kind == "entry_status":
                candidate, status = payload
                self.entry_statuses[candidate.key] = status
                sender_key = candidate_info(candidate).sender_key
                if sender_key in self.senders:
                    self.senders[sender_key].set_status(candidate, self._entry_status(candidate))
                self._dirty_rows.add(sender_key)
                changed = True
            elif kind == "summary":
                self.last_summary = payload
            elif kind == "result":
                self._record_result(payload)
                changed = True
            elif kind == "log":
                self.log(payload)
            elif kind == "connection_report" and not self.closing:
                messagebox.showinfo("Gmail connection test", payload, parent=self.root)
            elif kind == "error":
                self.task_had_error = True
                self._finish_progress("Error")
                self.status_var.set("Error. " + display_text(payload))
                self.log(payload)
                if not self.closing:
                    messagebox.showerror("Operation stopped", payload, parent=self.root)
            elif kind == "done":
                self.done_received = True
            if time.monotonic() >= deadline:
                break
        self._consume_progress()
        self._render_progress()
        if changed and self._dirty_rows:
            self.schedule_refresh()
        if self.done_received and self.worker is not None and not self.worker.is_alive():
            self.worker.join()
            self.worker = None
            self.done_received = False
            self.is_running = False
            self.progress_bar.stop()
            if self._auto_export_path and len(self.results) > self._batch_start_count:
                self._save_export(self._auto_export_path)
            self._auto_export_path = None
            if self.closing:
                self._destroy()
                return
            stopped = self.guard.stop_event.is_set()
            label = "Error" if self.task_had_error else "Stopped" if stopped else "Complete"
            self._finish_progress(label)
            if self.active_task in {"auto", "scan"}:
                detail = run_summary(self.last_summary) if self.last_summary else f"{len(self.candidates):,} entries found."
                self.status_var.set(f"{label}. {detail}")
            elif self.active_task == "connection_test":
                self.status_var.set(f"{label}. Connection test finished. See the Activity log; no login was attempted.")
            else:
                self.status_var.set(f"{label}. {len(self.results) - self._batch_start_count:,} method outcomes recorded. See results for each sender.")
            self.status_var.set(self.status_var.get() + f" Elapsed {elapsed_text(time.monotonic() - self._task_started)}.")
            self.active_task = ""
            for row in self.senders.values():
                for key, status in tuple(row.states.items()):
                    if status == "Processing":
                        row.set_entry_status(key, "Not submitted")
            self._dirty_rows.update(self.senders)
            self._refresh_results()
            self.show_details()
        if not self.destroyed:
            self.update_controls()
            self._poll_id = self.root.after(10 if not self.events.empty() else 80, self._poll_events)

    def show_details(self, _event: Any = None) -> None:
        selected = self.tree.selection()
        text = "Select a sender to inspect its mailing lists and recorded outcomes. A highlighted row is not a checked box."
        if len(selected) == 1 and selected[0] in self.senders:
            row = self.senders[selected[0]]
            info = row.latest
            lines = [f"Sender: {info.sender_name} <{info.sender_email}>", f"Latest scanned subject: {info.subject}",
                     f"Latest sent date: {display_date(info.sent_at)} (your local time)",
                     "Date header (UTC): " + (info.sent_at.isoformat() if info.sent_at else "Unknown"),
                     f"{len(row.message_uids):,} scanned messages; {row.list_count:,} distinct list/target groups.",
                     "Checking this sender includes all its discovered mailing lists.", ""]
            seen = set()
            for c in sorted(row.entries.values(), key=lambda c: int(c.uid), reverse=True):
                if c.key in seen:
                    continue
                if len(seen) >= 200:
                    lines.append("Showing the newest 200 distinct target sets. All discovered lists are still included when this sender is checked.")
                    break
                seen.add(c.key)
                lines.extend([f"Subject: {c.subject}", f"List-ID: {c.list_id or '(not provided)'}",
                              f"UID: {c.uid} | Sent: {display_date(c.sent_at)}", f"Outcome: {self._entry_status(c)}"])
                for target in c.targets:
                    lines.extend([f"{target.method}: {target.uri}", f"  {target.note}"])
                    if target.method == "MAILTO":
                        parsed = parse_mailto(target.uri)
                        lines.extend([f"  Recipients: {', '.join(parsed.recipients)}", f"  Subject: {display_text(parsed.subject)}",
                                      "  Body:", parsed.body])
                for result in self.row_results.get(c.key, ()):
                    lines.append(f"{result.timestamp}: {result.status} [{result.method}] - {result.detail}")
                lines.append("")
            text = "\n".join(lines)
        self.details.configure(state=tk.NORMAL)
        self.details.delete("1.0", tk.END)
        self.details.insert("1.0", text)
        self.details.configure(state=tk.DISABLED)
        self.update_controls()

    def copy_web_link(self) -> None:
        selected = self.tree.selection()
        if len(selected) != 1 or selected[0] not in self.senders:
            messagebox.showinfo("Select a sender", "Select a sender to copy its first web link.", parent=self.root)
            return
        entries = sorted(self.senders[selected[0]].entries.values(), key=lambda c: int(c.uid), reverse=True)
        links = [t.uri for c in entries for t in c.targets if t.method in {"POST", "MANUAL"}]
        if not links:
            messagebox.showinfo("No web link", "This sender has no supported web link. Inspect the original email in Gmail.", parent=self.root)
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(links[0])
        self.log("Copied the first web link. Check its domain before opening it; browser requests are outside the app's protections.")

    def _start_worker(self, target: Callable[..., None], args: tuple[Any, ...], password: str) -> None:
        self.guard = NetworkGuard()
        guard = self.guard
        self.is_running = True
        self.done_received = False
        self.task_had_error = False
        self.last_summary = None
        self.events.take_progress()
        self._progress = None
        self._activity = self.status_var.get()
        self._task_started = self._activity_started = time.monotonic()
        self.progress_bar.stop()
        self.progress_bar.configure(mode="indeterminate", maximum=100, value=0)
        self.progress_bar.start(60)
        self.progress_text_var.set("Connecting...")
        self.update_controls()

        def emit(kind: str, payload: Any) -> None:
            self.events.put((kind, payload))

        def run() -> None:
            try:
                target(*args, guard=guard, emit=emit)
            except Cancelled:
                guard.cancel()
                emit("log", "Stopped. Previously submitted requests cannot be recalled.")
            except AuthenticationError as exc:
                emit("error", str(exc))
            except (MailboxError, imaplib.IMAP4.error) as exc:
                emit("error", f"Mailbox operation failed: {display_text(exc)}")
            except Exception as exc:
                if guard.stop_event.is_set():
                    emit("log", "Stopped. Review recorded outcomes before retrying.")
                else:
                    detail = display_text(exc)
                    if password:
                        detail = detail.replace(password, "[redacted]")
                    emit("error", f"{type(exc).__name__}: {detail}")
            finally:
                guard.abort_sockets()
                emit("done", None)

        # Wait for the worker to finish before closing the window.
        self.worker = threading.Thread(target=run, name="gmail-unsubscribe-worker", daemon=False)
        self.worker.start()

    def _save_export(self, path: str) -> None:
        try:
            export_results(path, self.results)
            self.last_export_count = len(self.results)
            self.log(f"Exported {len(self.results)} outcomes to {path}. Treat the file as private; it includes unsubscribe tokens.")
        except (OSError, csv.Error, UnicodeError) as exc:
            # A failed export must not resend an unsubscribe request.
            self.closing = False
            self.log(f"CSV export failed: {display_text(exc)}. Results remain in memory.")
            messagebox.showerror("CSV export failed", "The request outcomes are unchanged and remain in memory.\n"
                                 "Close the CSV in Excel or choose another path, then use Export results.\n\n" + str(exc), parent=self.root)

    def manual_export(self) -> None:
        if self.is_running or not self.results:
            return
        path = filedialog.asksaveasfilename(parent=self.root, title="Export session results (contains private links)",
                                           defaultextension=".csv", initialfile="unsubscribe_results.csv",
                                           filetypes=[("CSV files", "*.csv")])
        if path:
            self._save_export(path)

    def on_close(self) -> None:
        if self.closing:
            return
        if self.is_running:
            if not messagebox.askyesno("Stop and close?", "Stop further work and close once the worker exits?\n"
                                      "Already-sent requests cannot be recalled. Unexported results will be lost.",
                                      parent=self.root, default=messagebox.NO):
                return
            self.closing = True
            self.stop_process()
        else:
            if len(self.results) > self.last_export_count and not messagebox.askyesno(
                    "Unsaved results", "Some outcomes have not been exported. Close without saving them?",
                    parent=self.root, default=messagebox.NO):
                return
            self._destroy()

    def _destroy(self) -> None:
        self.progress_bar.stop()
        if self._poll_id is not None:
            self.root.after_cancel(self._poll_id)
            self._poll_id = None
        if self._refresh_id is not None:
            self.root.after_cancel(self._refresh_id)
            self._refresh_id = None
        self.pass_var.set("")
        self.destroyed = True
        self.root.destroy()


def main() -> None:
    from desktop_launcher import launch
    launch()


if __name__ == "__main__":
    main()
