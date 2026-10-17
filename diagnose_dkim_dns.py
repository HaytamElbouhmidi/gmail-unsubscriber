#!/usr/bin/env python3
"""Check DKIM TXT lookup connectivity without accessing Gmail.

Version 1.0.0
This script does not log in, access a mailbox, or submit unsubscribe requests.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

VERSION = "1.0.0"
DOMAIN = "google.com"
LOOKUP_SECONDS = 6.0


def valid_hostname(value: str) -> str:
    value = value.strip().removesuffix(".").lower()
    if len(value) > 253 or not value or any(
        not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", label)
        for label in value.split(".")
    ):
        raise ValueError("Use an ASCII DNS hostname without spaces or URLs.")
    return value + "."


def python_probe(hostname: str, tcp: bool, lifetime: float = LOOKUP_SECONDS) -> str:
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        return "SKIPPED: dnspython is not installed in this interpreter"
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        result = resolver.resolve(hostname, "TXT", tcp=tcp, search=False, lifetime=lifetime)
        return f"PASS: {len(result)} TXT record(s) received"
    except dns.exception.Timeout:
        return "TIMEOUT: the configured DNS resolver did not answer"
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN: the requested DNS name was not found"
    except dns.resolver.NoAnswer:
        return "NOANSWER: the name exists but no TXT records were returned"
    except dns.exception.DNSException as exc:
        return f"DNS ERROR: {type(exc).__name__}"
    except (OSError, ValueError) as exc:
        return f"ERROR: {type(exc).__name__}"


def windows_probe(hostname: str) -> str:
    if os.name != "nt":
        return "SKIPPED: Windows Resolve-DnsName is not available"
    command = (
        "$ErrorActionPreference='Stop'\n"
        f"$answer=Resolve-DnsName -Name '{hostname}' -Type TXT -DnsOnly -ErrorAction Stop\n"
        "$items=@($answer | Where-Object { $_.Type -eq 'TXT' })\n"
        "Write-Output ('PASS: ' + $items.Count + ' TXT record(s) received')\n"
    )
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=12, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"FAILED: {type(exc).__name__}"
    if proc.returncode:
        return "FAILED: Windows DNS returned an error (details omitted)"
    return proc.stdout.strip() or "FAILED: no DNS result"


def runtime_hint() -> None:
    runtime = Path.home() / ".gmail-unsubscriber"
    if os.name != "nt":
        return
    if runtime.is_dir():
        interpreters = sorted(runtime.glob("runtime-cpython-*-*/Scripts/python.exe"))
        if interpreters:
            print("App runtime Python:", interpreters[-1])
            return
    print("App runtime Python: not located under", runtime)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check DNS TXT connectivity used for DKIM verification")
    parser.add_argument("--name", default=DOMAIN, help="Public DNS name to query, default google.com")
    args = parser.parse_args()
    try:
        hostname = valid_hostname(args.name)
    except ValueError as exc:
        parser.error(str(exc))
    print(f"DKIM TXT DNS connectivity diagnostic v{VERSION}")
    print("Python interpreter:", sys.executable)
    print("DNS name:", hostname)
    print("This utility does not read email, submit requests, or print TXT record contents.")
    try:
        import dns
        import dns.resolver
        r = dns.resolver.Resolver()
        print("dnspython version:", getattr(dns, "__version__", "installed"))
        print("Configured nameservers:", ", ".join(str(ns) for ns in r.nameservers))
    except (ImportError, OSError) as exc:
        print("dnspython status:", type(exc).__name__)
    runtime_hint()
    print("Windows native DNS: ", windows_probe(hostname))
    print("Python DNS over UDP:", python_probe(hostname, tcp=False))
    print("Python DNS over TCP:", python_probe(hostname, tcp=True))
    print("\nInterpretation:")
    print("* Native PASS, Python TIMEOUT: look at dnspython resolver or network policy for port 53.")
    print("* UDP TIMEOUT, TCP PASS: DNS UDP traffic may be blocked or unreliable.")
    print("* All TIMEOUT: test the router, VPN, firewall, and configured DNS service.")
    print("* All PASS: investigate DKIM selector-specific lookups and library ValidationError separately.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
