#!/usr/bin/env python3
"""Fail closed unless the repository contains only expected, public-safe files."""

from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {
    ".gitignore", "LICENSE", "README.md", "pyproject.toml",
    ".github/workflows/ci.yml",
    "examples/config.example.json", "examples/runtime.env.example",
    "src/ssh_socks_failover/__init__.py", "src/ssh_socks_failover/cli.py",
    "src/ssh_socks_failover/core.py", "tests/test_core.py",
    "tools/validate_public_repo.py",
    "systemd/ssh-socks-failover-tunnel.service",
    "systemd/ssh-socks-failover-guard.service",
    "systemd/ssh-socks-failover-guard.timer",
    "systemd/ssh-socks-failover-rotate.service",
    "systemd/ssh-socks-failover-rotate.timer",
}
MAX_FILE_BYTES = 200_000
TEXT_EXTENSIONS = {"", ".md", ".toml", ".json", ".env", ".example", ".py", ".service", ".timer", ".yml"}
PRIVATE_KEY_MARKER = "-----BEGIN " + "PRIVATE KEY-----"
SENSITIVE_WORDS = tuple(word.lower() for word in (
    "o" + "cid", "o" + "saka", "t" + "echwave", "o" + "racle",
))
GENERIC_SECRET = re.compile(
    r"(?i)(api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{12,}"
)
EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
ABSOLUTE_PRIVATE_PATH = re.compile(r"/(?:home|Users)/[^/\s'\"]+")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def repository_files() -> set[str]:
    files: set[str] = set()
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if relative.parts[0] == ".git" or "__pycache__" in relative.parts:
            continue
        if path.is_symlink():
            raise ValueError(f"symlink is forbidden: {relative}")
        if path.is_file():
            files.add(relative.as_posix())
    return files


def ip_is_documentation_safe(text: str) -> bool:
    address = ipaddress.ip_address(text)
    return (
        address.is_loopback
        or address.is_unspecified
        or address in ipaddress.ip_network("192.0.2.0/24")
        or address in ipaddress.ip_network("198.51.100.0/24")
        or address in ipaddress.ip_network("203.0.113.0/24")
    )


def validate() -> list[str]:
    errors: list[str] = []
    try:
        actual = repository_files()
    except ValueError as exc:
        return [str(exc)]
    missing = ALLOWED - actual
    unexpected = actual - ALLOWED
    errors.extend(f"missing allowlisted file: {path}" for path in sorted(missing))
    errors.extend(f"unexpected file: {path}" for path in sorted(unexpected))
    for relative in sorted(actual & ALLOWED):
        path = ROOT / relative
        if path.stat().st_size > MAX_FILE_BYTES:
            errors.append(f"oversized file: {relative}")
            continue
        if path.suffix not in TEXT_EXTENSIONS:
            errors.append(f"non-text extension: {relative}")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            errors.append(f"non-UTF-8 file: {relative}")
            continue
        lowered = text.lower()
        if PRIVATE_KEY_MARKER in text:
            errors.append(f"private key material: {relative}")
        if GENERIC_SECRET.search(text):
            errors.append(f"credential-like assignment: {relative}")
        if ABSOLUTE_PRIVATE_PATH.search(text):
            errors.append(f"private absolute path: {relative}")
        if EMAIL.search(text):
            errors.append(f"email address: {relative}")
        for word in SENSITIVE_WORDS:
            if word in lowered:
                errors.append(f"environment-specific term in {relative}")
        for candidate in IPV4.findall(text):
            try:
                if not ip_is_documentation_safe(candidate):
                    errors.append(f"non-documentation IPv4 address {candidate} in {relative}")
            except ValueError:
                errors.append(f"invalid IPv4-like value {candidate} in {relative}")
    return errors


def main() -> int:
    errors = validate()
    if errors:
        print("PUBLIC REPOSITORY VALIDATION FAILED", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"PUBLIC REPOSITORY VALIDATION PASSED: {len(ALLOWED)} allowlisted files")
    print("Checks: exact allowlist, no symlinks/binary/oversize files, credentials, private keys, emails,")
    print("private user paths, environment-specific terms, or non-documentation IPv4 addresses.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
