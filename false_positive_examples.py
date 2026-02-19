"""
false_positive_examples.py

Demonstrates common SAST (Static Application Security Testing) false positives.
In each example, a SAST tool may flag the code as vulnerable, but the input
is properly sanitized or parameterized before any actual risk is introduced.
"""

import sqlite3
import subprocess
import html
import re
import shlex


# ──────────────────────────────────────────────
# Example 1: SQL Injection False Positive
# ──────────────────────────────────────────────
# SAST tools often flag any use of user input near a database query.
# Here the raw input looks dangerous, but parameterized queries are used —
# making injection impossible.

def get_user_by_name(username: str):
    """
    SAST may flag `username` as tainted input flowing into a DB call.
    Reality: parameterized query prevents SQL injection entirely.
    """
    # SAST flag: "user-controlled input used in SQL query"
    raw_input = username  # tainted source — flagged here

    # Sanitization: parameterized query (the safe pattern)
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (raw_input,))  # safe
    return cursor.fetchall()


# ──────────────────────────────────────────────
# Example 2: XSS False Positive
# ──────────────────────────────────────────────
# SAST tools flag user input being embedded in HTML output.
# Here the input is escaped before rendering, neutralizing any XSS risk.

def render_comment(user_comment: str) -> str:
    """
    SAST may flag `user_comment` as a reflected XSS risk.
    Reality: html.escape() encodes all dangerous characters before output.
    """
    # SAST flag: "user input reflected in HTML response"
    raw_comment = user_comment  # tainted source

    # Sanitization: escape HTML special characters
    safe_comment = html.escape(raw_comment)  # <script> becomes &lt;script&gt;
    return f"<p>{safe_comment}</p>"


# ──────────────────────────────────────────────
# Example 3: Command Injection False Positive
# ──────────────────────────────────────────────
# SAST tools flag any subprocess call that involves user-supplied data.
# Here shlex.quote() and a list-form call prevent shell injection.

def ping_host(hostname: str) -> str:
    """
    SAST may flag this as a command injection vulnerability.
    Reality: shlex.quote sanitizes the input and shell=False is used,
    so no shell expansion occurs.
    """
    # SAST flag: "user-controlled data passed to subprocess"
    raw_host = hostname  # tainted source

    # Sanitization: validate format, then quote for shell safety
    if not re.match(r"^[a-zA-Z0-9.\-]+$", raw_host):
        raise ValueError("Invalid hostname")

    safe_host = shlex.quote(raw_host)
    result = subprocess.run(
        ["ping", "-c", "1", safe_host],  # list form — no shell interpolation
        capture_output=True,
        text=True,
        shell=False,  # explicit: no shell expansion
    )
    return result.stdout


# ──────────────────────────────────────────────
# Example 4: Path Traversal False Positive
# ──────────────────────────────────────────────
# SAST flags user input used to construct a file path.
# Here the resolved path is validated to stay within an allowed directory.

import os

def read_report(filename: str, base_dir: str = "/var/reports") -> str:
    """
    SAST may flag this as a path traversal vulnerability.
    Reality: os.path.realpath + prefix check confines access to base_dir.
    """
    # SAST flag: "user-controlled input used in file path construction"
    raw_filename = filename  # tainted source

    # Sanitization: resolve the real path and verify it stays in base_dir
    requested_path = os.path.realpath(os.path.join(base_dir, raw_filename))
    if not requested_path.startswith(os.path.realpath(base_dir) + os.sep):
        raise PermissionError("Access denied: path traversal detected")

    with open(requested_path, "r") as f:
        return f.read()


# ──────────────────────────────────────────────
# Main: show each example being called safely
# ──────────────────────────────────────────────

if __name__ == "__main__":
    # Example 1
    print("=== SQL Query (parameterized) ===")
    results = get_user_by_name("alice")
    print(f"Query returned {len(results)} rows (empty in-memory DB — no injection)")

    # Example 2
    print("\n=== XSS Escaped Output ===")
    malicious_input = "<script>alert('xss')</script>"
    safe_html = render_comment(malicious_input)
    print(f"Raw input : {malicious_input}")
    print(f"Safe HTML : {safe_html}")

    # Example 3 — skipped in demo to avoid requiring network
    print("\n=== Command Injection (shlex + shell=False) ===")
    try:
        safe_hostname = "localhost"
        print(f"Would ping: {shlex.quote(safe_hostname)} (skipping actual call in demo)")
    except ValueError as e:
        print(f"Rejected: {e}")

    # Example 4 — skipped to avoid requiring file system
    print("\n=== Path Traversal (realpath check) ===")
    try:
        read_report("../etc/passwd", base_dir="/var/reports")
    except PermissionError as e:
        print(f"Correctly blocked: {e}")
    except FileNotFoundError:
        print("Path traversal blocked — safe path didn't exist (expected in demo)")
