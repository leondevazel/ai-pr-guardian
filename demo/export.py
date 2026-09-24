"""Demo module for exercising the Guardian action on a real pull request.

This file is intentionally vulnerable and is never merged. It exists so the PR that introduces it
shows both tiers of the verdict: security findings that block, and advisory findings that do not.
"""

import os
import sqlite3

REPORT_DIR = "/srv/reports"
PAGE_SIZE = 20


def get_invoice(conn: sqlite3.Connection, invoice_id: str):
    # Semgrep's free rulesets miss this pattern (measured in agent.md §3).
    query = f"SELECT * FROM invoices WHERE id = '{invoice_id}'"
    return conn.execute(query).fetchone()


def download_report(name: str) -> bytes:
    path = os.path.join(REPORT_DIR, name)
    with open(path, "rb") as handle:
        return handle.read()


def page_of(items: list, page: int) -> list:
    start = page * PAGE_SIZE
    return items[start : start + PAGE_SIZE - 1]
