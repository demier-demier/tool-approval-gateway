"""SQLite transaction boundary shared by grant use, simulations, and audit."""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .models import AccessContext, Action

SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    grant_id TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL,
    used_at INTEGER
);
CREATE TABLE IF NOT EXISTS executions (
    tenant_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    result_json TEXT NOT NULL,
    executed_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, request_id)
);
CREATE TABLE IF NOT EXISTS inventory (
    tenant_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    quantity INTEGER NOT NULL CHECK (quantity >= 0),
    PRIMARY KEY (tenant_id, item_id)
);
CREATE TABLE IF NOT EXISTS simulated_messages (
    message_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at INTEGER NOT NULL,
    tenant_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    event TEXT NOT NULL,
    code TEXT NOT NULL,
    request_id TEXT,
    request_digest TEXT,
    tool TEXT,
    target TEXT
);
CREATE INDEX IF NOT EXISTS audit_scope ON audit_events (tenant_id, principal_id, event_id);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # New databases are private on POSIX. Existing permissions are the operator's responsibility.
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        with self.connection() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(SCHEMA)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA busy_timeout=10000")
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    @staticmethod
    def append_audit(connection: sqlite3.Connection, now: int, context: AccessContext,
                     event: str, code: str, action: Action | None = None) -> None:
        connection.execute(
            "INSERT INTO audit_events (occurred_at, tenant_id, principal_id, event, code, "
            "request_id, request_digest, tool, target) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (now, context.tenant_id, context.principal_id, event, code,
             action.request_id if action else None, action.request_digest if action else None,
             action.tool if action else None, action.target if action else None),
        )

    def audit(self, context: AccessContext) -> list[dict[str, Any]]:
        context.require("auditor")
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM audit_events WHERE tenant_id = ? ORDER BY event_id", (context.tenant_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def record_rejection(self, now: int, context: AccessContext, code: str) -> None:
        with self.transaction() as connection:
            self.append_audit(connection, now, context, "rejected", code)
