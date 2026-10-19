"""Fixed tool policy and atomic local simulator execution; no external I/O."""

from __future__ import annotations

import hmac
import secrets
import sqlite3
from pathlib import Path
from typing import Any, Callable

from .approvals import POLICY_VERSION, GrantSigner, checked_time, system_clock
from .models import AccessContext, Action, GatewayError, ITEMS, canonical_json
from .storage import Store


class ApprovalGateway:
    def __init__(self, database: str | Path, *, key: bytes, clock: Callable[[], int] = system_clock):
        self._signer = GrantSigner(key)
        self._store = Store(database)
        self._clock = clock

    def plan(self, raw: str | bytes, *, context: AccessContext) -> dict[str, Any]:
        """Validate and decide without reading or changing any simulator or audit state."""
        action = Action.parse(raw)
        action.bind(context)
        return {
            "decision": "allow" if action.risk == "read_only" else "approval_required",
            "risk": action.risk, "policy_version": POLICY_VERSION,
            "request_id": action.request_id, "request_digest": action.request_digest,
            "tenant_id": action.tenant_id, "principal_id": action.principal_id,
            "tool": action.tool, "target": action.target,
            "arguments": action.document["arguments"],
            "simulation": True, "external_actions": False,
            "notice": "All connectors are local simulations. This plan does not reserve execution or grant approval.",
        }

    def execute(self, raw: str | bytes, *, context: AccessContext,
                approval: str | None = None) -> dict[str, Any]:
        try:
            return self._execute(raw, context=context, approval=approval)
        except GatewayError as error:
            # Rejections never store raw payloads, tokens, or the claimed identity.
            self._store.record_rejection(checked_time(self._clock), context, error.code)
            raise

    def _execute(self, raw: str | bytes, *, context: AccessContext,
                 approval: str | None) -> dict[str, Any]:
        action = Action.parse(raw)
        action.bind(context)
        grant = None
        if action.risk == "sensitive":
            if approval is None:
                raise GatewayError("APPROVAL_REQUIRED", "A separately issued approval is required.")
            grant = self._signer.verify(approval)
            expected = {
                "request_digest": action.request_digest, "tenant_id": action.tenant_id,
                "principal_id": action.principal_id, "tool": action.tool, "target": action.target,
            }
            if any(not hmac.compare_digest(grant[key], value) for key, value in expected.items()):
                raise GatewayError("APPROVAL_MISMATCH", "Approval is bound to a different exact action.")
        elif approval is not None:
            raise GatewayError("UNEXPECTED_APPROVAL", "Read-only actions do not accept approval grants.")

        with self._store.transaction() as connection:
            # Check time after acquiring the write lock, before simulator mutation.
            now = checked_time(self._clock)
            if grant:
                if now < grant["issued_at"]:
                    raise GatewayError("INVALID_APPROVAL", "Approval is not valid before its issue time.")
                if now >= grant["expires_at"]:
                    raise GatewayError("APPROVAL_EXPIRED", "Approval has reached its exclusive expiry timestamp.")
                record = connection.execute("SELECT payload_json, used_at FROM approvals WHERE grant_id = ?",
                                            (grant["grant_id"],)).fetchone()
                if record is None or not hmac.compare_digest(record["payload_json"], canonical_json(grant)):
                    raise GatewayError("UNKNOWN_APPROVAL", "Approval is absent from the trusted grant registry.")
                if record["used_at"] is not None:
                    raise GatewayError("APPROVAL_REPLAY", "Approval has already been consumed.")
            if connection.execute("SELECT 1 FROM executions WHERE tenant_id = ? AND request_id = ?",
                                  (action.tenant_id, action.request_id)).fetchone():
                raise GatewayError("REQUEST_REPLAY", "This tenant request identifier has already executed.")

            result = self._simulate(connection, action)
            if grant:
                connection.execute("UPDATE approvals SET used_at = ? WHERE grant_id = ?", (now, grant["grant_id"]))
            connection.execute(
                "INSERT INTO executions (tenant_id, request_id, request_digest, result_json, executed_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (action.tenant_id, action.request_id, action.request_digest, canonical_json(result), now),
            )
            self._store.append_audit(connection, now, context, "execution_committed", "SIMULATED_SUCCESS", action)
        return {"status": "simulated_success", "request_id": action.request_id,
                "request_digest": action.request_digest, "simulation": True,
                "external_actions": False, "result": result}

    @staticmethod
    def _simulate(connection: sqlite3.Connection, action: Action) -> dict[str, Any]:
        """Only SQLite fixture changes; deliberately no plugin, network, shell, or path dispatch."""
        args = action.document["arguments"]
        if action.tool in {"catalog.lookup", "inventory.adjust"}:
            row = connection.execute("SELECT quantity FROM inventory WHERE tenant_id = ? AND item_id = ?",
                                     (action.tenant_id, args["item_id"])).fetchone()
            before = row["quantity"] if row else ITEMS[args["item_id"]]
            if action.tool == "catalog.lookup":
                return {"item_id": args["item_id"], "quantity": before, "source": "synthetic_fixture"}
            after = before + args["delta"]
            if after < 0:
                raise GatewayError("INVALID_STATE", "Simulated inventory cannot become negative.")
            connection.execute(
                "INSERT INTO inventory (tenant_id, item_id, quantity) VALUES (?, ?, ?) "
                "ON CONFLICT(tenant_id, item_id) DO UPDATE SET quantity = excluded.quantity",
                (action.tenant_id, args["item_id"], after),
            )
            return {"item_id": args["item_id"], "before": before, "after": after, "delta": args["delta"]}
        if action.tool == "notifications.send":
            message_id = "sim-" + secrets.token_hex(12)
            connection.execute(
                "INSERT INTO simulated_messages (message_id, tenant_id, channel_id, body) VALUES (?, ?, ?, ?)",
                (message_id, action.tenant_id, args["channel_id"], args["text"]),
            )
            return {"message_id": message_id, "channel_id": args["channel_id"],
                    "text_length": len(args["text"]), "delivery": "stored_locally_only"}
        # Defense in depth if parsing and dispatch ever diverge.
        raise GatewayError("UNKNOWN_TOOL", "No simulator exists for this tool.")

    def audit(self, *, context: AccessContext) -> list[dict[str, Any]]:
        return self._store.audit(context)
