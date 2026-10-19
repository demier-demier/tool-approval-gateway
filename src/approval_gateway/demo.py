"""Executable synthetic evidence, independent of the unit-test suite."""

from __future__ import annotations

import copy
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import AccessContext, ApprovalAuthority, ApprovalGateway, GatewayError
from .report import write_report


def sample_request(request_id: str = "request-demo-adjust") -> dict[str, Any]:
    return {
        "version": 1, "request_id": request_id, "tenant_id": "tenant-demo-a",
        "principal_id": "agent-demo-a", "tool": "inventory.adjust",
        "target": "item:item-demo-001",
        "arguments": {"item_id": "item-demo-001", "delta": 5, "reason": "Synthetic reconciliation"},
    }


def run_demo(directory: Path) -> dict[str, Any]:
    database = directory / "gateway.sqlite3"
    if database.exists():
        raise FileExistsError("Demo database already exists. Choose a new output directory to preserve prior evidence.")
    key = secrets.token_bytes(32)  # Ephemeral; neither the key nor live grants are exported.
    now = [1_800_000_000]
    clock = lambda: now[0]
    gateway = ApprovalGateway(database, key=key, clock=clock)
    authority = ApprovalAuthority(database, key=key, clock=clock)
    requester = AccessContext("tenant-demo-a", "agent-demo-a", frozenset({"requester"}))
    approver = AccessContext("tenant-demo-a", "reviewer-demo-a", frozenset({"approver"}))
    auditor = AccessContext("tenant-demo-a", "auditor-demo-a", frozenset({"auditor"}))
    scenarios: list[dict[str, Any]] = []

    def record(case_id: str, title: str, description: str, request: dict[str, Any] | str,
               expected: str, operation: Callable[[], dict[str, Any]], *, actor: AccessContext = requester,
               before: int | None = None) -> None:
        raw = request if isinstance(request, str) else json.dumps(request)
        start = len(gateway.audit(context=auditor)) if before is None else before
        try:
            plan = gateway.plan(raw, context=actor)
        except GatewayError:
            plan = None
        try:
            result = operation()
            actual = result["status"]
        except GatewayError as error:
            actual = error.code
            result = {"status": "rejected", "code": error.code, "message": str(error)}
        if actual != expected:
            raise AssertionError(f"Scenario {case_id}: expected {expected}, got {actual}")
        scenarios.append({
            "id": case_id, "title": title, "description": description,
            "tool": request.get("tool", "invalid request") if isinstance(request, dict) else "invalid request",
            "request": request, "plan": plan, "expected": expected, "actual": actual, "result": result,
            "audit": gateway.audit(context=auditor)[start:],
        })

    read = sample_request("request-demo-read")
    read.update(tool="catalog.lookup", arguments={"item_id": "item-demo-001"})
    record("case-01", "Read the synthetic catalog", "A fixed read-only tool executes without a grant.", read,
           "simulated_success", lambda: gateway.execute(json.dumps(read), context=requester))

    action = sample_request()
    raw = json.dumps(action)
    record("case-02", "Sensitive action, missing approval", "A valid action still needs an independent approval.",
           action, "APPROVAL_REQUIRED", lambda: gateway.execute(raw, context=requester))

    audit_start = len(gateway.audit(context=auditor))
    token = authority.issue(raw, requester=requester, approver=approver)
    record("case-03", "Approve the exact adjustment", "The synthetic quantity changes from 40 to 45 in the grant-consumption transaction.",
           action, "simulated_success", lambda: gateway.execute(raw, context=requester, approval=token), before=audit_start)

    changed = copy.deepcopy(action)
    changed["arguments"]["delta"] = 9
    record("case-04", "Change arguments after approval", "Changing one approved argument breaks the request binding.",
           changed, "APPROVAL_MISMATCH", lambda: gateway.execute(json.dumps(changed), context=requester, approval=token))

    restarted = ApprovalGateway(database, key=key, clock=clock)
    record("case-05", "Replay after gateway restart", "A new gateway instance reads the persisted consumed-grant state.",
           action, "APPROVAL_REPLAY", lambda: restarted.execute(raw, context=requester, approval=token))

    expired = sample_request("request-demo-expired")
    expired_raw = json.dumps(expired)
    expiry_start = len(gateway.audit(context=auditor))
    expiry_token = authority.issue(expired_raw, requester=requester, approver=approver, ttl_seconds=10)
    now[0] += 10
    record("case-06", "Reach the exact expiry boundary", "At expires_at, the grant is already expired; validity is an exclusive upper bound.",
           expired, "APPROVAL_EXPIRED", lambda: gateway.execute(expired_raw, context=requester, approval=expiry_token), before=expiry_start)

    wrong_actor = AccessContext("tenant-demo-a", "agent-demo-b", frozenset({"requester"}))
    record("case-07", "Use another principal's request", "The trusted caller identity must equal the request identity.",
           action, "IDENTITY_MISMATCH", lambda: gateway.execute(raw, context=wrong_actor, approval=token), actor=wrong_actor)

    cross_tenant = copy.deepcopy(action)
    cross_tenant["tenant_id"] = "tenant-demo-b"
    record("case-08", "Claim a different tenant", "A request cannot select a tenant other than the caller's authenticated tenant.",
           cross_tenant, "IDENTITY_MISMATCH", lambda: gateway.execute(json.dumps(cross_tenant), context=requester, approval=token))

    changed_principal = copy.deepcopy(action)
    changed_principal["principal_id"] = wrong_actor.principal_id
    record("case-09", "Transfer a grant to another principal", "Even with a matching new context, another principal cannot use the original grant.",
           changed_principal, "APPROVAL_MISMATCH", lambda: gateway.execute(json.dumps(changed_principal), context=wrong_actor, approval=token), actor=wrong_actor)

    target = copy.deepcopy(action)
    target["target"] = "item:item-demo-002"
    target["arguments"]["item_id"] = "item-demo-002"
    record("case-10", "Retarget an approved action", "A different allowlisted item still requires a different exact-action approval.",
           target, "APPROVAL_MISMATCH", lambda: gateway.execute(json.dumps(target), context=requester, approval=token))

    forged = token[:-2] + ("A" if token[-2] != "A" else "B") + token[-1]
    record("case-11", "Tamper with the grant signature", "Modified token bytes fail authentication before dispatch.",
           action, "INVALID_APPROVAL", lambda: gateway.execute(raw, context=requester, approval=forged))

    unknown = sample_request("request-demo-unknown")
    unknown["tool"] = "files.export"
    record("case-12", "Request an unknown tool", "The dispatcher cannot call tools outside its fixed allowlist.",
           unknown, "UNKNOWN_TOOL", lambda: gateway.execute(json.dumps(unknown), context=requester))

    malformed = sample_request("request-demo-malformed")
    malformed["arguments"]["delta"] = True
    record("case-13", "Send a boolean as a quantity", "Strict typing rejects booleans where an integer delta is required.",
           malformed, "INVALID_SCHEMA", lambda: gateway.execute(json.dumps(malformed), context=requester))

    message = sample_request("request-demo-message")
    message.update(tool="notifications.send", target="channel:channel-demo-ops",
                   arguments={"channel_id": "channel-demo-ops", "text": "Synthetic note: <script>alert('fixture')</script> is inert report text."})
    message_raw = json.dumps(message)
    message_start = len(gateway.audit(context=auditor))
    message_token = authority.issue(message_raw, requester=requester, approver=approver)
    record("case-14", "Store a synthetic notification", "The approved message is stored only in SQLite. Markup in its text stays inert in this report.",
           message, "simulated_success", lambda: gateway.execute(message_raw, context=requester, approval=message_token), before=message_start)

    self_context = AccessContext("tenant-demo-a", "agent-demo-a", frozenset({"requester", "approver"}))
    self_action = sample_request("request-demo-self-approval")
    record("case-15", "Attempt self-approval", "Holding both trusted roles does not permit approving your own sensitive action.",
           self_action, "SELF_APPROVAL", lambda: {"status": authority.issue(json.dumps(self_action), requester=requester, approver=self_context)})

    data = {
        "format_version": 1, "title": "Tool approval gateway — synthetic decision evidence",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "simulation": True, "external_actions": 0, "clock": "Fixed synthetic Unix clock starting at 1800000000",
        "expected_outcomes_verified": len(scenarios), "scenarios": scenarios,
        "audit": gateway.audit(context=auditor),
        "limitations": ["All connectors are local SQLite simulations.",
                        "Trusted authentication and authorization adapters are outside this reference.",
                        "Atomic local effects do not prove exactly-once effects in external systems."],
    }
    html, report_json = write_report(data, directory)
    return {"scenarios": len(scenarios), "expected_outcomes_verified": len(scenarios), "external_actions": 0,
            "html": str(html), "json": str(report_json), "database": str(database)}
