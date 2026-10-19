"""Synthetic trusted-adapter wiring. No server or external tool calls."""

import json
import secrets
import tempfile
from pathlib import Path

from approval_gateway import AccessContext, ApprovalAuthority, ApprovalGateway


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="approval-example-") as directory:
        database = Path(directory) / "gateway.sqlite3"
        runtime_key = secrets.token_bytes(32)
        gateway = ApprovalGateway(database, key=runtime_key)
        # In a real service, expose this authority only behind a separate trusted approval route.
        authority = ApprovalAuthority(database, key=runtime_key)
        requester = AccessContext("tenant-demo-a", "agent-demo-a", frozenset({"requester"}))
        approver = AccessContext("tenant-demo-a", "reviewer-demo-a", frozenset({"approver"}))
        request_json = json.dumps({
            "version": 1, "request_id": "request-demo-example", "tenant_id": requester.tenant_id,
            "principal_id": requester.principal_id, "tool": "inventory.adjust",
            "target": "item:item-demo-001",
            "arguments": {"item_id": "item-demo-001", "delta": 2, "reason": "Synthetic example"},
        })
        plan = gateway.plan(request_json, context=requester)
        print(json.dumps({"plan": plan}, indent=2))
        # This fixture represents a completed independent approval, not automatic production approval.
        token = authority.issue(request_json, requester=requester, approver=approver, ttl_seconds=60)
        result = gateway.execute(request_json, context=requester, approval=token)
        print(json.dumps({"execution": result}, indent=2))


if __name__ == "__main__":
    main()
