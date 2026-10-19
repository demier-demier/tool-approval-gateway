from __future__ import annotations

import copy
import json
import secrets
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from approval_gateway import AccessContext, ApprovalAuthority, ApprovalGateway, GatewayError
from approval_gateway.approvals import GrantSigner
from approval_gateway.demo import sample_request
from approval_gateway.models import Action


class GatewayTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.database = Path(self.directory.name) / "test.sqlite3"
        self.key = secrets.token_bytes(32)
        self.now = 1_800_000_000
        self.clock = lambda: self.now
        self.gateway = ApprovalGateway(self.database, key=self.key, clock=self.clock)
        self.authority = ApprovalAuthority(self.database, key=self.key, clock=self.clock)
        self.requester = AccessContext("tenant-demo-a", "agent-demo-a", frozenset({"requester"}))
        self.approver = AccessContext("tenant-demo-a", "reviewer-demo-a", frozenset({"approver"}))
        self.auditor = AccessContext("tenant-demo-a", "auditor-demo-a", frozenset({"auditor"}))
        self.document = sample_request()

    @property
    def raw(self) -> str:
        return json.dumps(self.document)

    def grant(self, **kwargs) -> str:
        return self.authority.issue(self.raw, requester=self.requester, approver=self.approver, **kwargs)

    def execute(self, token: str | None = None, **kwargs):
        return self.gateway.execute(self.raw, context=self.requester, approval=token, **kwargs)

    def assert_code(self, code, operation) -> None:
        with self.assertRaises(GatewayError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)

    def rows(self, table: str):
        # Test-owned constant table names, never user input.
        with sqlite3.connect(self.database) as connection:
            return connection.execute("SELECT * FROM " + table).fetchall()

    def test_plan_does_not_persist_or_execute(self):
        before = {table: self.rows(table) for table in ("approvals", "executions", "inventory", "audit_events")}
        plan = self.gateway.plan(self.raw, context=self.requester)
        self.assertEqual(plan["decision"], "approval_required")
        self.assertEqual(plan["arguments"]["delta"], 5)
        self.assertFalse(plan["external_actions"])
        self.assertEqual(before, {table: self.rows(table) for table in before})

    def test_read_only_tool_executes_without_approval(self):
        self.document.update(tool="catalog.lookup", arguments={"item_id": "item-demo-001"})
        self.assertEqual(self.gateway.plan(self.raw, context=self.requester)["risk"], "read_only")
        self.assertEqual(self.execute()["result"]["quantity"], 40)
        self.assertEqual(self.rows("inventory"), [])

    def test_sensitive_action_requires_approval(self):
        self.assert_code("APPROVAL_REQUIRED", self.execute)
        self.assertEqual(self.rows("inventory"), [])

    def test_approved_action_commits_effect_grant_execution_and_audit(self):
        result = self.execute(self.grant())
        self.assertEqual(result["result"], {"item_id": "item-demo-001", "before": 40, "after": 45, "delta": 5})
        self.assertEqual(self.rows("inventory")[0][2], 45)
        self.assertEqual(self.rows("approvals")[0][2], self.now)
        self.assertEqual(len(self.rows("executions")), 1)
        self.assertEqual([row["event"] for row in self.gateway.audit(context=self.auditor)],
                         ["approval_issued", "execution_committed"])

    def test_argument_tampering_is_rejected_without_consuming_grant(self):
        token = self.grant()
        self.document["arguments"]["delta"] = 6
        self.assert_code("APPROVAL_MISMATCH", lambda: self.execute(token))
        self.assertEqual(self.rows("inventory"), [])
        self.assertIsNone(self.rows("approvals")[0][2])
        self.document["arguments"]["delta"] = 5
        self.assertEqual(self.execute(token)["status"], "simulated_success")

    def test_equivalent_json_key_order_and_whitespace_preserve_binding(self):
        token = self.grant()
        reordered = dict(reversed(list(self.document.items())))
        result = self.gateway.execute(json.dumps(reordered, indent=4), context=self.requester, approval=token)
        self.assertEqual(result["status"], "simulated_success")

    def test_text_is_exact_and_unicode_is_not_normalized(self):
        self.document["arguments"]["reason"] = "Caf\u00e9"
        token = self.grant()
        self.document["arguments"]["reason"] = "Cafe\u0301"
        self.assert_code("APPROVAL_MISMATCH", lambda: self.execute(token))

    def test_replay_is_denied_after_new_gateway_instance(self):
        token = self.grant()
        self.execute(token)
        restarted = ApprovalGateway(self.database, key=self.key, clock=self.clock)
        self.assert_code("APPROVAL_REPLAY", lambda: restarted.execute(self.raw, context=self.requester, approval=token))
        self.assertEqual(self.rows("inventory")[0][2], 45)

    def test_reusing_request_id_with_a_second_grant_is_denied(self):
        first, second = self.grant(), self.grant()
        self.execute(first)
        self.assert_code("REQUEST_REPLAY", lambda: self.execute(second))
        self.assert_code("REQUEST_REPLAY", self.grant)

    def test_expiry_is_exclusive(self):
        token = self.grant(ttl_seconds=10)
        self.now += 10
        self.assert_code("APPROVAL_EXPIRED", lambda: self.execute(token))
        self.assertEqual(self.rows("inventory"), [])

    def test_last_second_before_expiry_is_accepted(self):
        token = self.grant(ttl_seconds=10)
        self.now += 9
        self.assertEqual(self.execute(token)["status"], "simulated_success")

    def test_clock_rollback_before_issue_time_is_denied(self):
        token = self.grant()
        self.now -= 1
        self.assert_code("INVALID_APPROVAL", lambda: self.execute(token))

    def test_invalid_approval_lifetimes_are_denied(self):
        for ttl in (0, -1, 301, True, 1.5, "10"):
            with self.subTest(ttl=ttl):
                self.assert_code("INVALID_TTL", lambda: self.grant(ttl_seconds=ttl))

    def test_principal_context_mismatch_is_denied(self):
        token = self.grant()
        wrong = AccessContext("tenant-demo-a", "agent-demo-b", frozenset({"requester"}))
        self.assert_code("IDENTITY_MISMATCH", lambda: self.gateway.execute(self.raw, context=wrong, approval=token))

    def test_grant_cannot_be_transferred_to_another_principal(self):
        token = self.grant()
        self.document["principal_id"] = "agent-demo-b"
        other = AccessContext("tenant-demo-a", "agent-demo-b", frozenset({"requester"}))
        self.assert_code("APPROVAL_MISMATCH", lambda: self.gateway.execute(self.raw, context=other, approval=token))

    def test_grant_cannot_cross_tenant_with_matching_caller_context(self):
        token = self.grant()
        self.document["tenant_id"] = "tenant-demo-b"
        other = AccessContext("tenant-demo-b", "agent-demo-a", frozenset({"requester"}))
        self.assert_code("APPROVAL_MISMATCH", lambda: self.gateway.execute(self.raw, context=other, approval=token))
        self.assertEqual(self.rows("inventory"), [])

    def test_request_cannot_claim_another_tenant(self):
        self.document["tenant_id"] = "tenant-demo-b"
        self.assert_code("IDENTITY_MISMATCH", self.execute)

    def test_approver_must_be_authorized_independent_and_same_tenant(self):
        cases = [
            (AccessContext("tenant-demo-a", "reviewer-demo-a", frozenset({"requester"})), "FORBIDDEN"),
            (AccessContext("tenant-demo-b", "reviewer-demo-a", frozenset({"approver"})), "APPROVER_TENANT_MISMATCH"),
            (AccessContext("tenant-demo-a", "agent-demo-a", frozenset({"approver"})), "SELF_APPROVAL"),
        ]
        for approver, code in cases:
            with self.subTest(code=code):
                self.assert_code(code, lambda: self.authority.issue(self.raw, requester=self.requester, approver=approver))
        self.assertEqual(self.rows("approvals"), [])

    def test_target_binding_and_target_allowlist(self):
        token = self.grant()
        self.document["target"] = "item:item-demo-002"
        self.assert_code("TARGET_MISMATCH", lambda: self.execute(token))
        self.document["arguments"]["item_id"] = "item-demo-002"
        self.assert_code("APPROVAL_MISMATCH", lambda: self.execute(token))
        self.document["arguments"]["item_id"] = "../../etc/config"
        self.assert_code("TARGET_NOT_ALLOWED", lambda: self.execute(token))

    def test_unknown_tool_is_denied(self):
        self.document["tool"] = "system.execute"
        self.assert_code("UNKNOWN_TOOL", self.execute)

    def test_signature_tampering_and_wrong_runtime_key_fail(self):
        token = self.grant()
        body, signature = token.split(".")
        tampered = body + "." + ("A" if signature[0] != "A" else "B") + signature[1:]
        self.assert_code("INVALID_APPROVAL", lambda: self.execute(tampered))
        wrong_key = ApprovalGateway(self.database, key=secrets.token_bytes(32), clock=self.clock)
        self.assert_code("INVALID_APPROVAL", lambda: wrong_key.execute(self.raw, context=self.requester, approval=token))

    def test_signed_but_unregistered_grant_is_denied(self):
        token = self.grant()
        signer = GrantSigner(self.key)
        payload = signer.verify(token)
        payload["grant_id"] = secrets.token_urlsafe(24)
        self.assert_code("UNKNOWN_APPROVAL", lambda: self.execute(signer.sign(payload)))

    def test_changed_policy_invalidates_an_old_grant(self):
        signer = GrantSigner(self.key)
        payload = signer.verify(self.grant())
        payload["policy_version"] = "policy-v0"
        self.assert_code("POLICY_CHANGED", lambda: self.execute(signer.sign(payload)))

    def test_malformed_tokens_fail_closed(self):
        for token in ("", "x", "a.b.c", "@@.@@", "a=.b=", "a.b", 123, b"a.b", "x" * 5000):
            with self.subTest(token_type=type(token)):
                self.assert_code("INVALID_APPROVAL", lambda: self.execute(token))

    def test_malformed_request_schema_is_rejected(self):
        mutations = [
            lambda d: d.update(extra="unknown"),
            lambda d: d.pop("version"),
            lambda d: d.update(version=True),
            lambda d: d.update(arguments=[]),
            lambda d: d["arguments"].update(delta=True),
            lambda d: d["arguments"].update(delta=1.0),
            lambda d: d["arguments"].update(delta=0),
            lambda d: d["arguments"].update(delta=101),
            lambda d: d["arguments"].update(reason=" "),
            lambda d: d["arguments"].update(reason="\ud800"),
            lambda d: d["arguments"].update(reason="\x00"),
            lambda d: d["arguments"].update(extra="unknown"),
            lambda d: d.update(principal_id="not a valid identity"),
        ]
        original = copy.deepcopy(self.document)
        for mutation in mutations:
            self.document = copy.deepcopy(original)
            mutation(self.document)
            with self.subTest(document=self.document):
                self.assert_code("INVALID_SCHEMA", self.execute)

    def test_nonstandard_duplicate_deep_and_oversize_json_is_rejected(self):
        examples = [
            ('{"a":1,"a":2}', "INVALID_JSON"),
            ('{"value":NaN}', "INVALID_JSON"),
            ('{"value":Infinity}', "INVALID_JSON"),
            ('[', "INVALID_JSON"),
            ('[' * 2000 + ']' * 2000, "INVALID_JSON"),
            ('"' + 'x' * 17000 + '"', "PAYLOAD_TOO_LARGE"),
            (b'\xff', "INVALID_JSON"),
            ({}, "INVALID_JSON"),
            ('[]', "INVALID_SCHEMA"),
        ]
        for raw, code in examples:
            with self.subTest(code=code):
                self.assert_code(code, lambda: self.gateway.execute(raw, context=self.requester))

    def test_concurrent_duplicates_commit_exactly_one_local_effect(self):
        token = self.grant()
        gateways = [ApprovalGateway(self.database, key=self.key, clock=self.clock) for _ in range(8)]
        barrier = threading.Barrier(len(gateways))

        def race(gateway):
            barrier.wait(timeout=10)
            try:
                return gateway.execute(self.raw, context=self.requester, approval=token)["status"]
            except GatewayError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(race, gateways))
        self.assertEqual(results.count("simulated_success"), 1)
        self.assertEqual(results.count("APPROVAL_REPLAY"), 7)
        self.assertEqual(self.rows("inventory")[0][2], 45)
        self.assertEqual(len(self.rows("executions")), 1)

    def test_partial_simulator_failure_rolls_back_effect_and_grant(self):
        token = self.grant()
        original = ApprovalGateway._simulate

        def fail_after_write(connection, action):
            original(connection, action)
            raise GatewayError("SIMULATOR_FAILURE", "Synthetic failure after a local write.")

        with patch.object(ApprovalGateway, "_simulate", side_effect=fail_after_write):
            self.assert_code("SIMULATOR_FAILURE", lambda: self.execute(token))
        self.assertEqual(self.rows("inventory"), [])
        self.assertEqual(self.rows("executions"), [])
        self.assertIsNone(self.rows("approvals")[0][2])
        self.assertEqual(self.execute(token)["status"], "simulated_success")

    def test_audit_write_failure_rolls_back_simulator_and_grant(self):
        token = self.grant()
        with patch.object(self.gateway._store, "append_audit", side_effect=sqlite3.OperationalError("synthetic audit failure")):
            with self.assertRaises(sqlite3.OperationalError):
                self.execute(token)
        self.assertEqual(self.rows("inventory"), [])
        self.assertEqual(self.rows("executions"), [])
        self.assertIsNone(self.rows("approvals")[0][2])

    def test_tenant_fixture_state_is_isolated(self):
        self.execute(self.grant())
        other = AccessContext("tenant-demo-b", "agent-demo-a", frozenset({"requester"}))
        self.document.update(tenant_id="tenant-demo-b", tool="catalog.lookup", arguments={"item_id": "item-demo-001"})
        result = self.gateway.execute(self.raw, context=other)
        self.assertEqual(result["result"]["quantity"], 40)

    def test_audit_requires_role_and_is_scoped_to_trusted_tenant(self):
        self.execute(self.grant())
        self.assert_code("FORBIDDEN", lambda: self.gateway.audit(context=self.requester))
        other_auditor = AccessContext("tenant-demo-b", "auditor-demo-b", frozenset({"auditor"}))
        self.assertEqual(self.gateway.audit(context=other_auditor), [])
        audit = json.dumps(self.gateway.audit(context=self.auditor))
        self.assertNotIn("Synthetic reconciliation", audit)
        self.assertNotIn("payload_json", audit)

    def test_notification_is_stored_only_in_the_local_simulator(self):
        self.document.update(tool="notifications.send", target="channel:channel-demo-ops",
                             arguments={"channel_id": "channel-demo-ops", "text": "Synthetic notification"})
        result = self.execute(self.grant())
        self.assertFalse(result["external_actions"])
        self.assertEqual(result["result"]["delivery"], "stored_locally_only")
        self.assertEqual(self.rows("simulated_messages")[0][3], "Synthetic notification")

    def test_invalid_business_state_does_not_consume_grant(self):
        self.document["arguments"]["delta"] = -100
        self.assert_code("INVALID_STATE", lambda: self.execute(self.grant()))
        self.assertIsNone(self.rows("approvals")[0][2])
        self.assertEqual(self.rows("executions"), [])

    def test_no_implicit_runtime_key(self):
        for key in (b"short", "x" * 32, b"x" * 129):
            self.assert_code("INVALID_KEY", lambda: ApprovalGateway(self.database, key=key))

    def test_mutating_plan_output_does_not_mutate_original_action(self):
        action = Action.parse(self.raw)
        doc = action.document
        doc["arguments"]["delta"] = 99
        self.assertEqual(action.document["arguments"]["delta"], 5)


if __name__ == "__main__":
    unittest.main()
