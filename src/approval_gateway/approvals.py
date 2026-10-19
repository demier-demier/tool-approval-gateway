"""Trusted approval issuance, separated from the tool execution API."""

from __future__ import annotations

import base64
import hmac
import re
import secrets
import time
from pathlib import Path
from typing import Any, Callable

from .models import AccessContext, Action, GatewayError, canonical_json, decode_json, exact_keys, identifier, TOOL_RISKS
from .storage import Store

POLICY_VERSION = "policy-v1"
MAX_TTL_SECONDS = 300
GRANT_KEYS = {
    "version", "policy_version", "grant_id", "issued_at", "expires_at", "request_digest",
    "tenant_id", "principal_id", "tool", "target", "approver_id",
}
_B64URL = re.compile(r"[A-Za-z0-9_-]+\Z", re.ASCII)
_HEX = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)


def system_clock() -> int:
    return int(time.time())


def checked_time(clock: Callable[[], int]) -> int:
    now = clock()
    if type(now) is not int or not 0 <= now < 2**63 - MAX_TTL_SECONDS:
        raise GatewayError("CLOCK_ERROR", "Clock must return a nonnegative integer Unix timestamp.")
    return now


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    if not _B64URL.fullmatch(value):
        raise GatewayError("INVALID_APPROVAL", "Approval encoding is invalid.")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as error:
        raise GatewayError("INVALID_APPROVAL", "Approval encoding is invalid.") from error
    if _encode(decoded) != value:
        raise GatewayError("INVALID_APPROVAL", "Approval encoding is not canonical.")
    return decoded


class GrantSigner:
    """HMAC assumes issuer and verifier are trusted holders of the same secret."""

    def __init__(self, key: bytes):
        if type(key) is not bytes or not 32 <= len(key) <= 128:
            raise GatewayError("INVALID_KEY", "Supply 32 to 128 runtime key bytes from a secure secret source.")
        self._key = key

    def sign(self, payload: dict[str, Any]) -> str:
        encoded = _encode(canonical_json(payload).encode("ascii"))
        signature = hmac.digest(self._key, encoded.encode("ascii"), "sha256")
        return encoded + "." + _encode(signature)

    def verify(self, token: str) -> dict[str, Any]:
        if type(token) is not str or len(token) > 4096 or token.count(".") != 1:
            raise GatewayError("INVALID_APPROVAL", "Expected a bounded signed approval token.")
        encoded, signature = token.split(".")
        raw = _decode(encoded)
        supplied = _decode(signature)
        expected = hmac.digest(self._key, encoded.encode("ascii"), "sha256")
        if not hmac.compare_digest(supplied, expected):
            raise GatewayError("INVALID_APPROVAL", "Approval signature does not verify.")
        try:
            payload = exact_keys(decode_json(raw, max_bytes=3072), GRANT_KEYS, code="INVALID_APPROVAL")
        except GatewayError as error:
            raise GatewayError("INVALID_APPROVAL", "Approval payload is invalid.") from error
        if canonical_json(payload).encode("ascii") != raw:
            raise GatewayError("INVALID_APPROVAL", "Approval payload is not canonical.")
        if type(payload["version"]) is not int or payload["version"] != 1:
            raise GatewayError("INVALID_APPROVAL", "Approval version is unsupported.")
        if payload["policy_version"] != POLICY_VERSION:
            raise GatewayError("POLICY_CHANGED", "Approval was issued under another policy version.")
        for key in ("issued_at", "expires_at"):
            if type(payload[key]) is not int or not 0 <= payload[key] < 2**63:
                raise GatewayError("INVALID_APPROVAL", "Approval timestamps are invalid.")
        if not 1 <= payload["expires_at"] - payload["issued_at"] <= MAX_TTL_SECONDS:
            raise GatewayError("INVALID_APPROVAL", "Approval lifetime is invalid.")
        for key in GRANT_KEYS - {"version", "issued_at", "expires_at"}:
            if type(payload[key]) is not str:
                raise GatewayError("INVALID_APPROVAL", "Approval fields have invalid types.")
        if not _HEX.fullmatch(payload["request_digest"]) or not _B64URL.fullmatch(payload["grant_id"]):
            raise GatewayError("INVALID_APPROVAL", "Approval identifiers are invalid.")
        for key in ("tenant_id", "principal_id", "approver_id"):
            identifier(payload[key], code="INVALID_APPROVAL")
        if payload["tool"] not in TOOL_RISKS or not payload["target"].isascii():
            raise GatewayError("INVALID_APPROVAL", "Approval tool or target is invalid.")
        return payload


class ApprovalAuthority:
    """Expose only behind a separately authenticated approver endpoint or workflow.

    The agent's execution API must never expose this method. Roles in AccessContext
    are assertions from your authentication layer, not credentials or authentication.
    """

    def __init__(self, database: str | Path, *, key: bytes, clock: Callable[[], int] = system_clock):
        self._signer = GrantSigner(key)
        self._store = Store(database)
        self._clock = clock

    def issue(self, raw: str | bytes, *, requester: AccessContext, approver: AccessContext,
              ttl_seconds: int = 120) -> str:
        try:
            action = Action.parse(raw)
            action.bind(requester)
            approver.require("approver")
            if approver.tenant_id != action.tenant_id:
                raise GatewayError("APPROVER_TENANT_MISMATCH", "Approver must belong to the action's tenant.")
            if approver.principal_id == action.principal_id:
                raise GatewayError("SELF_APPROVAL", "A distinct principal must approve the action.")
            if action.risk != "sensitive":
                raise GatewayError("APPROVAL_NOT_REQUIRED", "This tool does not require an approval grant.")
            if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
                raise GatewayError("INVALID_TTL", "Approval lifetime must be an integer from 1 to 300 seconds.")
            with self._store.transaction() as connection:
                now = checked_time(self._clock)
                if connection.execute("SELECT 1 FROM executions WHERE tenant_id = ? AND request_id = ?",
                                      (action.tenant_id, action.request_id)).fetchone():
                    raise GatewayError("REQUEST_REPLAY", "This tenant request identifier has already executed.")
                payload = {
                    "version": 1, "policy_version": POLICY_VERSION,
                    "grant_id": secrets.token_urlsafe(24), "issued_at": now,
                    "expires_at": now + ttl_seconds, "request_digest": action.request_digest,
                    "tenant_id": action.tenant_id, "principal_id": action.principal_id,
                    "tool": action.tool, "target": action.target, "approver_id": approver.principal_id,
                }
                token = self._signer.sign(payload)
                connection.execute("INSERT INTO approvals (grant_id, payload_json) VALUES (?, ?)",
                                   (payload["grant_id"], canonical_json(payload)))
                self._store.append_audit(connection, now, approver, "approval_issued", "APPROVED", action)
            return token
        except GatewayError as error:
            self._store.record_rejection(checked_time(self._clock), approver, error.code)
            raise
