"""Strict, bounded input decoding and immutable trusted identity context."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

MAX_REQUEST_BYTES = 16_384
IDENTIFIER = re.compile(r"[a-z][a-z0-9_-]{2,63}\Z", re.ASCII)
ROLES = frozenset({"requester", "approver", "auditor"})
ITEMS = {"item-demo-001": 40, "item-demo-002": 12, "item-demo-003": 8}
CHANNELS = frozenset({"channel-demo-ops", "channel-demo-quality"})
TOOL_RISKS = {
    "catalog.lookup": "read_only",
    "inventory.adjust": "sensitive",
    "notifications.send": "sensitive",
}


class GatewayError(Exception):
    """Stable machine-readable refusal; messages never echo raw payloads."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def canonical_json(value: Any) -> str:
    """Project-local canonical form, deliberately not an RFC 8785 claim."""
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GatewayError("INVALID_JSON", "Duplicate object keys are not accepted.")
        result[key] = value
    return result


def _nonfinite(_: str) -> None:
    raise GatewayError("INVALID_JSON", "Non-finite numbers are not accepted.")


def decode_json(raw: str | bytes, *, max_bytes: int = MAX_REQUEST_BYTES) -> Any:
    if type(raw) not in (str, bytes):
        raise GatewayError("INVALID_JSON", "Expected UTF-8 JSON text.")
    try:
        encoded = raw.encode("utf-8") if isinstance(raw, str) else raw
        if len(encoded) > max_bytes:
            raise GatewayError("PAYLOAD_TOO_LARGE", "The request exceeds its byte limit.")
        value = json.loads(encoded.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_nonfinite)
        pending = [(value, 0)]
        while pending:
            node, depth = pending.pop()
            if depth > 8:
                raise GatewayError("INVALID_JSON", "JSON nesting exceeds the supported depth.")
            if type(node) is dict:
                pending.extend((child, depth + 1) for child in node.values())
            elif type(node) is list:
                pending.extend((child, depth + 1) for child in node)
        return value
    except (UnicodeError, ValueError, RecursionError) as error:
        raise GatewayError("INVALID_JSON", "Expected well-formed UTF-8 JSON.") from error


def exact_keys(value: Any, keys: set[str], *, code: str = "INVALID_SCHEMA") -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise GatewayError(code, "Object properties do not match the required schema.")
    return value


def identifier(value: Any, *, code: str = "INVALID_SCHEMA") -> str:
    if type(value) is not str or not IDENTIFIER.fullmatch(value):
        raise GatewayError(code, "Expected a bounded lowercase identifier.")
    return value


def bounded_text(value: Any, limit: int) -> str:
    if type(value) is not str or not 1 <= len(value) <= limit or not value.strip():
        raise GatewayError("INVALID_SCHEMA", "Expected nonempty bounded text.")
    # Reject lone surrogates, NUL, and control characters except ordinary text whitespace.
    if any((ord(char) < 32 and char not in "\n\r\t") or 0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise GatewayError("INVALID_SCHEMA", "Text contains unsupported control characters.")
    return value


@dataclass(frozen=True)
class AccessContext:
    """Construct from trusted authentication, never from an agent's request JSON."""

    tenant_id: str
    principal_id: str
    roles: frozenset[str]

    def __post_init__(self) -> None:
        identifier(self.tenant_id, code="INVALID_CONTEXT")
        identifier(self.principal_id, code="INVALID_CONTEXT")
        if type(self.roles) is not frozenset or not self.roles or not self.roles <= ROLES:
            raise GatewayError("INVALID_CONTEXT", "Context requires known immutable roles.")

    def require(self, role: str) -> None:
        if role not in self.roles:
            raise GatewayError("FORBIDDEN", "The trusted context lacks the required role.")


@dataclass(frozen=True)
class Action:
    # Store validated JSON, not a caller-owned mutable dictionary.
    canonical: str
    request_digest: str
    request_id: str
    tenant_id: str
    principal_id: str
    tool: str
    target: str
    risk: str

    @property
    def document(self) -> dict[str, Any]:
        return json.loads(self.canonical)

    @classmethod
    def parse(cls, raw: str | bytes) -> Action:
        obj = exact_keys(decode_json(raw), {
            "version", "request_id", "tenant_id", "principal_id", "tool", "target", "arguments",
        })
        if type(obj["version"]) is not int or obj["version"] != 1:
            raise GatewayError("INVALID_SCHEMA", "Only integer schema version 1 is supported.")
        for key in ("request_id", "tenant_id", "principal_id"):
            identifier(obj[key])
        tool = obj["tool"]
        if type(tool) is not str or tool not in TOOL_RISKS:
            raise GatewayError("UNKNOWN_TOOL", "The tool is outside the fixed allowlist.")
        args = obj["arguments"]
        if tool == "catalog.lookup":
            exact_keys(args, {"item_id"})
        elif tool == "inventory.adjust":
            exact_keys(args, {"item_id", "delta", "reason"})
            if type(args["delta"]) is not int or not -100 <= args["delta"] <= 100 or args["delta"] == 0:
                raise GatewayError("INVALID_SCHEMA", "Quantity delta must be a nonzero integer from -100 to 100.")
            bounded_text(args["reason"], 200)
        else:
            exact_keys(args, {"channel_id", "text"})
            bounded_text(args["text"], 1200)
        if tool in {"catalog.lookup", "inventory.adjust"}:
            if type(args["item_id"]) is not str or args["item_id"] not in ITEMS:
                raise GatewayError("TARGET_NOT_ALLOWED", "Only fixture item identifiers are allowed.")
            expected_target = "item:" + args["item_id"]
        else:
            if type(args["channel_id"]) is not str or args["channel_id"] not in CHANNELS:
                raise GatewayError("TARGET_NOT_ALLOWED", "Only fixture channel identifiers are allowed.")
            expected_target = "channel:" + args["channel_id"]
        if type(obj["target"]) is not str or obj["target"] != expected_target:
            raise GatewayError("TARGET_MISMATCH", "Target must exactly match the allowlisted argument target.")
        return cls(canonical_json(obj), digest(obj), obj["request_id"], obj["tenant_id"],
                   obj["principal_id"], tool, obj["target"], TOOL_RISKS[tool])

    def bind(self, context: AccessContext) -> None:
        context.require("requester")
        if self.tenant_id != context.tenant_id or self.principal_id != context.principal_id:
            raise GatewayError("IDENTITY_MISMATCH", "Action identity differs from the trusted context.")
