# Integration guide

The reference has three boundaries: untrusted action JSON, trusted execution identity, and a separately trusted approval workflow. Keep those boundaries explicit in your product.

## Run the small example

```sh
PYTHONPATH=src python3 examples/integration.py
```

The example uses a temporary local database and generates a runtime key. It creates trusted synthetic contexts to demonstrate wiring; it does not authenticate a real person or expose a server.

## 1. Establish identity outside the model

Authenticate your application caller using your own session or service identity system. Derive tenant, principal, and roles from trusted authorization state. Do not accept them from model output, query parameters, or an unsigned client object. The request repeats tenant and principal so the gateway can reject a mismatch.

```python
requester = AccessContext(
    tenant_id="tenant-demo-a",
    principal_id="agent-demo-a",
    roles=frozenset({"requester"}),
)
```

These literals are synthetic examples. In a product, a verified adapter supplies them. Caller code and imports run in the trusted process; Python object construction itself provides no security boundary.

## 2. Validate and show the exact plan

`gateway.plan(request_json, context=requester)` returns the exact arguments, target, risk, policy version, and request digest. Validation failures raise `GatewayError` with a stable `code`. The method does not write an audit event, consume a grant, reserve a request ID, or change a fixture. Gateway construction initializes its configured SQLite database.

For sensitive actions, display the complete plan to the approver in an authenticated interface. Treat arguments as text and label them as untrusted content. Do not ask the model to summarize the action as the sole basis for approval. The browser report in this repository uses `textContent` and script-safe JSON embedding for this reason.

The machine-readable [action schema](action.schema.json) describes the request shape and allowed targets. The Python parser additionally enforces byte size, nesting depth, duplicate-key rejection, Unicode/control-character restrictions, and target agreement; it is the executable validation authority.

## 3. Issue approval only through the trusted route

Instantiate `ApprovalAuthority` behind an independently authenticated approval endpoint. Confirm the approver has the current required role and belongs to the action's tenant. This implementation rejects self-approval even when a principal has both roles.

```python
token = authority.issue(
    request_json,
    requester=requester,
    approver=approver,
    ttl_seconds=120,
)
```

Do not register this method as an agent-callable tool. Do not return a signing key to the agent, browser, or report. The runtime accepts 32–128 key bytes; obtain them from your secret manager or another protected runtime source. There is no fallback, hardcoded production key, or persistent demo key. Generating a new key on every service restart invalidates outstanding grants; a real service must choose and document its key lifecycle.

HMAC is symmetric: any verifier holding the secret can sign. If organizational separation between issuer and verifier is required, replace the signature design with a reviewed asymmetric protocol and protected key management. Merely splitting these Python classes does not isolate their privileges.

## 4. Execute the unchanged request

```python
result = gateway.execute(request_json, context=requester, approval=token)
```

The gateway revalidates the request, binds the trusted identity, checks the signature and exact request binding, obtains the SQLite write lock, checks expiry and the stored grant, and rejects any consumed grant or repeated tenant/request ID. Local simulator mutation, consumption, result persistence, and success audit commit together. A simulator or audit-write failure rolls back the transaction. The code does not catch storage errors and continue dispatch; the caller must treat any exception as a failed operation.

`catalog.lookup` needs no token. Supplying a token to a read-only call is rejected to avoid ambiguous grant handling. `inventory.adjust` and `notifications.send` always need approval. Fixed simulator dispatch deliberately has no dynamic imports, arbitrary handler name resolution, network target, filesystem path, or command string.

## 5. Read scoped evidence

Only an `AccessContext` containing the `auditor` role can call `gateway.audit(context=...)`. The method always filters by the trusted context's tenant. Success events contain bounded action metadata and a request digest; rejection events contain the trusted caller and refusal code, without the rejected payload's claimed identity or arguments. IDs, targets, and digests can still be sensitive in a real system.

Audit rows are ordinary SQLite records. Protect database access and export to an independently protected audit sink if your system needs stronger integrity, retention, or operator accountability. Never treat a locally generated HTML report as an immutable security record.

## Moving beyond the simulator

Do not copy `_simulate` and insert a remote call inside its transaction while claiming atomic external effects. A database rollback cannot undo a request already accepted by another service. A lost response also does not establish that an action failed.

A real connector needs a deliberate protocol, such as durable approval reservation and outbox dispatch, a target-supported idempotency key, persistent outcome states, and reconciliation of unknown results. If you consume approval before dispatch without retry, you can achieve at-most-once dispatch at the cost of lost actions after crashes. If you retry, target-side idempotency or reconciliation is needed to prevent duplicates. Choose these semantics for the tool's actual risk and failure model.

Also enforce current authorization and resource ownership at dispatch, isolate connector credentials by tenant, restrict outbound targets, bound response size and execution time, protect the signing key and durable replay store, and define revocation and restore behavior. The reference has no service endpoints or transport-level authentication; those belong in the integrating product.

## Refusal codes used in the demo

| Code | Meaning |
| --- | --- |
| `APPROVAL_REQUIRED` | Sensitive action has no token |
| `APPROVAL_MISMATCH` | Token is bound to another exact action |
| `APPROVAL_REPLAY` | Grant was consumed in a committed transaction |
| `APPROVAL_EXPIRED` | Current time is at or after exclusive expiry |
| `IDENTITY_MISMATCH` | Trusted caller and request identity differ |
| `INVALID_APPROVAL` | Token encoding, signature, or payload is invalid |
| `UNKNOWN_TOOL` | Requested tool is outside the fixed allowlist |
| `INVALID_SCHEMA` | Types, fields, or bounded values are invalid |
| `SELF_APPROVAL` | Requester and approver are the same principal |

Other refusal codes cover malformed JSON, unsupported targets, duplicate request IDs, missing roles, changed policy, unregistered grants, and invalid local fixture state. Integrations should branch on codes and avoid exposing exception internals or secrets.
