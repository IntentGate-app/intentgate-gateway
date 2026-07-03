"""IntentGate demo tool server.

A minimal HTTP-JSON-RPC service the gateway can forward to as
INTENTGATE_UPSTREAM_URL, so /v1/mcp returns real tool results
instead of the gateway's "stub: no upstream configured" placeholder.

The whole point: every demo / verify-session-N.sh in the IntentGate
project ended at "the gateway authorized this call, trust me bro."
With this upstream wired in, the demos now show authorization +
actual tool results, end-to-end.

Four mock tools, picked because they map cleanly to the existing
pitch scenarios:

  - read_invoice(id)         — basic read, used in most verify scripts
  - list_customers(limit)    — bulk read, returns PII-free customer profiles
  - read_customer(id|all)    — single-record read by id, or a deliberate
                               PII-bearing bulk pull when all=true. The
                               all=true branch is the LLM06 attack target:
                               policy denies it with a clear reason so the
                               lab card can demonstrate "bulk PII pull
                               blocked by policy" with a real deny code
                               rather than the historical -32601 "unknown
                               tool" workaround.
  - transfer_funds(...)      — high-risk write, the standard "escalate when
                               amount_eur > 5000" demo target

Tools return synthetic data, no DB connection required. The point
is to give the gateway something to forward to so the response body
is non-stub; the data itself is fixture.

# Protocol

JSON-RPC 2.0 over HTTP POST /. The gateway forwards the entire
JSON-RPC envelope from its /v1/mcp endpoint. We implement two
methods:

  - tools/list  : returns the static catalog
  - tools/call  : dispatches to the named tool

Unknown methods or unknown tool names return JSON-RPC errors with
the standard codes. Tool exceptions become CodeInternalError.

This file is deliberately self-contained (no separate handler
module, no database client, no auth) — the whole point is that the
demo upstream is a small understandable artifact someone can read
in one sitting. Production tool servers are a different shape.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(
    title="IntentGate demo tool server",
    description=(
        "Minimal HTTP-JSON-RPC tool server for demoing the IntentGate "
        "gateway end-to-end. Not for production use."
    ),
)

# ---------------------------------------------------------------------------
# Tool catalog
# ---------------------------------------------------------------------------

TOOLS: list[dict[str, Any]] = [
    {
        "name": "read_invoice",
        "description": "Read a single invoice by id.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Invoice id."},
            },
            "required": ["id"],
        },
    },
    {
        "name": "list_customers",
        "description": "List customer records, capped by limit.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Max records to return (1..100).",
                    "default": 10,
                },
            },
            "required": [],
        },
    },
    {
        "name": "read_customer",
        "description": (
            "Read a single customer record by id, including PII-bearing "
            "fields (national-ID equivalent, email, phone). The bulk "
            "branch (all=true) is intentionally PII-heavy and exists so "
            "the demo policy can hard-deny it as a bulk PII pull — "
            "supplying a specific id is the only policy-correct shape."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Customer id."},
                "all": {
                    "type": "boolean",
                    "description": (
                        "If true, return the full customer table including "
                        "PII. Intended as a footgun the policy layer denies."
                    ),
                    "default": False,
                },
            },
            "required": [],
        },
    },
    {
        "name": "transfer_funds",
        "description": (
            "Move money from one account to another. The demo policy "
            "in the pitch kit escalates this above 5,000 EUR."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "from_account": {"type": "string"},
                "to_account": {"type": "string"},
                "amount_eur": {
                    "type": "number",
                    "description": "Amount in EUR.",
                },
            },
            "required": ["from_account", "to_account", "amount_eur"],
        },
    },
    {
        "name": "create_payee",
        "description": (
            "Register a new payee / supplier that money can later be sent "
            "to. A procurement agent calls this before paying a brand-new "
            "vendor. Harmless on its own; the risk is the SEQUENCE "
            "create-a-supplier-then-pay-it in the same session (the "
            "invoice-fraud pattern), which the gateway's plan-level "
            "correlation catches even when each step is individually legal."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Payee / supplier name."},
                "iban": {"type": "string", "description": "Optional account / IBAN."},
            },
            "required": ["name"],
        },
    },
    {
        "name": "flaky_demo",
        "description": (
            "Controlled-failure tool used by the AGENT08 cascading-failure "
            "lab card. The caller sets `failure_mode` to force the tool "
            "server to return a real HTTP 5xx (502, 503, or 500) instead "
            "of a successful response. The gateway's fault-isolation "
            "breaker counts status >= 500 against the per-tool failure "
            "threshold; once the threshold is crossed, the breaker opens "
            "and subsequent calls fail fast at -32018 without ever "
            "contacting upstream. Used for live demos of the breaker "
            "opening on a degraded dependency."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "failure_mode": {
                    "type": "string",
                    "description": (
                        "One of 'ok' (default — synthetic success), "
                        "'502'/'bad_gateway', '503'/'unavailable', or "
                        "'500'/'internal_error'. Any 5xx mode causes the "
                        "tool server to return that HTTP status code, "
                        "which the gateway's breaker counts as a failure."
                    ),
                    "default": "ok",
                },
            },
            "required": [],
        },
    },
]


# Fixture data. read_invoice falls back to a synthetic invoice when
# the requested id isn't in this map, so the demo never 404s — the
# point is to demonstrate the gateway's authorization path, not to
# stress-test fixture lookups.
INVOICE_FIXTURES: dict[str, dict[str, Any]] = {
    "INV-1001": {
        "id": "INV-1001",
        "vendor": "Acme Office Supplies",
        "amount_eur": 1240.50,
        "due_date": "2026-05-30",
        "status": "open",
    },
    "INV-1002": {
        "id": "INV-1002",
        "vendor": "Globex Cloud Hosting",
        "amount_eur": 8900.00,
        "due_date": "2026-06-15",
        "status": "open",
    },
}

CUSTOMER_FIXTURES: list[dict[str, Any]] = [
    {"id": "CUST-1", "name": "Initech BV", "country": "NL", "tier": "enterprise"},
    {"id": "CUST-2", "name": "Hooli SARL", "country": "FR", "tier": "mid-market"},
    {"id": "CUST-3", "name": "Pied Piper Inc.", "country": "US", "tier": "startup"},
    {"id": "CUST-4", "name": "Massive Dynamic", "country": "GB", "tier": "enterprise"},
]

# PII-bearing customer records. Used ONLY by read_customer — deliberately
# kept separate from the PII-free CUSTOMER_FIXTURES (which list_customers
# uses) so the data-classification boundary is visible in the code. The
# national_id values are obviously synthetic but shaped to look like real
# identifiers (BSN-style for NL, INSEE for FR, SSN for US, NINO for GB)
# so the LLM06 demo's "dump all SSNs" framing has something concrete to
# point at when the policy layer blocks.
CUSTOMER_PII_FIXTURES: list[dict[str, Any]] = [
    {
        "id": "CUST-1",
        "name": "Initech BV",
        "country": "NL",
        "tier": "enterprise",
        "national_id": "BSN-123456782",
        "email": "ap@initech.example",
        "phone": "+31-30-555-0142",
    },
    {
        "id": "CUST-2",
        "name": "Hooli SARL",
        "country": "FR",
        "tier": "mid-market",
        "national_id": "INSEE-2730475108912",
        "email": "compta@hooli.example",
        "phone": "+33-1-5555-0188",
    },
    {
        "id": "CUST-3",
        "name": "Pied Piper Inc.",
        "country": "US",
        "tier": "startup",
        "national_id": "SSN-123-45-6789",
        "email": "finance@piedpiper.example",
        "phone": "+1-415-555-0193",
    },
    {
        "id": "CUST-4",
        "name": "Massive Dynamic",
        "country": "GB",
        "tier": "enterprise",
        "national_id": "NINO-AB123456C",
        "email": "accounts@massivedynamic.example",
        "phone": "+44-20-5555-0177",
    },
]


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def tool_read_invoice(args: dict[str, Any]) -> dict[str, Any]:
    """Return the invoice by id, falling back to a synthetic record
    so the demo doesn't 404 on unfamiliar ids."""
    invoice_id = str(args.get("id", "")).strip()
    if not invoice_id:
        raise ValueError("id is required")
    if invoice_id in INVOICE_FIXTURES:
        return INVOICE_FIXTURES[invoice_id]
    # Synthetic fallback so live demos with arbitrary ids still work.
    return {
        "id": invoice_id,
        "vendor": "Synthetic Vendor Corp.",
        "amount_eur": 999.00,
        "due_date": "2026-06-30",
        "status": "open",
        "_note": "synthetic record (id not in fixture map)",
    }


def tool_list_customers(args: dict[str, Any]) -> dict[str, Any]:
    """Return a slice of the customer fixture list. Clamps limit to
    [1, 100]; the upper bound keeps demo responses from getting huge."""
    raw = args.get("limit", 10)
    try:
        limit = int(raw)
    except (TypeError, ValueError):
        limit = 10
    limit = max(1, min(limit, 100))
    return {"customers": CUSTOMER_FIXTURES[:limit], "total": len(CUSTOMER_FIXTURES)}


def tool_read_customer(args: dict[str, Any]) -> dict[str, Any]:
    """Return a single PII-bearing customer record by id, or — if
    all=true — the full PII table.

    The all=true branch exists so the LLM06 lab card has a concrete
    deny target: bulk PII pulls are denied by the baseline policy, and
    we want the gateway's deny code (not -32601 "unknown tool") to be
    what stops the call. In production a tool exposing both shapes
    would be a footgun; the lab keeps it deliberately so the demo can
    show the policy layer doing real work."""
    if bool(args.get("all", False)):
        # This branch should be unreachable when the baseline policy is
        # loaded — included so a misconfigured deployment surfaces the
        # PII clearly rather than silently returning an empty result.
        return {
            "customers": CUSTOMER_PII_FIXTURES,
            "total": len(CUSTOMER_PII_FIXTURES),
            "_warning": (
                "bulk PII pull executed — policy layer failed to deny. "
                "Check baseline.rego is loaded and the read_customer "
                "rule is present."
            ),
        }
    customer_id = str(args.get("id", "")).strip()
    if not customer_id:
        raise ValueError("id is required when all=true is not set")
    match = next(
        (c for c in CUSTOMER_PII_FIXTURES if c["id"] == customer_id),
        None,
    )
    if match is None:
        # Synthetic fallback, mirrors read_invoice. PII-free because
        # synthetic — no leak in this branch even if reached unexpectedly.
        return {
            "id": customer_id,
            "name": "Synthetic Customer",
            "country": "NL",
            "tier": "unknown",
            "_note": "synthetic record (id not in fixture map)",
        }
    return match


class FlakyToolFailure(Exception):
    """Raised by tool_flaky_demo to force a specific HTTP status code
    out of the JSON-RPC handler. The gateway's fault-isolation breaker
    counts upstream HTTP status >= 500 as a failure, so the AGENT08
    cascading-failure lab card needs an upstream that can return a real
    5xx rather than a JSON-RPC application error. This exception is the
    signalling channel between the tool function (which decides the
    failure mode based on its args) and the handler (which writes the
    HTTP response with the chosen status code)."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(message)


def tool_flaky_demo(args: dict[str, Any]) -> dict[str, Any]:
    """Controlled-failure tool for the AGENT08 cascading-failure
    lab card. Stateless by design — the caller decides per-call
    whether to fail and which 5xx to return, so the demo flow is
    deterministic and replayable. Set failure_mode=502/503/500 to
    raise FlakyToolFailure (which the handler turns into a real
    HTTP 5xx response, which the gateway's breaker counts as a
    failure for the per-tool failure threshold). Set failure_mode=ok
    (or omit) to return a synthetic success — used as the half-open
    probe at the end of a demo, to show the breaker closing again
    once the dependency recovers."""
    mode = str(args.get("failure_mode", "ok")).lower().strip()
    if mode in ("502", "bad_gateway"):
        raise FlakyToolFailure(502, "synthetic 502 from flaky_demo")
    if mode in ("503", "unavailable", "service_unavailable"):
        raise FlakyToolFailure(503, "synthetic 503 from flaky_demo")
    if mode in ("500", "internal", "internal_error"):
        raise FlakyToolFailure(500, "synthetic 500 from flaky_demo")
    return {
        "ok": True,
        "tool": "flaky_demo",
        "failure_mode": mode,
        "_note": (
            "set failure_mode=502|503|500 to force a real HTTP 5xx, "
            "which the gateway's AGENT08 breaker counts as a failure"
        ),
    }


def tool_transfer_funds(args: dict[str, Any]) -> dict[str, Any]:
    """Return a 'would-transfer' acknowledgement. The DEMO doesn't
    move real money — this is a deliberately stubbed return so the
    pitch can show the gateway's policy + escalation behavior without
    needing a real banking integration. Production tool servers
    obviously would do the actual transfer here."""
    src = str(args.get("from_account", "")).strip()
    dst = str(args.get("to_account", "")).strip()
    try:
        amount = float(args.get("amount_eur", 0))
    except (TypeError, ValueError):
        amount = 0.0
    if not src or not dst:
        raise ValueError("from_account and to_account are required")
    if amount <= 0:
        raise ValueError("amount_eur must be > 0")
    return {
        "ok": True,
        "from_account": src,
        "to_account": dst,
        "amount_eur": amount,
        "reference": f"DEMO-TX-{abs(hash((src, dst, amount))) % 100000:05d}",
        "_note": "demo tool — no real banking integration",
    }


def tool_create_payee(args: dict[str, Any]) -> dict[str, Any]:
    """Register a new payee/supplier and return a synthetic ack. The demo
    persists nothing — the point is that this OpCreate is what the
    gateway's plan-level correlation records, so a later payment to the
    same party (the invoice-fraud pattern) can be caught and held even
    though creating a supplier and paying a supplier are each legal on
    their own. Production tool servers would write to the vendor master."""
    name = str(args.get("name", "")).strip()
    if not name:
        raise ValueError("name is required")
    iban = str(args.get("iban", "")).strip()
    return {
        "ok": True,
        "payee": name,
        "iban": iban or f"DEMO-IBAN-{abs(hash(name)) % 100000:05d}",
        "status": "registered",
        "_note": "demo tool — no real vendor-master update",
    }


TOOL_DISPATCH = {
    "read_invoice": tool_read_invoice,
    "list_customers": tool_list_customers,
    "read_customer": tool_read_customer,
    "transfer_funds": tool_transfer_funds,
    "create_payee": tool_create_payee,
    "flaky_demo": tool_flaky_demo,
}


# ---------------------------------------------------------------------------
# JSON-RPC handler
# ---------------------------------------------------------------------------

# JSON-RPC 2.0 error codes the gateway expects.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


def _error(req_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    """Build a JSON-RPC error response."""
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _result(req_id: Any, result: Any) -> dict[str, Any]:
    """Build a JSON-RPC success response. The MCP convention wraps
    tool results in {content: [...], isError: false}, which the
    gateway forwards verbatim. We match that shape so the gateway
    doesn't have to special-case our responses."""
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "content": [
                {"type": "text", "text": _stringify(result)},
            ],
            "isError": False,
            "_data": result,  # convenience: clients that prefer structured data can use this
        },
    }


def _stringify(value: Any) -> str:
    """Render a tool result into the human-readable text content
    field. For the demo we just dump the structured result; a real
    tool server might pretty-print or summarize."""
    import json

    try:
        return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return str(value)


@app.post("/")
async def jsonrpc(request: Request) -> JSONResponse:
    """JSON-RPC 2.0 endpoint. Dispatches on method:

      - tools/list : returns the static catalog
      - tools/call : invokes the named tool

    Unknown methods return METHOD_NOT_FOUND. Tool exceptions are
    surfaced as INTERNAL_ERROR with the exception's message in the
    error.data field so the gateway can surface it cleanly."""
    try:
        body = await request.json()
    except Exception as exc:
        return JSONResponse(
            content=_error(None, PARSE_ERROR, "parse error", str(exc)),
            status_code=400,
        )

    req_id = body.get("id")
    method = body.get("method", "")
    params = body.get("params") or {}

    if body.get("jsonrpc") != "2.0":
        return JSONResponse(
            content=_error(req_id, INVALID_REQUEST, "jsonrpc must be '2.0'"),
            status_code=400,
        )

    if method == "tools/list":
        return JSONResponse(content=_result(req_id, {"tools": TOOLS}))

    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments") or {}
        fn = TOOL_DISPATCH.get(name)
        if fn is None:
            return JSONResponse(
                content=_error(req_id, METHOD_NOT_FOUND, f"unknown tool: {name}"),
            )
        try:
            return JSONResponse(content=_result(req_id, fn(args)))
        except FlakyToolFailure as exc:
            # tool_flaky_demo signals a forced HTTP-level failure here.
            # The gateway's fault-isolation breaker counts upstream
            # status >= 500 toward the per-tool failure threshold —
            # this is the codepath the AGENT08 lab card exercises.
            return JSONResponse(
                content=_error(req_id, INTERNAL_ERROR, exc.message),
                status_code=exc.status_code,
            )
        except ValueError as exc:
            return JSONResponse(
                content=_error(req_id, INVALID_PARAMS, str(exc)),
            )
        except Exception as exc:  # noqa: BLE001 — last-resort wrap
            return JSONResponse(
                content=_error(req_id, INTERNAL_ERROR, "tool error", str(exc)),
            )

    return JSONResponse(content=_error(req_id, METHOD_NOT_FOUND, f"unknown method: {method}"))


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    """Match the gateway's healthz shape so the helm chart's
    liveness/readiness probes work the same way."""
    return {"status": "ok", "version": os.getenv("DEMO_TOOLSERVER_VERSION", "0.1.0")}
