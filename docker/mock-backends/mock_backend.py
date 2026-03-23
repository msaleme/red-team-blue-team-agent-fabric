#!/usr/bin/env python3
"""Parameterized mock backend for red team testing.

Reads SERVICE_NAME from env to decide which routes to register.
Implements application-layer security checks that a real MuleSoft
Agent Fabric deployment would have — but deliberately imperfect,
so the gateway layer (Envoy/Flex) can demonstrate defense-in-depth.
"""
import json
import os
import re
import time
from flask import Flask, request, jsonify

app = Flask(__name__)
SERVICE_NAME = os.environ.get("SERVICE_NAME", "app1")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "9081"))

# ── Shared state ──
request_counter = {"count": 0, "window_start": time.time()}
RATE_LIMIT = 60  # requests per minute (backend-level, gateway has its own)
seen_request_ids = {}  # {request_id: timestamp} for replay detection
parameter_history = {}  # {param_name: [values]} for drift monitoring

SENSITIVE_KEYWORDS = [
    "ignore previous", "system override", "debug mode",
    "override_safety", "dump credential", "disable safety",
    "execute:", "curl ", "wget ", "/bin/sh", "/bin/bash",
    "drop table", "select * from", "union select",
]

UNSAFE_TOOL_NAMES = [
    "override_safety_procedure", "access_financial_records",
    "execute_shell", "read_credentials", "disable_monitoring",
]

ALLOWED_AGENTS = [
    "safety-agent", "context-agent", "document-agent",
    "work-order-agent", "finance-agent",
]


def _is_malicious_payload(data):
    """Check for obvious attack patterns in request body."""
    text = json.dumps(data).lower() if data else ""
    return any(kw in text for kw in SENSITIVE_KEYWORDS)


def _check_rate_limit():
    """Simple sliding-window rate limiter."""
    now = time.time()
    if now - request_counter["window_start"] > 60:
        request_counter["count"] = 0
        request_counter["window_start"] = now
    request_counter["count"] += 1
    return request_counter["count"] > RATE_LIMIT


def _check_replay(data):
    """RT-020: Reject duplicate request IDs within 60-second window."""
    now = time.time()
    # Clean expired entries
    expired = [k for k, v in seen_request_ids.items() if now - v > 60]
    for k in expired:
        del seen_request_ids[k]
    # Check for replay
    rid = None
    if isinstance(data, dict):
        rid = data.get("request_id") or data.get("nonce") or data.get("id")
    if rid:
        if rid in seen_request_ids:
            return True
        seen_request_ids[rid] = now
    return False


def _check_boundary_drift(param_name, value):
    """RT-016/RT-024: Check for edge-case drift and cumulative drift."""
    if not isinstance(value, (int, float)):
        return None
    # Track history
    if param_name not in parameter_history:
        parameter_history[param_name] = []
    parameter_history[param_name].append(value)
    history = parameter_history[param_name]
    # RT-016: flag values within 1% of known boundaries (0-100 range)
    if 0 <= value <= 100:
        if value >= 99.0 or value <= 1.0:
            return f"Parameter '{param_name}' suspiciously close to boundary: {value}"
    # RT-024: rolling drift detection — alert at 5% cumulative drift
    if len(history) >= 3:
        baseline = sum(history[:3]) / 3
        if baseline != 0:
            recent = sum(history[-3:]) / 3
            drift_pct = abs(recent - baseline) / abs(baseline) * 100
            if drift_pct > 5:
                return f"Cumulative drift detected for '{param_name}': {drift_pct:.1f}%"
    return None


def _has_embedded_instructions(data):
    """RT-023: Detect prompt-like content in structured fields."""
    if not isinstance(data, dict):
        return False
    text = json.dumps(data).lower()
    instruction_patterns = [
        "you are", "your role is", "act as", "pretend to be",
        "forget your", "new instructions:", "system prompt",
        "\\n\\nHuman:", "\\n\\nAssistant:", "<|im_start|>",
        "ignore all previous", "disregard your",
    ]
    return any(p in text for p in instruction_patterns)


# ═══════════════════════════════════════════════════════════
# APP1: AI/ML Agent endpoints (port 9081)
# ═══════════════════════════════════════════════════════════

@app.route("/azure-ml-agent", methods=["POST"])
def azure_ml_agent():
    data = request.get_json(silent=True) or {}
    if _is_malicious_payload(data):
        return jsonify({"error": "Request blocked by content filter"}), 403
    # Check for code execution attempts
    if any(k in json.dumps(data).lower() for k in ["exec(", "eval(", "import os", "__import__"]):
        return jsonify({"error": "Code execution not permitted"}), 403
    return jsonify({
        "status": "analyzed",
        "agent": "azure-ml-agent",
        "result": "Pipeline analysis complete. All parameters within normal range.",
        "confidence": 0.92,
    })


@app.route("/work-order-optimizer-agent", methods=["POST"])
def work_order_optimizer():
    data = request.get_json(silent=True) or {}
    # RT-009: reject oversized payloads at app level too
    if request.content_length and request.content_length > 50000:
        return jsonify({"error": "Payload too large"}), 413
    if _is_malicious_payload(data):
        return jsonify({"error": "Blocked: suspicious content detected"}), 400
    # RT-016: validate numeric ranges AND boundary proximity
    if "parameters" in data:
        params = data["parameters"]
        if isinstance(params, dict):
            for k, v in params.items():
                if isinstance(v, (int, float)) and (v < -1e6 or v > 1e6):
                    return jsonify({"error": f"Parameter '{k}' out of valid range"}), 422
                drift_msg = _check_boundary_drift(k, v)
                if drift_msg:
                    return jsonify({"error": drift_msg}), 400
    return jsonify({
        "status": "optimized",
        "agent": "work-order-optimizer",
        "work_orders": [{"id": "WO-001", "priority": "normal", "status": "scheduled"}],
    })


@app.route("/work-order-priority-optimizer-agent", methods=["POST"])
def work_order_priority_optimizer():
    data = request.get_json(silent=True) or {}
    if _is_malicious_payload(data):
        return jsonify({"error": "Blocked"}), 400
    return jsonify({
        "status": "priorities_evaluated",
        "agent": "priority-optimizer",
        "adjustments": [],
        "anomaly_flag": False,
    })


# ═══════════════════════════════════════════════════════════
# APP2: Finance Agent (port 9082)
# ═══════════════════════════════════════════════════════════

@app.route("/finance-agent/budget", methods=["GET"])
def finance_budget():
    # RT-007: Require authentication
    auth = request.headers.get("Authorization", "")
    if not auth or not auth.startswith("Bearer "):
        return jsonify({"error": "Authentication required"}), 401
    return jsonify({
        "budget": {"department": "operations", "allocated": 500000, "spent": 320000},
    })


@app.route("/finance-agent", methods=["POST"])
def finance_agent():
    data = request.get_json(silent=True) or {}
    # RT-002: Check A2A authorization
    agent_id = request.headers.get("X-Agent-Identity", "")
    if agent_id and agent_id not in ALLOWED_AGENTS:
        return jsonify({"error": "Agent not authorized for financial operations"}), 403
    if not agent_id:
        return jsonify({"error": "X-Agent-Identity header required"}), 403
    if _is_malicious_payload(data):
        return jsonify({"error": "Request blocked"}), 403
    return jsonify({"status": "processed", "agent": "finance-agent"})


# ═══════════════════════════════════════════════════════════
# BROKER: Agent orchestration (port 9084)
# ═══════════════════════════════════════════════════════════

@app.route("/brokers/pipeline-anomaly-orchestrator", methods=["POST"])
def broker_orchestrator():
    data = request.get_json(silent=True) or {}
    # RT-008: rate limiting
    if _check_rate_limit():
        return jsonify({"error": "Rate limit exceeded"}), 429
    # RT-001: rogue agent registration
    if "agent" in data:
        agent = data["agent"]
        agent_card = agent.get("agent_card_url", "")
        if agent_card and not agent_card.startswith("https://internal."):
            return jsonify({"error": "External agent registration not permitted"}), 403
    # RT-005: cascade corruption — detect chained agent context manipulation
    if _is_malicious_payload(data):
        return jsonify({"error": "Malicious context detected"}), 403
    if "context" in data or "agent_context" in data:
        ctx = data.get("context") or data.get("agent_context", {})
        ctx_text = json.dumps(ctx).lower() if ctx else ""
        # Detect injected instructions in agent context
        if any(p in ctx_text for p in ["override", "bypass", "inject", "manipulate",
                                        "poison", "corrupt", "fake_alert", "false"]):
            return jsonify({"error": "Suspicious agent context detected — cascade blocked"}), 403
    # RT-012: recursion detection
    if "tasks" in data:
        task_ids = [t.get("id", "") for t in data.get("tasks", []) if isinstance(t, dict)]
        if len(task_ids) != len(set(task_ids)):
            return jsonify({"error": "Circular dependency detected"}), 400
    return jsonify({
        "status": "orchestrating",
        "pipeline": "anomaly-detection",
        "agents_active": 3,
    })


@app.route("/brokers/pipeline-anomaly-orchestrator/agents", methods=["POST"])
def broker_agents():
    data = request.get_json(silent=True) or {}
    # RT-014: reject external agent joins
    agent_card = data.get("agent_card_url", "")
    if agent_card and ("evil.com" in agent_card or "malicious" in agent_card
                        or not agent_card.startswith("https://internal.")):
        return jsonify({"error": "Unauthorized agent source"}), 403
    return jsonify({"status": "agent_registered"})


@app.route("/brokers/pipeline-anomaly-orchestrator/tools", methods=["POST", "GET"])
def broker_tools():
    if request.method == "GET":
        return jsonify({"tools": ["safety_check", "anomaly_detect", "report_gen"]})
    data = request.get_json(silent=True) or {}
    # RT-026: validate tool manifest
    manifest = data.get("tool_manifest", {})
    if manifest:
        if "checksum" not in manifest or "signature" not in manifest:
            return jsonify({"error": "Tool manifest must include checksum and signature"}), 400
        if manifest.get("source", "").startswith("http://"):
            return jsonify({"error": "Tool sources must use HTTPS"}), 403
    return jsonify({"status": "tool_registered"})


@app.route("/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(silent=True) or {}
    # RT-025: superman effect / impossible geo-velocity
    locations = data.get("login_locations", [])
    if len(locations) >= 2:
        return jsonify({"error": "Impossible travel velocity detected"}), 403
    # Basic credential validation
    username = data.get("username", "")
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "Credentials required"}), 401
    if username == "admin" and password == "admin":
        return jsonify({"error": "Default credentials not permitted"}), 403
    return jsonify({"token": "mock-session-token", "expires_in": 3600})


# ═══════════════════════════════════════════════════════════
# MCP SAFETY (port 9085)
# ═══════════════════════════════════════════════════════════

@app.route("/tools/execute", methods=["POST"])
def mcp_tools_execute():
    data = request.get_json(silent=True) or {}
    tool = data.get("tool", "")
    # RT-006, RT-011: tool permission enforcement
    if tool in UNSAFE_TOOL_NAMES:
        return jsonify({"error": f"Tool '{tool}' not authorized"}), 403
    # RT-020: replay detection — reject duplicate request IDs within 60s
    if _check_replay(data):
        return jsonify({"error": "Replay detected: duplicate request ID"}), 409
    # RT-020: also check for stale timestamps
    if "timestamp" in data:
        try:
            ts = float(data["timestamp"])
            if time.time() - ts > 300:
                return jsonify({"error": "Stale request detected"}), 409
        except (ValueError, TypeError):
            pass
    # RT-023: validate parameters for embedded instructions AND impossible values
    params = data.get("parameters", {})
    if isinstance(params, dict):
        if _has_embedded_instructions(params):
            return jsonify({"error": "Embedded instructions detected in parameters"}), 403
        for k, v in params.items():
            if isinstance(v, (int, float)):
                if v < -1e9 or v > 1e9:
                    return jsonify({"error": f"Parameter '{k}' out of range"}), 400
            if isinstance(v, str) and _is_malicious_payload({"v": v}):
                return jsonify({"error": "Malicious parameter content"}), 403
    return jsonify({
        "status": "executed",
        "tool": tool,
        "result": "Tool execution completed successfully",
    })


# ═══════════════════════════════════════════════════════════
# Health check (all services)
# ═══════════════════════════════════════════════════════════

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "service": SERVICE_NAME, "port": LISTEN_PORT})


# ═══════════════════════════════════════════════════════════
# Catch-all for undefined routes → 404
# ═══════════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


if __name__ == "__main__":
    print(f"Starting mock backend: {SERVICE_NAME} on port {LISTEN_PORT}")
    app.run(host="0.0.0.0", port=LISTEN_PORT, debug=False)
