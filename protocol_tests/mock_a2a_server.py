#!/usr/bin/env python3
"""A minimal A2A JSON-RPC target for labs, CI and the harness's own controls.

Speaks A2A 0.3, 1.0, or both, and runs in one of two modes:

    hardened    rejects what the A2A-004/005/007/008/009/010/011 attacks send
    vulnerable  accepts it, so the same tests can be seen to FAIL

A target that only ever produces PASS cannot show that a test works, so both
modes ship. Requested after a v4.30.0 clean-install dry run found no A2A target
in the wheel (2026-11-18).

Wire formats follow the A2A specification v1.0.1 (a2aproject/A2A @ v1.0.1,
docs/specification.md and specification/a2a.proto):

    version     `A2A-Version` header; an empty value means 0.3 (§3.6.2). A
                version the server does not serve gets VersionNotSupportedError
                -32009 (§5.4).
    methods     0.3: message/send, tasks/get, tasks/cancel
                1.0: SendMessage, GetTask, CancelTask, ListTasks (§5.3)
    parts       0.3: {"kind": "text"|"file"|"data", ...}
                1.0: no `kind`; exactly one of text / raw / url / data (App. A.2.1)
    role        0.3: "user"; 1.0: "ROLE_USER" (a2a.proto Role)
    states      0.3: "completed"; 1.0: "TASK_STATE_COMPLETED" (a2a.proto TaskState)
    push        0.3: configuration.pushNotificationConfig
                1.0: configuration.taskPushNotificationConfig

A hardened 1.0 interface rejects a 0.3-shaped part (one carrying `kind`) with
-32602. That strictness is the point: a client that sends 0.3 shapes under a 1.0
header must not be graded as if the server read its request.

Usage:
    python -m protocol_tests.mock_a2a_server [--port 8404] [--versions 0.3,1.0] [--vulnerable]
    agent-security test a2a --url http://localhost:8404

Not a reference implementation: no streaming, no persistence beyond the process,
no authentication. Never expose it beyond localhost.
"""
from __future__ import annotations

import argparse
import json
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

#: 8402 is the MCP mock. 8403 was the first choice and collided with a lab layout
#: that runs its own MCP target there, so the two could not run side by side.
DEFAULT_PORT = 8404
CARD_PATH = "/.well-known/agent-card.json"

#: JSON-RPC codes (JSON-RPC 2.0; A2A §5.4).
PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS = -32700, -32600, -32601, -32602
TASK_NOT_FOUND, CONTENT_TYPE_NOT_SUPPORTED, VERSION_NOT_SUPPORTED = -32001, -32005, -32009

METHODS = {
    "0.3": {"send": "message/send", "get": "tasks/get", "cancel": "tasks/cancel"},
    "1.0": {"send": "SendMessage", "get": "GetTask", "cancel": "CancelTask", "list": "ListTasks"},
}
ROLE_USER = {"0.3": "user", "1.0": "ROLE_USER"}
STATE_COMPLETED = {"0.3": "completed", "1.0": "TASK_STATE_COMPLETED"}
PUSH_KEY = {"0.3": "pushNotificationConfig", "1.0": "taskPushNotificationConfig"}
CONFIG_KEYS = {
    "0.3": {"acceptedOutputModes", "pushNotificationConfig", "historyLength", "blocking"},
    "1.0": {"acceptedOutputModes", "taskPushNotificationConfig", "historyLength", "returnImmediately"},
}
#: Media types a hardened server refuses to accept as attachments (A2A-009).
DANGEROUS_MEDIA = {"text/html", "application/x-executable", "application/x-msdownload"}
MAX_TEXT = 100_000
#: Push-notification hosts a hardened server accepts (A2A-007).
PUSH_ALLOWLIST = ("localhost", "127.0.0.1")


class MockA2AState:
    def __init__(self, versions: tuple[str, ...], vulnerable: bool, port: int):
        self.versions = versions
        self.vulnerable = vulnerable
        self.port = port
        self.tasks: dict[str, dict] = {}
        #: Requests refused for their SHAPE (a part, role or messageId wrong for the
        #: wire version), not for their attack. A client whose translation is wrong
        #: is refused here, which a hardened run would otherwise read as a rejection.
        self.shape_rejections: list[str] = []

    def card(self) -> dict:
        base = {
            "name": "ash-mock-a2a",
            "description": "Agent Security Harness mock A2A target (labs and CI only).",
            "version": "1.0.0",
            "capabilities": {"streaming": False, "pushNotifications": True},
            "defaultInputModes": ["text/plain"],
            "defaultOutputModes": ["text/plain"],
            "skills": [{"id": "summarize", "name": "Summarize",
                        "description": "Summarizes the text it is given.", "tags": ["text"]}],
            "limitations": ("Mock target: no authentication, no persistence, no streaming; "
                            "for local labs and CI only."),
        }
        url = f"http://127.0.0.1:{self.port}/"
        if "1.0" in self.versions:
            base["supportedInterfaces"] = [
                {"url": url, "protocolBinding": "JSONRPC", "protocolVersion": v}
                for v in self.versions]
        else:
            base["url"] = url
            base["protocolVersion"] = "0.3.0"
        return base


def _err(rid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def _ok(rid, result) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _part_problem(part, wire: str) -> str | None:
    """Why *part* is not a valid Part for *wire*, or None."""
    if not isinstance(part, dict):
        return "part is not an object"
    if wire == "1.0":
        if "kind" in part:
            return "v1.0 parts carry no `kind` (A2A App. A.2.1)"
        present = [k for k in ("text", "raw", "url", "data") if k in part]
        return None if len(present) == 1 else "a v1.0 part needs exactly one of text/raw/url/data"
    if part.get("kind") not in ("text", "file", "data"):
        return "a 0.3 part needs kind text, file or data"
    return None


def _part_text(part: dict) -> str:
    return str(part.get("text", "")) if isinstance(part.get("text"), str) else ""


def _part_media(part: dict, wire: str) -> str:
    if wire == "1.0":
        return str(part.get("mediaType", ""))
    f = part.get("file")
    return str(f.get("mimeType", "")) if isinstance(f, dict) else ""


def _part_uri(part: dict, wire: str) -> str:
    if wire == "1.0":
        return str(part.get("url", ""))
    f = part.get("file")
    return str(f.get("uri", "")) if isinstance(f, dict) else ""


def _part_data(part: dict):
    return part.get("data")


def _dangerous(part: dict, wire: str) -> bool:
    media = _part_media(part, wire).split(";")[0].strip().lower()
    if media in DANGEROUS_MEDIA:
        return True
    data = _part_data(part)
    return isinstance(data, dict) and any(str(k).startswith("__") for k in data)


def _task(state: MockA2AState, wire: str, text: str, context_id: str | None) -> dict:
    tid = str(uuid.uuid4())
    task = {
        "id": tid,
        "contextId": context_id or str(uuid.uuid4()),
        "status": {"state": STATE_COMPLETED[wire]},
        "artifacts": [{"artifactId": str(uuid.uuid4()),
                       "parts": [{"text": text} if wire == "1.0" else {"kind": "text", "text": text}]}],
    }
    if wire == "0.3":
        task["kind"] = "task"
    state.tasks[tid] = task
    return task


def handle_rpc(state: MockA2AState, body: bytes, version_header: str | None) -> dict:
    """One JSON-RPC exchange. Pure apart from the task store, so tests can call it."""
    try:
        rpc = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return _err(None, PARSE_ERROR, "Parse error")
    if not isinstance(rpc, dict):
        return _err(None, INVALID_REQUEST, "Invalid Request: not an object")
    rid = rpc.get("id")
    if rpc.get("jsonrpc") != "2.0":
        return _err(rid, INVALID_REQUEST, "Invalid Request: jsonrpc must be 2.0")
    method = rpc.get("method")
    if not isinstance(method, str):
        return _err(rid, INVALID_REQUEST, "Invalid Request: method missing")

    wire = (version_header or "").strip() or "0.3"
    wire = ".".join(wire.split(".")[:2])  # patch versions MUST NOT be considered (§3.6)
    if wire not in state.versions:
        return _err(rid, VERSION_NOT_SUPPORTED,
                    f"VersionNotSupportedError: A2A {wire} is not served; "
                    f"supported: {', '.join(state.versions)}")
    names = METHODS[wire]
    params = rpc.get("params", {})

    if method not in names.values():
        if state.vulnerable and method.split("/")[0] in ("admin", "debug", "internal", "system"):
            return _ok(rid, {"ok": True, "method": method})  # an exposed hidden method
        return _err(rid, METHOD_NOT_FOUND, f"Method not found: {method}")
    if not isinstance(params, dict):
        return _err(rid, INVALID_PARAMS, "Invalid params: params must be an object")

    if method in (names["get"], names["cancel"]):
        task = state.tasks.get(str(params.get("id")))
        if task is None:
            if state.vulnerable:
                return _ok(rid, {"id": params.get("id"), "status": {"state": STATE_COMPLETED[wire]},
                                 "history": [{"note": "served a task the caller does not own"}]})
            return _err(rid, TASK_NOT_FOUND, "TaskNotFoundError")
        return _ok(rid, task)
    if method == names.get("list"):
        return _ok(rid, {"tasks": [], "nextPageToken": ""})

    # send
    msg = params.get("message")
    if not isinstance(msg, dict) or not isinstance(msg.get("parts"), list) or not msg["parts"]:
        return _err(rid, INVALID_PARAMS, "Invalid params: message.parts is required")
    shape = None
    if wire == "1.0" and not msg.get("messageId"):
        shape = "message.messageId is required"
    elif msg.get("role") != ROLE_USER[wire]:
        shape = f"role must be {ROLE_USER[wire]}"
    else:
        shape = next((w for w in (_part_problem(p, wire) for p in msg["parts"]) if w), None)
    if shape:
        state.shape_rejections.append(f"{method}: {shape}")
        return _err(rid, INVALID_PARAMS, f"Invalid params: {shape}")
    texts = [_part_text(p) for p in msg["parts"]]
    if sum(len(t) for t in texts) > MAX_TEXT:
        return _err(rid, INVALID_PARAMS, "Invalid params: message too large")

    config = params.get("configuration") or {}
    if not isinstance(config, dict):
        return _err(rid, INVALID_PARAMS, "Invalid params: configuration must be an object")
    if not state.vulnerable:
        unknown = sorted(set(config) - CONFIG_KEYS[wire])
        if unknown:
            return _err(rid, INVALID_PARAMS, f"Invalid params: unknown configuration {unknown}")
        push = config.get(PUSH_KEY[wire])
        if isinstance(push, dict):
            host = str(push.get("url", "")).split("//")[-1].split("/")[0].split(":")[0]
            if host not in PUSH_ALLOWLIST:
                return _err(rid, INVALID_PARAMS, "Invalid params: push URL host is not allowed")
        if any(_dangerous(p, wire) for p in msg["parts"]):
            return _err(rid, CONTENT_TYPE_NOT_SUPPORTED, "ContentTypeNotSupportedError")
        # Processes the input (the reply depends on it) without echoing it.
        reply = (f"Received {len(msg['parts'])} part(s), "
                 f"{sum(len(t) for t in texts)} characters of text.")
    else:
        leaked = []
        for p in msg["parts"]:
            if _part_uri(p, wire).startswith("file:///etc/passwd"):
                leaked.append("root:x:0:0:root:/root:/bin/bash")
            data = _part_data(p)
            if isinstance(data, dict) and "__proto__" in data:
                leaked.append("isAdmin: true")
        reply = "Done. " + " ".join(texts + leaked)
    result = _task(state, wire, reply, msg.get("contextId"))
    return _ok(rid, {"task": result} if wire == "1.0" else result)


def make_handler(state: MockA2AState):
    class MockA2AHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *args):
            pass

        def _send(self, status: int, body: dict):
            payload = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if self.path.split("?")[0] == CARD_PATH:
                return self._send(200, state.card())
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(min(n, 2_000_000)) if n else b""
            return self._send(200, handle_rpc(state, body, self.headers.get("A2A-Version")))

    return MockA2AHandler


def serve(port: int, versions: tuple[str, ...], vulnerable: bool) -> ThreadingHTTPServer:
    state = MockA2AState(versions, vulnerable, port)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state))
    state.port = httpd.server_address[1]
    httpd.state = state  # type: ignore[attr-defined]  # read by the harness's own controls
    return httpd


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--versions", default="0.3,1.0",
                    help="comma-separated A2A versions to serve: 0.3, 1.0 or both")
    ap.add_argument("--vulnerable", action="store_true",
                    help="accept the attacks, so the A2A tests can be seen to FAIL")
    args = ap.parse_args(argv)
    versions = tuple(v.strip() for v in args.versions.split(",") if v.strip())
    bad = [v for v in versions if v not in METHODS]
    if bad or not versions:
        ap.error(f"--versions takes 0.3 and/or 1.0, got {args.versions!r}")
    httpd = serve(args.port, versions, args.vulnerable)
    mode = "VULNERABLE" if args.vulnerable else "hardened"
    print(f"mock A2A target ({mode}, A2A {', '.join(versions)}) on "
          f"http://127.0.0.1:{httpd.server_address[1]}  card: {CARD_PATH}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
