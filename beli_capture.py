"""
Beli API traffic capture addon for mitmproxy.

Usage:
    mitmproxy -s beli_capture.py
    # or headless:
    mitmdump -s beli_capture.py

Then proxy your phone through this and use the Beli app.
Captures are written to beli_api_log.jsonl (one JSON object per request).
"""

import json
import time
from pathlib import Path
from mitmproxy import http

LOG_FILE = Path(__file__).parent / "beli_api_log.jsonl"
BELI_DOMAINS = ("beli", "beliapp")


def matches_beli(host: str) -> bool:
    return any(d in host.lower() for d in BELI_DOMAINS)


def response(flow: http.HTTPFlow) -> None:
    if not matches_beli(flow.request.pretty_host):
        return

    req = flow.request
    resp = flow.response

    try:
        req_body = req.get_text()
    except Exception:
        req_body = None

    try:
        resp_body = resp.get_text()
    except Exception:
        resp_body = None

    # Try to parse response as JSON for cleaner output
    resp_json = None
    if resp_body:
        try:
            resp_json = json.loads(resp_body)
        except (json.JSONDecodeError, ValueError):
            pass

    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "method": req.method,
        "url": req.pretty_url,
        "path": req.path,
        "status": resp.status_code,
        "request_headers": {
            k: v for k, v in req.headers.items()
            if k.lower() in ("authorization", "content-type", "x-api-key",
                             "x-device-id", "x-app-version", "user-agent",
                             "accept")
        },
        "request_body": req_body if req_body else None,
        "response_content_type": resp.headers.get("content-type", ""),
        "response_body": resp_json if resp_json else resp_body,
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry, default=str) + "\n")

    # Also print a summary to the mitmproxy event log
    from mitmproxy import ctx
    ctx.log.info(
        f"[BELI] {req.method} {req.path} → {resp.status_code}"
    )
