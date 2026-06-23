"""
Analyze captured Beli API traffic and produce a structured API map.

Usage:
    python analyze_capture.py [path/to/beli_api_log.jsonl]

Outputs:
    - Unique endpoints grouped by resource
    - Auth scheme detected
    - Request/response shape summaries
"""

import json
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse


def load_entries(path: Path) -> list[dict]:
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def extract_auth_scheme(entries: list[dict]) -> str:
    for e in entries:
        auth = e.get("request_headers", {}).get("authorization", "")
        if auth:
            scheme = auth.split(" ")[0] if " " in auth else auth[:20]
            return f"{scheme} (token length: {len(auth)})"
        if e.get("request_headers", {}).get("x-api-key"):
            return "x-api-key header"
    return "none detected"


def summarize_shape(obj, depth=0, max_depth=2) -> str:
    if depth >= max_depth:
        return type(obj).__name__
    if isinstance(obj, dict):
        fields = {k: summarize_shape(v, depth + 1) for k, v in list(obj.items())[:15]}
        return json.dumps(fields)
    elif isinstance(obj, list):
        if obj:
            return f"[{summarize_shape(obj[0], depth + 1)}, ...] (len={len(obj)})"
        return "[]"
    elif isinstance(obj, str):
        return f"str({len(obj)})"
    elif isinstance(obj, (int, float)):
        return type(obj).__name__
    elif obj is None:
        return "null"
    return type(obj).__name__


def main():
    log_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "beli_api_log.jsonl"

    if not log_path.exists():
        print(f"No log file at {log_path}. Run mitmproxy with beli_capture.py first.")
        sys.exit(1)

    entries = load_entries(log_path)
    print(f"Loaded {len(entries)} captured requests\n")

    # Auth
    print(f"Auth scheme: {extract_auth_scheme(entries)}\n")

    # Group by path pattern (strip IDs)
    endpoints = defaultdict(list)
    for e in entries:
        parsed = urlparse(e["url"])
        endpoints[f"{e['method']} {parsed.path}"].append(e)

    print("=" * 60)
    print("ENDPOINTS")
    print("=" * 60)

    for endpoint, reqs in sorted(endpoints.items()):
        print(f"\n{'─' * 60}")
        print(f"{endpoint}  (called {len(reqs)}x)")
        print(f"  Status codes: {set(r['status'] for r in reqs)}")

        # Show response shape from first successful response
        for r in reqs:
            if 200 <= r["status"] < 300 and r.get("response_body"):
                body = r["response_body"]
                if isinstance(body, str):
                    try:
                        body = json.loads(body)
                    except (json.JSONDecodeError, ValueError):
                        pass
                print(f"  Response shape: {summarize_shape(body)}")
                break

        # Show request body shape if present
        for r in reqs:
            if r.get("request_body"):
                try:
                    req_body = json.loads(r["request_body"])
                    print(f"  Request body shape: {summarize_shape(req_body)}")
                except (json.JSONDecodeError, ValueError):
                    print(f"  Request body: (non-JSON, len={len(r['request_body'])})")
                break

    # Base URL
    hosts = set()
    for e in entries:
        parsed = urlparse(e["url"])
        hosts.add(f"{parsed.scheme}://{parsed.netloc}")

    print(f"\n{'=' * 60}")
    print(f"Base URLs: {', '.join(sorted(hosts))}")
    print(f"Total unique endpoints: {len(endpoints)}")


if __name__ == "__main__":
    main()
