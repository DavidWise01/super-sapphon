#!/usr/bin/env python3
"""SAPPHON-161: reproducible Actions diagnostics, without claims of external custody.

Commands:
  python3 tools/sapphon_161_probe.py pages URL EXPECTED_TITLE
  python3 tools/sapphon_161_probe.py report

The pages probe never accepts an HTML response without an expected title and
nonempty body. The report writes observations from explicit Actions step
outcomes, not guessed conclusions. No GitHub-owned artifact is an external root.
"""
import hashlib
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

OUTPUT = pathlib.Path("qualification-artifact/161-diagnostic.json")
CHECKS = (
    ("rust-check", "RUST_CHECK"),
    ("rust-tests", "RUST_TESTS"),
    ("historical-freeze", "FROZEN_188"),
    ("pages-http", "PAGES_HTTP"),
    ("browser-smoke", "BROWSER_SMOKE"),
)
STATES = {
    "success": "success",
    "failure": "failure",
    "cancelled": "cancelled",
    "skipped": "skipped",
    "unknown": "unknown",
}


def normalized_state(value):
    return STATES.get(value, "unknown")


def evidence_report(env):
    commit = env.get("GH_SHA", "")
    if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
        raise ValueError("expected exact 40-digit Git commit")
    rid = env.get("GH_RUN", "")
    attempt = env.get("GH_ATTEMPT", "")
    if not (rid.isdecimal() and int(rid) > 0 and
            attempt.isdecimal() and int(attempt) > 0):
        raise ValueError("missing GitHub run id/attempt")
    if env.get("GH_REPO") != "DavidWise01/super-sapphon":
        raise ValueError("unexpected source repository")
    checks = [
        {"name": name, "conclusion": normalized_state(env.get(variable, "unknown")),
         "observed_from": "github-actions-step-outcome", "log_sha256": None}
        for name, variable in CHECKS
    ]
    return {
        "schema": "sapphon-161-check-evidence-v1",
        "repository": env["GH_REPO"],
        "commit_sha": commit,
        "run_id": int(rid),
        "run_attempt": int(attempt),
        "checks": checks,
        "github_api_readback_claimed": False,
        "independent_custody_authenticated": False,
        "recovery_authorized": False,
        "lock_cleared": False,
        "decision": "DIAGNOSTIC_ONLY_HOLD",
    }


def pages_probe(url, expected_title):
    if not url.startswith("https://davidwise01.github.io/super-sapphon/"):
        raise ValueError("must probe intended GitHub Pages origin")
    request = urllib.request.Request(url, headers={"User-Agent": "SAPPHON-161-CI-probe"})
    with urllib.request.urlopen(request, timeout=25) as response:
        code = response.status
        mime = response.headers.get_content_type()
        content = response.read(2_000_001)
    if code != 200 or mime != "text/html" or len(content) > 2_000_000:
        raise ValueError(f"invalid Pages response status={code}, mime={mime}")
    decoded = content.decode("utf-8")
    if expected_title not in decoded or "<canvas" not in decoded or "<script" not in decoded:
        raise ValueError("expected rendered source markers not found")
    return {"http_code": code, "content_type": mime,
            "sha256": hashlib.sha256(content).hexdigest(),
            "body_bytes": len(content)}


def main(argv):
    if len(argv) == 4 and argv[1] == "pages":
        print(json.dumps(pages_probe(argv[2], argv[3]), sort_keys=True))
        return
    if len(argv) == 2 and argv[1] == "report":
        result = evidence_report(os.environ)
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print("WROTE", OUTPUT)
        for c in result["checks"]:
            print(c["name"], c["conclusion"])
        print("DESIGN ONLY: independent custody, external anti-rollback and recovery HOLD")
        return
    raise SystemExit("usage: pages URL TITLE | report")


if __name__ == "__main__":
    main(sys.argv)
