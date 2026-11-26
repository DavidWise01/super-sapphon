#!/usr/bin/env python3
"""SAPPHON-163: exact GitHub commit-to-Pages byte parity, without custody promotion.

Command: python3 tools/sapphon_163_pages_parity.py --commit SHA --out PATH
GitHub's authenticated repository Contents API is read against a pinned commit.
The deployed Pages HTML is obtained separately over HTTPS. The two observations
share the same owned GitHub ancestry and are NOT independent witnesses.
"""
import argparse
import base64
import hashlib
import json
import pathlib
import urllib.error
import urllib.parse
import urllib.request

REPO = "DavidWise01/super-sapphon"
PAGES = "https://davidwise01.github.io/super-sapphon/"
API = "https://api.github.com/repos/" + REPO + "/contents/"
TARGETS = (
    ("SAPPHON-160", "docs/sapphon/phase-xiv/160/index.html"),
    ("SAPPHON-161", "docs/sapphon/phase-xv/161/index.html"),
    ("SAPPHON-162", "docs/sapphon/phase-xv/162/index.html"),
)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def valid_commit(value):
    return len(value) == 40 and all(c in "0123456789abcdef" for c in value)


def fetch_bytes(url, headers=None):
    request = urllib.request.Request(
        url, headers={"User-Agent": "SAPPHON-163-parity-v1", **(headers or {})}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 200:
            raise ValueError("unexpected HTTP status " + str(response.status))
        data = response.read(2_000_001)
        if len(data) > 2_000_000:
            raise ValueError("asset exceeds 2MB")
        return data


def repository_bytes(commit, path, token=""):
    if not valid_commit(commit) or path not in [p for _, p in TARGETS]:
        raise ValueError("invalid pinned source path or commit")
    url = API + urllib.parse.quote(path, safe="/") + "?ref=" + commit
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    payload = json.loads(fetch_bytes(url, headers))
    if payload.get("encoding") != "base64" or payload.get("path") != path:
        raise ValueError("GitHub source content not a known base64 path")
    decoded = base64.b64decode(payload["content"], validate=False)
    if len(decoded) > 2_000_000 or payload.get("size") != len(decoded):
        raise ValueError("GitHub source byte length mismatch")
    return decoded


def pages_bytes(path):
    if path not in [p for _, p in TARGETS]:
        raise ValueError("unexpected Pages path")
    return fetch_bytes(PAGES + path.removesuffix("index.html"))


def compare(label, path, source, deployed):
    result = {
        "name": label,
        "source_path": path,
        "source_sha256": sha256(source),
        "pages_sha256": sha256(deployed),
        "source_bytes": len(source),
        "pages_bytes": len(deployed),
        "matched": source == deployed,
    }
    if b"<canvas" not in deployed or label.encode() not in deployed:
        result["matched"] = False
        result["reason"] = "missing expected HTML identifier or canvas"
    if not result["matched"] and "reason" not in result:
        result["reason"] = "deployed Pages bytes differ from pinned source"
    return result


def run(commit, token=""):
    if not valid_commit(commit):
        raise ValueError("a pinned 40-digit commit is required")
    outcomes = []
    for label, path in TARGETS:
        try:
            source = repository_bytes(commit, path, token)
            deployed = pages_bytes(path)
            outcomes.append(compare(label, path, source, deployed))
        except Exception as exc:
            outcomes.append({
                "name": label, "source_path": path, "matched": False,
                "error": type(exc).__name__ + ": " + str(exc)[:400],
            })
    return {
        "schema": "sapphon-163-pages-parity-v1",
        "repository": REPO,
        "commit_sha": commit,
        "origins": ["github-repository-api", "github-pages"],
        "shared_source_ancestry": "github-owned-corpus",
        "checks": outcomes,
        "all_deployed_bytes_match": all(x["matched"] for x in outcomes),
        "external_custody_authenticated": False,
        "recovery_authorized": False,
        "lock_cleared": False,
        "decision": "PINNED_ASSET_OBSERVATION_HOLD",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", required=True)
    parser.add_argument("--out", default="qualification-artifact/163-pages-parity.json")
    args = parser.parse_args()
    import os
    result = run(args.commit, os.environ.get("GH_TOKEN", ""))
    output = pathlib.Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    for item in result["checks"]:
        print(item["name"], "MATCH" if item["matched"] else "MISMATCH", item.get("reason", item.get("error", "")))
    if not result["all_deployed_bytes_match"]:
        raise SystemExit("SAPPHON-163: deployment parity FAILED; recovery HOLD")
    print("SAPPHON-163: all source-owned Pages bytes match pinned commit; custody HOLD")


if __name__ == "__main__":
    main()
