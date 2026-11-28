#!/usr/bin/env bash
# SAPPHON-216 — resolve an actual OCI base digest, never synthesize one.
# An optional mutable tag is used for *discovery only*. Docker build receives
# the exact repository@sha256 digest observed in RepoDigests.
set -euo pipefail
: "${GITHUB_ENV:?GITHUB_ENV is required}"
mkdir -p qualification-artifact
candidate="${REQUESTED_BASE:-}"
discovery="CONFIGURED_IMMUTABLE"
if [[ -z "$candidate" ]]; then
  discovery="REGISTRY_TAG_DISCOVERY_PINNED_IN_RUN"
  discovery_tag="docker.io/library/rust:1-bookworm"
  docker pull "$discovery_tag"
  docker image inspect "$discovery_tag" > qualification-artifact/216-discovery-image.json
  candidate="$(python3 - <<'PY'
import json,re
items=json.load(open("qualification-artifact/216-discovery-image.json"))
if len(items)!=1:
    raise SystemExit("IMAGE_DISCOVERY_NOT_UNIQUE")
refs=items[0].get("RepoDigests") or []
valid=sorted(x for x in refs if re.fullmatch(r"[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}",x))
if len(valid)!=1:
    raise SystemExit("IMAGE_DISCOVERY_DIGEST_NOT_UNIQUE")
print(valid[0])
PY
)"
fi
if [[ ! "$candidate" =~ ^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$ ]]; then
  echo "::error::The resolved base reference is not an immutable repository digest"
  exit 1
fi
docker pull "$candidate"
docker image inspect "$candidate" > qualification-artifact/216-pinned-image.json
BASE="$candidate" DISCOVERY="$discovery" python3 - <<'PY'
import json,os
item=json.load(open("qualification-artifact/216-pinned-image.json"))[0]
ref=os.environ["BASE"]
if ref not in (item.get("RepoDigests") or []):
    raise SystemExit("PINNED_BASE_DIGEST_NOT_IN_LOCAL_REPODIGESTS")
image_id=item.get("Id")
if not isinstance(image_id,str) or not image_id.startswith("sha256:") or len(image_id)!=71:
    raise SystemExit("PINNED_IMAGE_ID_INVALID")
receipt={
    "schema":"sapphon-216-registry-digest-acquisition-v1",
    "discovery_mode":os.environ["DISCOVERY"],
    "pinned_base_ref":ref,
    "local_image_id":image_id,
    "source_owned":True,
    "external_custody_authenticated":False,
    "independent_witnesses":0,
    "recovery_authorized":False,
    "lock_cleared":False,
    "decision":"HOLD"
}
with open("qualification-artifact/216-base-resolution.json","w") as f:
    json.dump(receipt,f,sort_keys=True,indent=2)
    f.write("\n")
PY
printf 'BASE=%s\n' "$candidate" >> "$GITHUB_ENV"
echo "SAPPHON_216_RESOLVED_IMMUTABLE_BASE"
