#!/usr/bin/env python3
"""SAPPHON-164: extend exact Pages byte parity to the SAPPHON-163 viewer.
Source and deployment share GitHub ancestry. No custody qualification.
"""
import argparse
import json
import os
import pathlib
import sapphon_163_pages_parity as prior

prior.TARGETS = prior.TARGETS + (
    ("SAPPHON-163", "docs/sapphon/phase-xv/163/index.html"),
)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--commit",required=True)
    ap.add_argument("--out",default="qualification-artifact/164-pages-parity.json")
    args=ap.parse_args()
    report=prior.run(args.commit,os.environ.get("GH_TOKEN",""))
    report["schema"]="sapphon-164-four-page-parity-v1"
    report["decision"]="FOUR_PAGE_OBSERVATION_HOLD"
    report["dependency_integrity_from_registry_verified"]=False
    out=pathlib.Path(args.out)
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    for item in report["checks"]:
        print(item["name"],"MATCH" if item["matched"] else "MISMATCH",item.get("reason",item.get("error","")))
    if len(report["checks"])!=4 or not report["all_deployed_bytes_match"]:
        raise SystemExit("SAPPHON-164 exact deployed-byte comparison FAILED; HOLD")
    print("Four GitHub-owned Pages assets match source commit; external custody HOLD")

if __name__=="__main__":
    main()
