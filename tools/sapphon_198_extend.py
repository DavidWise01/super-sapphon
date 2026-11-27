#!/usr/bin/env python3
"""SAPPHON-198: append a new observation onto a genuinely imported 197 chain.

Missing predecessor stays missing; it cannot be replaced by a new genesis.
Any inherited fork is preserved in the adjudication, never 'repaired' away.
"""
import argparse,importlib.util,json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parent
sp=importlib.util.spec_from_file_location("ledger197",ROOT/"sapphon_197_ledger.py")
legacy=importlib.util.module_from_spec(sp);sp.loader.exec_module(legacy)
SOURCE="9bddb4491893ee121f71821b61692685508adae6"
def extend(prior,import_report,current):
 if type(import_report) is not dict or import_report.get("schema")!="sapphon-198-import-v1" or import_report.get("source_sha")!=SOURCE:
  raise ValueError("IMPORT_REPORT_NOT_PINNED")
 if import_report.get("prior_ledger_observed") is not True or import_report.get("cross_run_continuity_verified") is not True or import_report.get("state")!="OWNED_197_CHAIN_IMPORTED":
  raise ValueError("NO_VERIFIED_PREDECESSOR")
 old=legacy.validate(prior)
 if old["entries"]!=import_report.get("chain_entries") or old["tip_sha256"]!=import_report.get("prior_tip_sha256") or old["forks"]!=import_report.get("prior_forks"):
  raise ValueError("PREDECESSOR_TIP_OR_FORK_CHANGED")
 if import_report.get("recovery_authorized") is not False or import_report.get("independent_witnesses")!=0:
  raise ValueError("UNSUPPORTED_PREDECESSOR_AUTHORITY")
 event=legacy.from_reacquisition(current)
 new=legacy.append(prior,event)
 verdict=legacy.validate(new)
 if new[:-1]!=prior or new[-1]["envelope"]["previous_sha256"]!=old["tip_sha256"]:
  raise ValueError("NON_APPEND_MUTATION")
 return new,{"schema":"sapphon-198-cross-run-v1","source_sha":SOURCE,
  "predecessor_entries":old["entries"],"predecessor_tip_sha256":old["tip_sha256"],
  "new_entries":verdict["entries"],"new_tip_sha256":verdict["tip_sha256"],
  "new_observation_state":event["state"],
  "inherited_forks":old["forks"],"all_forks":verdict["forks"],
  "prior_missing":old["missing_and_expired"],
  "new_missing":verdict["missing_and_expired"],
  "cross_run_chain_continuity_verified":True,
  "source_owned_fork_present":bool(verdict["forks"]),
  "independent_witnesses":0,"authenticated_utc":False,
  "global_anti_rollback_authenticated":False,
  "recovery_authorized":False,"lock_cleared":False,
  "decision":"CROSS_RUN_LEDGER_TIP_HOLD"}
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--prior-ledger",required=True)
 p.add_argument("--import-report",required=True)
 p.add_argument("--current",required=True)
 p.add_argument("--ledger-out",default="qualification-artifact/198-ledger.jsonl")
 p.add_argument("--report-out",default="qualification-artifact/198-adjudication.json")
 a=p.parse_args()
 try:
  prior=[json.loads(line) for line in pathlib.Path(a.prior_ledger).read_bytes().splitlines() if line.strip()]
  receipt=json.loads(pathlib.Path(a.import_report).read_text())
  current=json.loads(pathlib.Path(a.current).read_text())
  records,report=extend(prior,receipt,current)
 except (OSError,ValueError,KeyError,TypeError) as e:
  report={"schema":"sapphon-198-cross-run-v1","source_sha":SOURCE,
   "state":"NO_VERIFIED_PREDECESSOR","error_type":type(e).__name__,
   "cross_run_chain_continuity_verified":False,
   "independent_witnesses":0,"recovery_authorized":False,"lock_cleared":False,
   "decision":"CROSS_RUN_LEDGER_TIP_HOLD"}
  records=None
 path=pathlib.Path(a.report_out);path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
 if records is None:sys.exit(1)
 path=pathlib.Path(a.ledger_out);path.parent.mkdir(parents=True,exist_ok=True)
 with path.open("xb") as f:
  for row in records:f.write(legacy.canonical(row)+b"\n")
  f.flush()
  import os
  os.fsync(f.fileno())
 print(report["decision"],report["new_entries"],len(report["all_forks"]))
 if report["all_forks"]:sys.exit(1)
if __name__=="__main__":main()
