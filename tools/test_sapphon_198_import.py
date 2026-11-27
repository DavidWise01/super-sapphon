#!/usr/bin/env python3
"""SAPPHON-198 mocked original artifact and cross-run lineage regression."""
import importlib.util,io,json,pathlib,unittest,zipfile
P=pathlib.Path(__file__).parent
def mod(name,file):
 spec=importlib.util.spec_from_file_location(name,P/file);x=importlib.util.module_from_spec(spec);spec.loader.exec_module(x);return x
i=mod("import198","sapphon_198_import.py")
e=mod("extend198","sapphon_198_extend.py")
l=mod("ledger197","sapphon_197_ledger.py")
def event(log="a"*64,state="GITHUB_OWNED_HASH_MATCH"):
 o=l.from_reacquisition({"schema":"sapphon-196-original-byte-reacquisition-v1",
    "state":state,"original_run_id":193,"original_attempt":2,
    "log_sha256":log,"zip_sha256":"b"*64,"original_bytes_reacquired":True})
 if state!="GITHUB_OWNED_HASH_MATCH":o["original_bytes_reacquired"]=False
 return o
def history():return l.append([],event())
def receipt(h):
 v=l.validate(h)
 return {"schema":"sapphon-198-import-v1","source_sha":i.SOURCE,
   "prior_ledger_observed":True,"cross_run_continuity_verified":True,
   "state":"OWNED_197_CHAIN_IMPORTED","chain_entries":v["entries"],
   "prior_tip_sha256":v["tip_sha256"],"prior_forks":v["forks"],
   "recovery_authorized":False,"independent_witnesses":0}
def archive(h=None,tip_override=None,attempt=2):
 if h is None:h=history()
 adjud=l.validate(h)
 if tip_override is not None:adjud["tip_sha256"]=tip_override
 summary={"schema":"sapphon-197-owned-run-results-v1",
   "commit":i.SOURCE,"run_id":"197","attempt":str(attempt),
   "recovery_authorized":False,"source_owned_forks":len(adjud["forks"]),
   "ledger_complete":True}
 b=io.BytesIO()
 with zipfile.ZipFile(b,"w") as z:
  z.writestr("197-ledger.jsonl",b"".join(l.canonical(x)+b"\n" for x in h))
  z.writestr("197-adjudication.json",json.dumps(adjud))
  z.writestr("197-summary.json",json.dumps(summary))
  z.writestr("197-import.json",json.dumps({"schema":"sapphon-197-import-v1"}))
 return b.getvalue()
def run():return {"id":197,"run_attempt":2,"head_sha":i.SOURCE}
def artifact():return {"id":198,"name":i.ARTIFACT,"expired":False}
class Tests(unittest.TestCase):
 def test_original_chain_import(self):
  r=i.inspect(archive(),run(),artifact())
  self.assertEqual(r["state"],"OWNED_197_CHAIN_IMPORTED")
  self.assertEqual(r["prior_tip_sha256"],l.validate(history())["tip_sha256"])
 def test_wrong_zip_attempt_denied(self):
  self.assertEqual(i.inspect(archive(attempt=3),run(),artifact())["state"],"RUN_ATTEMPT_SUBSTITUTED")
 def test_forged_tip_denied(self):
  self.assertEqual(i.inspect(archive(tip_override="f"*64),run(),artifact())["state"],"ADJUDICATION_TIP_CONFLICT")
 def test_modified_ledger_denied(self):
  h=history();h[0]["envelope"]["observation"]["log_sha256"]="c"*64
  self.assertEqual(i.inspect(archive(h),run(),artifact())["state"],"CHAIN_TAMPER_OR_SCHEMA")
 def test_invalid_zip_denied(self):
  self.assertEqual(i.inspect(b"notzip",run(),artifact())["state"],"ORIGINAL_ZIP_CORRUPT")
 def test_missing_archive_not_owned(self):
  self.assertFalse(i.unavailable("ARTIFACT_EXPIRED_OR_UNKNOWN")["prior_ledger_observed"])
 def test_append_exact_previous_tip(self):
  h=history();updated,report=e.extend(h,receipt(h),{"state":"NOT_OBSERVED"})
  self.assertEqual(updated[-1]["envelope"]["previous_sha256"],l.validate(h)["tip_sha256"])
  self.assertEqual(report["new_entries"],2)
 def test_unavailable_predecessor_refused(self):
  r=receipt(history());r["prior_ledger_observed"]=False
  with self.assertRaisesRegex(ValueError,"NO_VERIFIED_PREDECESSOR"):
   e.extend(history(),r,{})
 def test_changed_tip_refused(self):
  r=receipt(history());r["prior_tip_sha256"]="f"*64
  with self.assertRaisesRegex(ValueError,"PREDECESSOR_TIP_OR_FORK_CHANGED"):
   e.extend(history(),r,{})
 def test_inherited_fork_preserved(self):
  h=l.append(history(),event("c"*64))
  updated,report=e.extend(h,receipt(h),{"state":"NOT_OBSERVED"})
  self.assertEqual(len(report["inherited_forks"]),1)
  self.assertEqual(report["all_forks"],l.validate(updated)["forks"])
 def test_new_fork_detected(self):
  h=history();current={"schema":"sapphon-196-original-byte-reacquisition-v1",
    "state":"GITHUB_OWNED_HASH_MATCH","original_run_id":193,"original_attempt":2,
    "log_sha256":"d"*64,"zip_sha256":"b"*64,"original_bytes_reacquired":True}
  _,report=e.extend(h,receipt(h),current)
  self.assertTrue(report["source_owned_fork_present"])
 def test_no_outside_witness_from_valid_chain(self):
  _,r=e.extend(history(),receipt(history()),{"state":"NOT_OBSERVED"})
  self.assertEqual(r["independent_witnesses"],0)
  self.assertFalse(r["recovery_authorized"])
 def test_forged_external_receipt_refused(self):
  r=receipt(history());r["independent_witnesses"]=2
  with self.assertRaisesRegex(ValueError,"UNSUPPORTED_PREDECESSOR_AUTHORITY"):
   e.extend(history(),r,{})
 def test_empty_chain_import_cannot_claim_two_entries(self):
  x=i.inspect(archive([]),run(),artifact())
  self.assertEqual(x["chain_entries"],0)
 def test_mismatched_summary_forks_denied(self):
  h=l.append(history(),event("c"*64))
  z=archive(h)
  with zipfile.ZipFile(io.BytesIO(z)) as original:
   data={n:original.read(n) for n in original.namelist()}
  summary=json.loads(data["197-summary.json"]);summary["source_owned_forks"]=0
  data["197-summary.json"]=json.dumps(summary).encode()
  b=io.BytesIO()
  with zipfile.ZipFile(b,"w") as out:
   for name,body in data.items():out.writestr(name,body)
  self.assertEqual(i.inspect(b.getvalue(),run(),artifact())["state"],"SUMMARY_FORK_CONFLICT")
if __name__=="__main__":unittest.main()
