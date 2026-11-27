#!/usr/bin/env python3
"""SAPPHON-196: synthetic original bytes; never asserts real hosted acquisition."""
import importlib.util,io,json,pathlib,unittest,zipfile
p=pathlib.Path(__file__).with_name("sapphon_196_reacquire.py")
sp=importlib.util.spec_from_file_location("r196",p)
m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
def archive193(run_id=193,attempt=2):
 b=io.BytesIO()
 with zipfile.ZipFile(b,"w") as z:
  for name in sorted(m.a194.MEMBERS):
   obj={"schema":"fixture"}
   if name=="193-summary.json":
    obj={"schema":"sapphon-193-source-run-v1","commit":m.a194.SHA,
       "run_id":str(run_id),"attempt":str(attempt),"recovery_authorized":False}
   z.writestr(name,json.dumps(obj))
 return b.getvalue()
def anchor(raw_log=b"log bytes",raw_zip=None):
 if raw_zip is None:raw_zip=archive193()
 report={"schema":"sapphon-195-crossverify-v1",
 "source_sha":"c2f237a5065c29a13947657c707d101ff2dca31e",
 "prior_source_sha":m.a194.SHA,
 "issues":[],"replay_executed":False,"recovery_authorized":False,
 "original_log_bytes_reread_in_195":False,"original_zip_bytes_reread_in_195":False,
 "original_run_id":193,"original_attempt":2,
 "original_log_sha256":m.sha(raw_log),"original_zip_sha256":m.sha(raw_zip)}
 summary={"schema":"sapphon-195-source-owned-v1","commit":m.SOURCE_195,
 "run_id":"195","attempt":"1","recovery_authorized":False}
 zip195=io.BytesIO()
 with zipfile.ZipFile(zip195,"w") as z:
  for name,obj in [("195-import.json",{"schema":"sapphon-195-import-v1"}),
                   ("195-crossverify.json",report),("195-summary.json",summary)]:
   z.writestr(name,json.dumps(obj))
 return report,summary,zip195.getvalue(),raw_log,raw_zip
def original():
 return {"id":193,"run_attempt":2,"head_sha":m.a194.SHA}
def artifact():
 return {"id":304,"name":m.a194.ARTIFACT,"expired":False,
 "workflow_run":{"id":193,"head_sha":m.a194.SHA}}
class Tests(unittest.TestCase):
 def test_fresh_matching_original_bytes_remain_owned(self):
  report,_,_,log,z=anchor()
  x=m.compare(report,original(),artifact(),log,z)
  self.assertEqual(x["state"],"GITHUB_OWNED_HASH_MATCH")
  self.assertFalse(x["recovery_authorized"])
 def test_changed_original_log_detected(self):
  report,_,_,log,z=anchor()
  x=m.compare(report,original(),artifact(),log+b"changed",z)
  self.assertEqual(x["state"],"GITHUB_OWNED_READBACK_EQUIVOCATION")
 def test_changed_original_zip_detected(self):
  report,_,_,log,z=anchor()
  updated=archive193()
  # Different ZIP compression bytes; valid embedded identity.
  b=io.BytesIO()
  with zipfile.ZipFile(b,"w",zipfile.ZIP_DEFLATED) as q:
   with zipfile.ZipFile(io.BytesIO(updated)) as r:
    for n in sorted(r.namelist()):q.writestr(n,r.read(n))
  self.assertEqual(m.compare(report,original(),artifact(),log,b.getvalue())["state"],
                   "GITHUB_OWNED_READBACK_EQUIVOCATION")
 def test_wrong_archive_attempt_denied(self):
  report,_,_,log,z=anchor()
  x=m.compare(report,original(),artifact(),log,archive193(attempt=1))
  self.assertEqual(x["state"],"193_ORIGINAL_ZIP_IDENTITY_INVALID")
 def test_expired_artifact_denied(self):
  report,_,_,log,z=anchor();a=artifact();a["expired"]=True
  self.assertEqual(m.compare(report,original(),a,log,z)["state"],"193_ARTIFACT_EXPIRED")
 def test_unknown_expiry_denied(self):
  report,_,_,log,z=anchor();a=artifact();a.pop("expired")
  self.assertEqual(m.compare(report,original(),a,log,z)["state"],"193_ARTIFACT_EXPIRY_UNKNOWN")
 def test_wrong_run_sha_denied(self):
  report,_,_,log,z=anchor();r=original();r["head_sha"]="b"*40
  self.assertEqual(m.compare(report,r,artifact(),log,z)["state"],"193_IDENTITY_MISMATCH")
 def test_wrong_artifact_ancestry(self):
  report,_,_,log,z=anchor();a=artifact();a["workflow_run"]["id"]=45
  self.assertEqual(m.compare(report,original(),a,log,z)["state"],"193_ARTIFACT_ANCESTRY_MISMATCH")
 def test_no_original_log_denied(self):
  report,_,_,_,z=anchor()
  self.assertEqual(m.compare(report,original(),artifact(),b"",z)["state"],"193_ORIGINAL_BYTES_MISSING_OR_OVERSIZE")
 def test_forged_replay_denied(self):
  report,_,_,log,z=anchor();report["replay_executed"]=True
  self.assertEqual(m.compare(report,original(),artifact(),log,z)["state"],"195_REPORT_NOT_QUALIFIED")
 def test_report_hash_not_sha_denied(self):
  report,_,_,log,z=anchor();report["original_log_sha256"]="bad"
  self.assertEqual(m.compare(report,original(),artifact(),log,z)["state"],"195_ORIGINAL_DIGESTS_INVALID")
 def test_195_zip_members_exact(self):
  _,_,b,_,_=anchor()
  self.assertIn("report",m.zip_read(b))
 def test_duplicate_195_zip_members_rejected(self):
  _,_,b,_,_=anchor();out=io.BytesIO()
  with zipfile.ZipFile(out,"w") as z:
   with zipfile.ZipFile(io.BytesIO(b)) as inp:
    for n in inp.namelist():z.writestr(n,inp.read(n))
   z.writestr("195-summary.json","{}")
  self.assertEqual(m.zip_read(out.getvalue())["state"],"195_ZIP_MEMBER_CONFLICT")
 def test_missing_195_zip_denied(self):
  self.assertEqual(m.zip_read(b"")["state"],"195_ZIP_UNAVAILABLE")
 def test_195_invalid_summary_attempt(self):
  report,summary,_,_,_=anchor();summary["attempt"]="2"
  self.assertEqual(m.validate_anchor(report,summary,{"id":195,"run_attempt":1}),"195_SUMMARY_IDENTITY")
 def test_source_anomaly_no_witness(self):
  report,_,_,log,z=anchor();report["issues"]=["ORIGINAL_BYTES_NOT_COMPLETE"]
  x=m.compare(report,original(),artifact(),log,z)
  self.assertFalse(x["original_bytes_reacquired"])
if __name__=="__main__":unittest.main()
