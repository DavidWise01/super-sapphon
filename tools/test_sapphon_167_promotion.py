#!/usr/bin/env python3
"""SAPPHON-167 synthetic negative controls for controlled lock review."""
import base64,copy,hashlib,importlib.util,json,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_167_promotion_review.py")
spec=importlib.util.spec_from_file_location("promotion167",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
SOURCE=m.SOURCE;HEAD="b"*40
def fixture():
    integrity="sha512-"+base64.b64encode(b"x"*64).decode()
    lock={"lockfileVersion":3,"packages":{
       "":{"devDependencies":{"playwright":"1.65.1"}},
       "node_modules/playwright":{"version":"1.65.1","resolved":"https://registry.npmjs.org/playwright/-/playwright-1.65.1.tgz","integrity":integrity,"dependencies":{"playwright-core":"1.65.1"}},
       "node_modules/playwright-core":{"version":"1.65.1","resolved":"https://registry.npmjs.org/playwright-core/-/playwright-core-1.65.1.tgz","integrity":integrity}
    }}
    candidate=json.dumps(lock).encode()
    summary={"schema":"sapphon-165-run-v1","source_commit":SOURCE,"run_id":"1234",
       "attempt":"2","outcomes":{"REGISTRY":"success"},
       "external_custody_authenticated":False,"recovery_authority":"HOLD"}
    inspection={"schema":"sapphon-165-lock-inspection-v1","lock_sha256":m.digest(candidate),
       "candidate_schema_complete":True,"issues":[]}
    intake={"schema":"sapphon-166-exact-artifact-intake-v1","status":"EXACT_RUN_ARTIFACT_OBSERVED",
       "expected_commit":SOURCE,"run_id":1234,"attempt":2,"run_conclusion":"failure",
       "candidate_files_present":["165-registry-candidate-package-lock.json"]}
    review={"schema":"sapphon-166-candidate-review-v1","candidate_sha256":m.digest(candidate),
       "expected_commit":SOURCE,"run_id":1234,"attempt":2,"issues":[],
       "candidate_consistent_with_supplied_runner_evidence":True,
       "decision":"CANDIDATE_REVIEW_HOLD"}
    return [candidate,summary,inspection,intake,review,HEAD]
class ControlledPromotionTests(unittest.TestCase):
    def run_case(self,mutation=lambda x:None):
        x=fixture();mutation(x);return m.reconcile(*x)
    def test_valid_candidate_only_review_eligible(self):
        r=self.run_case();self.assertTrue(r["candidate_review_eligible"])
        self.assertFalse(r["candidate_committed"]);self.assertFalse(r["recovery_authorized"])
    def test_wrong_source_commit(self):
        r=self.run_case(lambda x:x[1].update(source_commit="a"*40))
        self.assertIn("SOURCE_COMMIT_MISMATCH",r["issues"])
    def test_wrong_run(self):
        r=self.run_case(lambda x:x[3].update(run_id=1235))
        self.assertIn("RUN_ID_MISMATCH",r["issues"])
    def test_wrong_attempt(self):
        r=self.run_case(lambda x:x[3].update(attempt=3))
        self.assertIn("ATTEMPT_MISMATCH",r["issues"])
    def test_candidate_digest_conflict(self):
        r=self.run_case(lambda x:x[2].update(lock_sha256="f"*64))
        self.assertIn("CANDIDATE_DIGEST_CONFLICT",r["issues"])
    def test_candidate_not_claimed_present(self):
        r=self.run_case(lambda x:x[3].update(candidate_files_present=[]))
        self.assertIn("CANDIDATE_FILE_NOT_IN_INTAKE",r["issues"])
    def test_registry_not_success(self):
        r=self.run_case(lambda x:x[1]["outcomes"].update(REGISTRY="failure"))
        self.assertIn("REGISTRY_STEP_NOT_SUCCESS",r["issues"])
    def test_unsigned_provenance_claim_rejected(self):
        r=self.run_case(lambda x:x[1].update(external_custody_authenticated=True))
        self.assertIn("FALSE_EXTERNAL_AUTHORITY_CLAIM",r["issues"])
    def test_predecessor_review_bad(self):
        r=self.run_case(lambda x:x[4].update(issues=["BAD"]))
        self.assertIn("PREDECESSOR_REVIEW_NOT_CLEAN",r["issues"])
    def test_added_unexpected_package_rejected(self):
        def change(x):
            v=json.loads(x[0]);v["packages"]["node_modules/something"]={"version":"1.0"}
            x[0]=json.dumps(v).encode()
            x[2]["lock_sha256"]=m.digest(x[0]);x[4]["candidate_sha256"]=m.digest(x[0])
        r=self.run_case(change)
        self.assertIn("UNEXPECTED_LOCK_DEPENDENCY_SET",r["issues"])
    def test_invalid_integrity_rejected(self):
        def change(x):
            v=json.loads(x[0]);v["packages"]["node_modules/playwright"]["integrity"]="sha512-bad"
            x[0]=json.dumps(v).encode()
            x[2]["lock_sha256"]=m.digest(x[0]);x[4]["candidate_sha256"]=m.digest(x[0])
        self.assertIn("INTEGRITY_FIELD_INVALID:playwright",self.run_case(change)["issues"])
    def test_missing_readback_rejected(self):
        r=self.run_case(lambda x:x[3].update(status="READBACK_BLOCKED"))
        self.assertIn("ARTIFACT_INTAKE_NOT_CONFIRMED",r["issues"])
    def test_source_head_invalid(self):
        r=self.run_case(lambda x:x.__setitem__(5,"not-a-sha"))
        self.assertIn("SOURCE_HEAD_INVALID",r["issues"])
if __name__=="__main__":unittest.main()
