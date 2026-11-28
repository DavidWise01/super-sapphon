#!/usr/bin/env python3
"""SAPPHON-218 readback: synthetic fixtures are not external custody."""
import hashlib,importlib.util,json,pathlib,tempfile,unittest
p=pathlib.Path(__file__).with_name("sapphon_218_second_runner.py")
spec=importlib.util.spec_from_file_location("s218",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
RUN="46154833375"; ATTEMPT="1"
COMMIT="c167a95a05177e280625fa61613c1b1fa20f75e9"
BASE="rust@sha256:"+"a"*64
def setup(root):
    def put(name,data):
        x=root/name;x.parent.mkdir(parents=True,exist_ok=True)
        x.write_bytes(data)
        return hashlib.sha256(data).hexdigest()
    lock=put("207-Cargo.lock",b"lock")
    vendor=put("207-vendor.tar",b"vendor")
    image=put("207-image.tar",b"oci")
    (root/"207-image.sha256").write_text(image+"  qualification-artifact/207-image.tar\n")
    j={
       "207-summary.json":{"schema":"sapphon-207-source-owned-run-v1",
          "run_id":RUN,"attempt":ATTEMPT,"commit":COMMIT,
          "steps":{k:"success" for k in ("PYTHON","RUST","FROZEN","VENDOR","IMAGE")},
          "vendor_archive_sha256":vendor,"vendor_tree_sha256":"f"*64,
          "built_image_archive_sha256":image,"built_image_local_id":"sha256:"+"b"*64,
          "recovery_authorized":False,"lock_cleared":False},
       "207-vendor.json":{"lock_sha256":lock,"archive_sha256":vendor,"tree_sha256":"f"*64},
       "207-image-report.json":{"base_ref":BASE,"base_local_id":"sha256:"+"c"*64,
          "built_image_local_id":"sha256:"+"b"*64,"archive_sha256":image,
          "recovery_authorized":False,"lock_cleared":False},
       "215-image-verdict.json":{"state":"SOURCE_OWNED_IMAGE_ARCHIVE_VERIFIED",
           "image_archive_sha256":image,"external_witnesses":0,
           "recovery_authorized":False,"lock_cleared":False},
       "216-base-resolution.json":{"pinned_base_ref":BASE,"local_image_id":"sha256:"+"c"*64,
           "independent_witnesses":0,"recovery_authorized":False,"lock_cleared":False}}
    for name,v in j.items():(root/name).write_text(json.dumps(v))
class Tests(unittest.TestCase):
    def run_case(self,mutator=lambda d:None):
        with tempfile.TemporaryDirectory() as t:
            d=pathlib.Path(t);setup(d);mutator(d)
            return m.assess(d,RUN,ATTEMPT,COMMIT)
    def test_exact_owned_rehash_never_grants_recovery(self):
        x=self.run_case()
        self.assertEqual(x["state"],"GITHUB_OWNED_EXTRACTED_BYTES_MATCH")
        self.assertFalse(x["recovery_authorized"])
        self.assertFalse(x["zip_envelope_sha256_independently_read"])
    def test_mutated_image_denied(self):
        x=self.run_case(lambda d:(d/"207-image.tar").write_bytes(b"altered"))
        self.assertIn("207_IMAGE_TAR_HASH_MISMATCH",x["blockers"])
    def test_run_attempt_substitution_denied(self):
        x=self.run_case(lambda d:(d/"207-summary.json").write_text(
            json.dumps({**json.loads((d/"207-summary.json").read_text()),"attempt":"2"})))
        self.assertIn("EXACT_RUN_ATTEMPT_COMMIT_MISMATCH",x["blockers"])
    def test_missing_base_receipt_denied(self):
        x=self.run_case(lambda d:(d/"216-base-resolution.json").unlink())
        self.assertIn("REQUIRED_FILES_MISSING",x["blockers"])
    def test_false_authority_denied(self):
        def mutate(d):
            p=d/"207-summary.json";v=json.loads(p.read_text());v["lock_cleared"]=True;p.write_text(json.dumps(v))
        self.assertIn("OPERATIONAL_AUTHORITY_CLAIM",self.run_case(mutate)["blockers"])
if __name__=="__main__":unittest.main()
