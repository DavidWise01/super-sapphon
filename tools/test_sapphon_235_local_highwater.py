#!/usr/bin/env python3
"""SAPPHON-235: restart, replay, torn-write and branch preservation tests."""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import sapphon_235_local_highwater as m

N1="1"*64
N2="2"*64
N3="3"*64
class Tests(unittest.TestCase):
 def setUp(self):
    self.tmp=tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    self.p=pathlib.Path(self.tmp.name)/"journal.jsonl"
 def test_append_and_reload(self):
    m.append(self.p,N1,"alpha",0)
    self.assertTrue(m.audit_rows(m.read_rows(self.p))["valid"])
    self.assertEqual(len(m.read_rows(self.p)),1)
 def test_process_restart_detects_nonce(self):
    m.append(self.p,N1,"alpha",0)
    command=[sys.executable,str(pathlib.Path(__file__).with_name("sapphon_235_local_highwater.py")),
       "append","--journal",str(self.p),"--nonce",N1,"--witness","alpha","--epoch","1"]
    p=subprocess.run(command,capture_output=True,text=True)
    self.assertNotEqual(p.returncode,0)
    self.assertIn("NONCE_REPLAY",p.stderr)
    self.assertEqual(len(m.read_rows(self.p)),1)
 def test_monotonic_epoch(self):
    m.append(self.p,N1,"alpha",0)
    with self.assertRaisesRegex(ValueError,"WITNESS_EPOCH_NOT_MONOTONIC"):
        m.append(self.p,N2,"alpha",0)
 def test_new_witness_must_begin_epoch_zero(self):
    with self.assertRaisesRegex(ValueError,"WITNESS_EPOCH_NOT_MONOTONIC"):
        m.append(self.p,N1,"alpha",3)
 def test_two_serial_appends(self):
    m.append(self.p,N1,"alpha",0)
    m.append(self.p,N2,"alpha",1)
    self.assertEqual(m.audit_rows(m.read_rows(self.p))["rows"],2)
 def test_torn_tail_rejected(self):
    self.p.write_bytes(b'{"incomplete":')
    with self.assertRaisesRegex(ValueError,"TORN_JOURNAL_TAIL"):m.read_rows(self.p)
 def test_modified_digest_rejected(self):
    m.append(self.p,N1,"alpha",0)
    rows=m.read_rows(self.p)
    rows[0]["nonce"]=N2
    self.p.write_bytes(m.canonical(rows[0])+b"\n")
    with self.assertRaisesRegex(ValueError,"INVALID_ANCESTRY"):
        m.append(self.p,N3,"alpha",1)
 def test_valid_fork_preserved(self):
    a=pathlib.Path(self.tmp.name)/"branch-a"
    b=pathlib.Path(self.tmp.name)/"branch-b"
    m.append(a,N1,"alpha",0);m.append(b,N1,"alpha",0)
    m.append(a,N2,"alpha",1);m.append(b,N3,"alpha",1)
    z=m.compare(m.read_rows(a),m.read_rows(b))
    self.assertEqual(z["state"],"CONFLICTING_VALID_HISTORIES_HOLD")
    self.assertEqual(z["first_conflict_index"],1)
    self.assertFalse(z["recovery_authorized"])
 def test_prefix_relation_not_authority(self):
    a=pathlib.Path(self.tmp.name)/"branch-a"
    b=pathlib.Path(self.tmp.name)/"branch-b"
    m.append(a,N1,"alpha",0);m.append(b,N1,"alpha",0)
    m.append(b,N2,"alpha",1)
    z=m.compare(m.read_rows(a),m.read_rows(b))
    self.assertEqual(z["state"],"PREFIX_RELATED_HISTORIES_HOLD")
    self.assertFalse(z["external_highwater_authenticated"])
 def test_identical_history_still_hold(self):
    m.append(self.p,N1,"alpha",0)
    z=m.compare(m.read_rows(self.p),m.read_rows(self.p))
    self.assertEqual(z["state"],"SAME_LOCAL_HISTORY_HOLD")
    self.assertEqual(z["independently_authenticated_witnesses"],0)
 def test_duplicate_nonce_in_inventory(self):
    m.append(self.p,N1,"alpha",0)
    rows=m.read_rows(self.p)
    duplicate=dict(rows[0],sequence=1,previous_row_sha256=rows[0]["row_sha256"])
    duplicate["row_sha256"]=m.row_hash(duplicate)
    z=m.audit_rows(rows+[duplicate])
    self.assertIn("NONCE_REPLAY",z["faults"])
 def test_invalid_chain(self):
    m.append(self.p,N1,"alpha",0)
    r=dict(m.read_rows(self.p)[0],sequence=1,nonce=N2,previous_row_sha256="f"*64,witness_epoch=1)
    r["row_sha256"]=m.row_hash(r)
    self.assertIn("PREDECESSOR_LINK_INVALID",m.audit_rows(m.read_rows(self.p)+[r])["faults"])
 def test_nonhex_nonce_rejected(self):
    with self.assertRaisesRegex(ValueError,"INVALID_APPEND_INPUT"):
        m.append(self.p,"x","alpha",0)
 def test_bounded_ledger(self):
    self.assertIn("ROW_INVENTORY_INVALID",m.audit_rows([None]*(m.MAX_ROWS+1))["faults"])
 def test_hash_determinism(self):
    row=m.append(self.p,N1,"alpha",0)
    self.assertEqual(row["row_sha256"],m.row_hash(row))
if __name__=="__main__":unittest.main()
