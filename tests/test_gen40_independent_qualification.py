"""Scoped negative controls: never turn inventory PASS into book PASS."""
import copy,importlib.util,json,pathlib,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('gen40_independent_qualification',ROOT/'gate/gen40_independent_qualification.py')
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
INVENTORY=json.loads((ROOT/'reports/GEN40_NORMATIVE_SCOPE_INVENTORY_V1.json').read_text())
SCOPE=json.loads((ROOT/'request/GEN40_INDEPENDENT_QA_SCOPE_V1.json').read_text())

class Gen40ScopeTests(unittest.TestCase):
 def run_check(self,i=None,s=None):return mod.inspect(i if i is not None else INVENTORY,s if s is not None else SCOPE)
 def test_1397_lines_1064_nonempty_114_cases_only(self):
  r=self.run_check();self.assertEqual(r['status'],'PASS_SCOPED_INVENTORY_ONLY');self.assertEqual((r['source_lines'],r['nonempty_lines'],r['case_records']),(1397,1064,114));self.assertEqual(r['qualification'],'NOT_PROVEN')
 def test_duplicate_source_rejected(self):
  x=copy.deepcopy(INVENTORY);x['source_rows'][0]=x['source_rows'][1];self.assertEqual(self.run_check(x)['status'],'FAIL_CLOSED')
 def test_deleted_source_rejected(self):
  x=copy.deepcopy(INVENTORY);x['source_rows'].pop();self.assertEqual(self.run_check(x)['status'],'FAIL_CLOSED')
 def test_wrong_nonempty_count_rejected(self):
  x=copy.deepcopy(INVENTORY);x['source_rows'][0]['nonempty']=False;self.assertEqual(self.run_check(x)['status'],'FAIL_CLOSED')
 def test_forged_line_success_rejected(self):
  x=copy.deepcopy(INVENTORY);x['source_rows'][0]['qualification']='PASS';self.assertEqual(self.run_check(x)['status'],'FAIL_CLOSED')
 def test_forged_case_success_rejected(self):
  x=copy.deepcopy(INVENTORY);x['cases'][0]['qualification']='PASS';self.assertEqual(self.run_check(x)['status'],'FAIL_CLOSED')
 def test_duplicate_case_rejected(self):
  x=copy.deepcopy(INVENTORY);x['cases'][0]=x['cases'][1];self.assertEqual(self.run_check(x)['status'],'FAIL_CLOSED')
 def test_missing_case_rejected(self):
  x=copy.deepcopy(INVENTORY);x['cases'].pop();self.assertEqual(self.run_check(x)['status'],'FAIL_CLOSED')
 def test_wrong_public_sha_rejected(self):
  s=copy.deepcopy(SCOPE);s['current_public_lock_sha256']='0'*64;self.assertEqual(self.run_check(s=s)['status'],'FAIL_CLOSED')
 def test_unverified_ppges_registry_cannot_pass(self):
  x=copy.deepcopy(INVENTORY);x['original_ppges_registry_verified']=True;self.assertEqual(self.run_check(x)['status'],'FAIL_CLOSED')
 def test_unverified_book_bytes_cannot_pass(self):
  x=copy.deepcopy(INVENTORY);x['official_docx_bytes_available']=True;self.assertEqual(self.run_check(x)['status'],'FAIL_CLOSED')
 def test_unverified_word_pdf_cannot_pass(self):
  x=copy.deepcopy(INVENTORY);x['word_desktop_mobile_pdf_evidence']=True;self.assertEqual(self.run_check(x)['status'],'FAIL_CLOSED')
 def test_wrong_action_id_rejected(self):
  s=copy.deepcopy(SCOPE);s['requested_action_id']='EXECUTE_PRODUCER';self.assertEqual(self.run_check(s=s)['status'],'FAIL_CLOSED')
 def test_wrong_docx_sha_rejected(self):
  x=copy.deepcopy(INVENTORY);x['official_gen40_docx_sha256']='0'*64;self.assertEqual(self.run_check(x)['status'],'FAIL_CLOSED')
 def test_replaced_valid_length_line_hash_rejected(self):
  x=copy.deepcopy(INVENTORY);x['source_rows'][0]['text_sha256']='e'*64
  r=self.run_check(x);self.assertEqual(r['status'],'FAIL_CLOSED');self.assertIn('SOURCE_LINE_ROSTER_NOT_PINNED',r['blockers'])
 def test_fabricated_case_id_same_group_counts_rejected(self):
  x=copy.deepcopy(INVENTORY);x['cases'][0]['id']='FABRICATED-001'
  r=self.run_check(x);self.assertEqual(r['status'],'FAIL_CLOSED');self.assertIn('114_CASE_IDS_AND_ORDER_NOT_PINNED',r['blockers'])
 def test_no_input_is_fail_closed(self):self.assertEqual(mod.inspect(None,None)['status'],'FAIL_CLOSED')

if __name__=='__main__':unittest.main()
