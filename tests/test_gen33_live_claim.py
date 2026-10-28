"""GEN33 synthetic/negative tests: no network, no secrets, no Git ref writes."""
import copy
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"broker"))
import gen33_live_claim as claim
from gen33_source_bound_broker import expected_claim_ref, NotActivated, launch_producer

def ruleset():
    return {"id":1234,"name":"GEN33-PROTECTED-CLAIM-TEST","target":"tag",
        "enforcement":"active","bypass_actors":[],
        "conditions":{"ref_name":{"include":["refs/tags/gen33-execution-claim/*"],"exclude":[]}},
        "rules":[{"type":"deletion"},{"type":"non_fast_forward"},{"type":"update"}]}

REF=expected_claim_ref("GLOBAL","ELIGIBLE-NEW-METHOD","ATTEMPT-NEW-01")
SHA="a"*40
def good_response():
    return {"ref":REF,"object":{"sha":SHA,"type":"commit"}}

def classify(status=201,response=None,ref=REF,rules=None):
    if response is None: response=good_response()
    return claim.classify_claim_http_result(status,response,ref,SHA,rules if rules is not None else ruleset())

class TestLiveClaimProof(unittest.TestCase):
    def test_P01_correct_ruleset_shape(self):
        self.assertEqual(claim.verify_ruleset(ruleset()),(True,"PROTECTION_SHAPE_PASS_READ_ONLY"))
    def test_P02_synthetic_winner_never_allows_claim(self):
        r=classify();self.assertEqual(r["status"],"SYNTHETIC_WIN_ONLY")
        self.assertFalse(r["physical_claim_authorized"]);self.assertFalse(r["producer_launch_authorized"])
    def test_P03_proposed_claim_key_stable(self):
        self.assertEqual(REF,expected_claim_ref("GLOBAL","ELIGIBLE-NEW-METHOD","ATTEMPT-NEW-01"))
    def test_P04_distinct_attempt_key(self):
        self.assertNotEqual(REF,expected_claim_ref("GLOBAL","ELIGIBLE-NEW-METHOD","ATTEMPT-NEW-02"))
    def test_P05_simulation_is_read_only(self):
        z=claim.simulated_competition("GLOBAL","ELIGIBLE-NEW-METHOD","ATTEMPT-NEW-01",
            [{"http_status":201,"body":good_response(),"commit_sha":SHA},
             {"http_status":422,"body":{},"commit_sha":SHA}],ruleset())
        self.assertEqual(z["observed_synthetic_wins"],1)
        self.assertFalse(z["launch_allowed"])
        self.assertFalse(z["physical_claim_authorized"])
    def test_P06_ruleset_observation_is_not_live_attestation(self):
        r=claim.observe_claim_protection(ruleset())
        self.assertTrue(r["ruleset_shape_verified"]);self.assertIsNone(r["ruleset_exists_in_github"])
    def test_N01_ruleset_absent(self):
        self.assertEqual(claim.verify_ruleset(None)[0],False)
    def test_N02_wrong_ruleset_namespace(self):
        x=ruleset();x["conditions"]["ref_name"]["include"]=["refs/tags/gen32-sentinel-claim/*"]
        self.assertFalse(claim.verify_ruleset(x)[0])
    def test_N03_broad_wildcard_namespace(self):
        x=ruleset();x["conditions"]["ref_name"]["include"]=["refs/tags/*"]
        self.assertFalse(claim.verify_ruleset(x)[0])
    def test_N04_ruleset_inactive(self):
        x=ruleset();x["enforcement"]="disabled"
        self.assertFalse(claim.verify_ruleset(x)[0])
    def test_N05_ruleset_evaluate_only(self):
        x=ruleset();x["enforcement"]="evaluate"
        self.assertFalse(claim.verify_ruleset(x)[0])
    def test_N06_ruleset_bypass_actor(self):
        x=ruleset();x["bypass_actors"]=[{"actor_id":1,"actor_type":"OrganizationAdmin"}]
        self.assertFalse(claim.verify_ruleset(x)[0])
    def test_N07_ruleset_bypass_missing(self):
        x=ruleset();del x["bypass_actors"]
        self.assertFalse(claim.verify_ruleset(x)[0])
    def test_N08_ruleset_missing_update(self):
        x=ruleset();x["rules"].pop()
        self.assertFalse(claim.verify_ruleset(x)[0])
    def test_N09_ruleset_duplicate_type(self):
        x=ruleset();x["rules"].append({"type":"deletion"})
        self.assertFalse(claim.verify_ruleset(x)[0])
    def test_N10_ruleset_incorrect_target(self):
        x=ruleset();x["target"]="branch"
        self.assertFalse(claim.verify_ruleset(x)[0])
    def test_N11_ruleset_extra_condition(self):
        x=ruleset();x["conditions"]["repository_name"]={"include":["*"],"exclude":[]}
        self.assertFalse(claim.verify_ruleset(x)[0])
    def test_N12_ruleset_exclusion(self):
        x=ruleset();x["conditions"]["ref_name"]["exclude"]=["refs/tags/gen33-execution-claim/override"]
        self.assertFalse(claim.verify_ruleset(x)[0])
    def test_N13_status_422_replay_denied(self):
        self.assertEqual(classify(status=422,response={})["status"],"DENY")
    def test_N14_network_timeout_is_not_claim(self):
        self.assertEqual(classify(status=None,response={})["status"],"UNKNOWN")
    def test_N15_non201_accepted_by_no_one(self):
        self.assertEqual(classify(status=202,response={})["status"],"UNKNOWN")
    def test_N16_malformed_success(self):
        self.assertEqual(classify(response={"ref":REF})["status"],"UNKNOWN")
    def test_N17_success_with_wrong_ref(self):
        x=good_response();x["ref"]=REF+"extra"
        self.assertEqual(classify(response=x)["status"],"UNKNOWN")
    def test_N18_success_with_wrong_sha(self):
        x=good_response();x["object"]["sha"]="b"*40
        self.assertEqual(classify(response=x)["status"],"UNKNOWN")
    def test_N19_success_without_ruleset(self):
        x=claim.classify_claim_http_result(201,good_response(),REF,SHA,None)
        self.assertEqual(x["status"],claim.RULESET_UNKNOWN)
    def test_N20_success_with_bypass(self):
        x=ruleset();x["bypass_actors"]=[{"actor_id":11}]
        self.assertNotEqual(classify(rules=x)["status"],"SYNTHETIC_WIN_ONLY")
    def test_N21_producer_launch_disabled(self):
        with self.assertRaises(NotActivated):
            launch_producer()
    def test_N22_reject_noncanonical_identity(self):
        with self.assertRaises(ValueError):
            expected_claim_ref("GLOBAL","M/../../../bad","ONE")
    def test_N23_invalid_result_sequence(self):
        with self.assertRaises(ValueError):
            claim.simulated_competition("GLOBAL","M","A",[{"http_status":201}],ruleset())
    def test_N24_offline_observation_unverified(self):
        self.assertFalse(claim.observe_claim_protection(None)["ruleset_shape_verified"])

if __name__=="__main__":unittest.main()
