"""Pure, offline tests for isolated GEN33 synthetic Git ref race. No network."""
import importlib.util
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

FILE=Path(__file__).resolve().parents[1]/"scripts/gen33_synthetic_claim_race.py"
spec=importlib.util.spec_from_file_location("gen33_synthetic_claim_race",FILE)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
SHA="a"*40
RUN="40769999999"

def rule():
    return {"id":m.RULESET_ID,"node_id":m.RULESET_NODE_ID,"name":m.RULESET_NAME,
            "target":"tag","source_type":"Repository","source":m.REPO,
            "enforcement":"active","updated_at":m.RULESET_UPDATED_AT,
            "conditions":{"ref_name":{"include":[m.REF_PATTERN],"exclude":[]}},
            "rules":[{"type":"deletion"},{"type":"update"},{"type":"non_fast_forward"}],
            "bypass_actors":[],"current_user_can_bypass":"never"}

def auth():
    return {"schema":"GLOBAL_PUBLICATION_MANUAL_AUTHORIZATION/1.0.0",
            "authorization_id":RUN,"github_run_id":RUN,"github_actor":m.OWNER,
            "manual_workflow":True,"public_lock_sha256":m.PUBLIC_SHA,
            "private_execution_state_sha256":m.PRIVATE_SHA,
            "requested_action_id":m.OWNER_ACTION,"action_kind":"GOVERNANCE_UPGRADE",
            "project":"GLOBAL","operations":["GOVERNANCE_UPGRADE"],
            "target_scope_ids":m.SCOPES}

def env():
    return {"GITHUB_REPOSITORY":m.REPO,"GITHUB_ACTOR":m.OWNER,
            "GITHUB_EVENT_NAME":"workflow_dispatch","GITHUB_REF":"refs/heads/main",
            "GITHUB_RUN_ATTEMPT":"1",
            "GITHUB_WORKFLOW_REF":m.REPO+"/"+m.WORKFLOW+"@refs/heads/main",
            "GITHUB_SHA":SHA}

def response():
    return {"ref":m.ref_for_owner_run(RUN),"object":{"sha":SHA,"type":"commit"}}

class ClaimRaceProofTest(unittest.TestCase):
    def test_P01_ref_stable(self):
        self.assertEqual(m.ref_for_owner_run(RUN),m.ref_for_owner_run(RUN))
    def test_P02_ref_64lowercase(self):
        self.assertRegex(m.ref_for_owner_run(RUN),r"^refs/tags/gen33-execution-claim/[0-9a-f]{64}$")
    def test_P03_distinct_owner_auth(self):
        self.assertNotEqual(m.ref_for_owner_run(RUN),m.ref_for_owner_run("40769999998"))
    def test_P04_exact_ruleset(self):
        self.assertEqual(m.ruleset_check(rule()),"PINNED_OWNER_RULESET_VERSION_MATCH")
    def test_P05_utc_instant_equivalence(self):
        x=rule();x["updated_at"]="2026-10-28T19:24:47.017Z"
        self.assertEqual(m.ruleset_check(x),"PINNED_OWNER_RULESET_VERSION_MATCH")
    def test_P06_owner_auth(self):
        self.assertTrue(m.verify_owner_artifact(auth(),RUN))
    def test_P07_runner_origin(self):
        self.assertEqual(m.verify_runner(env()),SHA)
    def test_P08_exact_201(self):
        self.assertEqual(m.classify(201,response(),response()["ref"],SHA),"WON_SYNTHETIC_ONLY")
    def test_P09_collision_422(self):
        self.assertEqual(m.classify(422,{},response()["ref"],SHA),"CONFLICT_NO_WIN")
    def test_P10_collision_409(self):
        self.assertEqual(m.classify(409,{},response()["ref"],SHA),"CONFLICT_NO_WIN")
    def test_N01_bad_claim_id(self):
        with self.assertRaises(m.Deny):m.ref_for_owner_run("00")
    def test_N02_bad_claim_id_path(self):
        with self.assertRaises(m.Deny):m.ref_for_owner_run("4/other")
    def test_N03_missing_ruleset(self):
        with self.assertRaises(m.Deny):m.ruleset_check(None)
    def test_N04_broad_ruleset(self):
        x=rule();x["conditions"]["ref_name"]["include"]=["refs/tags/*"]
        with self.assertRaises(m.Deny):m.ruleset_check(x)
    def test_N05_wrong_ruleset_id(self):
        x=rule();x["id"]=26012498
        with self.assertRaises(m.Deny):m.ruleset_check(x)
    def test_N06_ruleset_version_drift(self):
        x=rule();x["updated_at"]="2026-10-28T19:24:47.018Z"
        with self.assertRaises(m.Deny):m.ruleset_check(x)
    def test_N07_ruleset_disabled(self):
        x=rule();x["enforcement"]="evaluate"
        with self.assertRaises(m.Deny):m.ruleset_check(x)
    def test_N08_ruleset_bypass(self):
        x=rule();x["bypass_actors"]=[{"actor_id":1}]
        with self.assertRaises(m.Deny):m.ruleset_check(x)
    def test_N09_unexpected_rule(self):
        x=rule();x["rules"].append({"type":"creation"})
        with self.assertRaises(m.Deny):m.ruleset_check(x)
    def test_N10_missing_update(self):
        x=rule();x["rules"]=[{"type":"deletion"},{"type":"non_fast_forward"}]
        with self.assertRaises(m.Deny):m.ruleset_check(x)
    def test_N11_malformed_201(self):
        self.assertEqual(m.classify(201,{"ref":response()["ref"]},response()["ref"],SHA),"UNKNOWN_NO_RETRY")
    def test_N12_wrong_sha_201(self):
        x=response();x["object"]["sha"]="b"*40
        self.assertEqual(m.classify(201,x,x["ref"],SHA),"UNKNOWN_NO_RETRY")
    def test_N13_wrong_ref_201(self):
        x=response();x["ref"]+="x"
        self.assertEqual(m.classify(201,x,response()["ref"],SHA),"UNKNOWN_NO_RETRY")
    def test_N14_timeout(self):
        self.assertEqual(m.classify(None,None,response()["ref"],SHA),"UNKNOWN_NO_RETRY")
    def test_N15_forbidden(self):
        self.assertEqual(m.classify(403,{},response()["ref"],SHA),"UNKNOWN_NO_RETRY")
    def test_N16_wrong_action(self):
        x=auth();x["requested_action_id"]="CODE_ONLY"
        with self.assertRaises(m.Deny):m.verify_owner_artifact(x,RUN)
    def test_N17_wrong_scope(self):
        x=auth();x["target_scope_ids"]=["*"]
        with self.assertRaises(m.Deny):m.verify_owner_artifact(x,RUN)
    def test_N18_wrong_public_sha(self):
        x=auth();x["public_lock_sha256"]="b"*64
        with self.assertRaises(m.Deny):m.verify_owner_artifact(x,RUN)
    def test_N19_wrong_auth_run(self):
        with self.assertRaises(m.Deny):m.verify_owner_artifact(auth(),"40768888888")
    def test_N20_rerun_denied(self):
        x=env();x["GITHUB_RUN_ATTEMPT"]="2"
        with self.assertRaises(m.Deny):m.verify_runner(x)
    def test_N21_wrong_workflow_denied(self):
        x=env();x["GITHUB_WORKFLOW_REF"]="invalid"
        with self.assertRaises(m.Deny):m.verify_runner(x)
    def test_N22_wrong_actor(self):
        x=env();x["GITHUB_ACTOR"]="attacker"
        with self.assertRaises(m.Deny):m.verify_runner(x)
    def test_N23_no_repo_access(self):
        x=env();x["GITHUB_REPOSITORY"]="other/repo"
        with self.assertRaises(m.Deny):m.verify_runner(x)
    def test_N24_owner_artifact_not_code_install_grant(self):
        x=auth();x["requested_action_id"]="GLOBAL_PUBLICATION_GEN33_SYNTHETIC_PROTECTED_REF_RACE_V1_CODE_ONLY_IMPLEMENTATION"
        with self.assertRaises(m.Deny):m.verify_owner_artifact(x,RUN)
    def test_N25_wrong_owner_run_sha(self):
        x=env();x["GITHUB_SHA"]="b"*40
        self.assertEqual(m.verify_runner(x),"b"*40)
        with self.assertRaises(m.Deny):m.verify_owner_artifact({"schema":"false"},RUN)
    def test_N26_owner_no_auth_never_claims(self):
        with patch.object(m,"verify_local_authority",return_value=None):
            with patch.object(m,"auth_remote",side_effect=m.Deny("NO_AUTH")):
                with patch.object(m,"api") as api:
                    code=m.stage("claim",root=Path("."),env=env(),token="fake",run_id=RUN)
                    self.assertEqual(code,3)
                    api.assert_not_called()
    def test_N27_preflight_preexisting_ref_deny(self):
        with patch.object(m,"verify_local_authority",return_value=None):
            with patch.object(m,"auth_remote",return_value=None):
                with patch.object(m,"api",side_effect=[(200,rule()),(200,response())]) as api:
                    with self.assertRaises(m.Deny):
                        m.protected_preflight(env(),"fake",RUN,Path("."),require_absent=True)
                    self.assertEqual(api.call_count,2)
    def test_P11_competitor_does_not_recheck_ref(self):
        with patch.object(m,"verify_local_authority",return_value=None):
            with patch.object(m,"auth_remote",return_value=None):
                with patch.object(m,"api",side_effect=[(200,rule())]) as api:
                    sha,ref=m.protected_preflight(env(),"fake",RUN,Path("."),require_absent=False)
                    self.assertEqual(sha,SHA)
                    self.assertEqual(ref,response()["ref"])
                    self.assertEqual(api.call_count,1)
    def test_N28_final_ref_drift_deny(self):
        x=env();x.update({"PREFLIGHT":"success","OUTCOME_A":"WON_SYNTHETIC_ONLY",
                          "OUTCOME_B":"CONFLICT_NO_WIN"})
        with patch.object(m,"protected_preflight",return_value=(SHA,response()["ref"])):
            with patch.object(m,"api",return_value=(200,{"ref":response()["ref"],"object":{"sha":"b"*40}})):
                self.assertEqual(m.stage("verify",env=x,token="x",run_id=RUN),3)
    def test_N29_two_winners_denied(self):
        x=env();x.update({"PREFLIGHT":"success","OUTCOME_A":"WON_SYNTHETIC_ONLY",
                          "OUTCOME_B":"WON_SYNTHETIC_ONLY"})
        with patch.object(m,"protected_preflight",return_value=(SHA,response()["ref"])):
            with patch.object(m,"api") as api:
                self.assertEqual(m.stage("verify",env=x,token="x",run_id=RUN),3)
                api.assert_not_called()
    def test_N30_status_201_obj_type_mismatch(self):
        x=response();x["object"]["type"]="tag"
        self.assertEqual(m.classify(201,x,x["ref"],SHA),"UNKNOWN_NO_RETRY")

if __name__=="__main__":unittest.main()
