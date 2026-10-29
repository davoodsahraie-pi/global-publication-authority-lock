"""New bridge boundary tests. Fake Git APIs and fake Driver only.

These tests never import the original Generator/Driver, deliver a manuscript,
issue a live claim or qualify a real DOCX. The authoritative existing physical
GEN33 claim-race evidence is not repeated here.
"""
import base64
import contextlib
import copy
import datetime as dt
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch,Mock
import zipfile

ROOT=Path(__file__).resolve().parents[1]
for sub in ("broker","gate","scripts"): sys.path.insert(0,str(ROOT/sub))
import gen34_r25r7_bridge as b
import publication_gate as gate
import transition_guard as guard
import ci_validate_pr as ci

PUB="a"*64;PRIV="b"*64;HEAD="c"*40;RUN="90000001"
KEY=b"unit-test-only-not-a-deployment-k"[:32].ljust(32,b"0")

def profile():
    return {"schema":guard.GEN34_SCHEMA,"enabled":True,"runtime_profile":"LEGACY_R25R7_FULL_BOOK",
        **guard.GEN34_PINS,**{k:"d"*64 for k in guard.GEN34_SHA_FIELDS},
        "action_id":"GEN34_BOUND_ORIGINAL_DRIVER_ONCE","project":"GLOBAL",
        "method_id":"EXISTING_R25R7_CONNECTION_TEST","attempt_id":"BOUND_01","executor_id":"PROTECTED_MAIN",
        "private_repository":b.PRIVATE_REPO,"bundle_blob_sha":"e"*40,
        "environment":"gen34-r25r7-production","target_scope_ids":["GEN34_R25R7_ORIGINAL_FULL_BOOK_ONCE"],
        "operations":["BUILD","GENERATE_DOCX"],"max_seconds":2400}

def authority():
    p=profile()
    lock={"gen34_r25r7_bridge":p,"execution_authorized_now":True,
        "current_action":{"id":p["action_id"],"mode":"MUTATING"},"private_execution_state_sha256":PRIV,
        "ledger_hashes":{"method_fail":[],"immutable_pass":[],"blocked_project":[],"frozen_project":[]},
        "attempt_ledger":[{"schema":guard.EVENT_SCHEMA,"event":"RESERVE","project_id":p["project"],
            "method_id":p["method_id"],"attempt_id":p["attempt_id"],"owner_authorization_run_id":"80000001",
            "reservation_source_public_sha256":"f"*64,"candidate_sha256":None}]}
    private={"next_action_contract":{"id":p["action_id"],"mode":"MUTATING","build_authorized":True,
        "private_payload_delivery_allowed":True,"real_claim_authorized":True}}
    req={"schema":gate.REQ_SCHEMA,"requested_action_id":p["action_id"],"action_kind":"EXECUTE","mode":"MUTATING",
        "input_public_lock_sha256":PUB,"input_private_state_sha256":PRIV,"authorization_run_id":RUN,
        "user_explicit_authorization":True,**{k:p[k] for k in ("project","method_id","attempt_id","executor_id","operations","target_scope_ids")}}
    auth={"schema":gate.AUTH_SCHEMA,"requested_action_id":p["action_id"],"action_kind":"EXECUTE","project":"GLOBAL",
        "public_lock_sha256":PUB,"private_execution_state_sha256":PRIV,"operations":p["operations"],
        "target_scope_ids":p["target_scope_ids"],"authorization_id":RUN,"github_run_id":RUN,"github_actor":b.OWNER,"manual_workflow":True}
    return lock,private,req,auth

def rules():
    return {"id":26070404,"target":"tag","enforcement":"active","bypass_actors":[],
        "conditions":{"ref_name":{"include":[b.REAL_NAMESPACE+"*"],"exclude":[]}},
        "rules":[{"type":x} for x in ("deletion","update","non_fast_forward")]}

class FakeGit:
    def __init__(self,private=False):
        self.private=private;self.blobs={};self.trees={};self.commits={};self.refs={};self.calls=[]
        self.unknown_ref=None;self.drift=False;self.fail_private=False;self.tamper_receipt=False
    def get(self,path):
        self.calls.append(("GET",path))
        if path=="": return {"private":self.private}
        if path=="/git/ref/heads/main": return {"object":{"sha":"0"*40 if self.drift else HEAD}}
        if path=="/rulesets/26070404": return rules()
        if path.startswith("/git/blobs/"):
            oid=path.rsplit("/",1)[1];data=self.blobs[oid]
            return {"sha":oid,"encoding":"base64","content":base64.b64encode(data).decode()}
        if path.startswith("/git/commits/"):return self.commits[path.rsplit("/",1)[1]]
        if path.startswith("/git/trees/"):
            oid=path.rsplit("/",1)[1].split("?")[0]
            return {"truncated":False,"tree":self.trees[oid]}
        if path.startswith("/git/ref/"):
            ref="refs/"+path.removeprefix("/git/ref/")
            return {"ref":ref,"object":{"type":"commit","sha":self.refs[ref]}}
        raise AssertionError(path)
    def post(self,path,data):
        self.calls.append(("POST",path,copy.deepcopy(data)))
        if self.fail_private:raise b.Denied("HTTP_OUTCOME_UNKNOWN_NO_RETRY")
        if path=="/git/blobs":
            raw=base64.b64decode(data["content"]);oid=b.git_blob_sha(raw);self.blobs[oid]=raw;return {"sha":oid}
        if path=="/git/trees":
            oid=b.sha(b.canonical(data))[:40];self.trees[oid]=data["tree"];return {"sha":oid}
        if path=="/git/commits":
            oid=b.sha(b.canonical(data))[:40];self.commits[oid]={"tree":{"sha":data["tree"]},"parents":[{"sha":x} for x in data["parents"]]};return {"sha":oid}
        if path=="/git/refs":
            ref=data["ref"]
            if ref in self.refs:raise b.Denied("HTTP_422")
            self.refs[ref]=data["sha"]
            if ref==self.unknown_ref:raise b.Denied("HTTP_OUTCOME_UNKNOWN_NO_RETRY")
            return {"ref":ref,"object":{"type":"commit","sha":data["sha"]}}
        raise AssertionError(path)

def zip_bytes(files):
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,"w",zipfile.ZIP_DEFLATED) as z:
        for name,data in files.items(): z.writestr(name,data)
    return stream.getvalue()

class AdmissionTests(unittest.TestCase):
    def check(self,mutator=None):
        values=authority()
        if mutator:mutator(*values)
        return gate.validate_gen34_admission(*values,PUB)
    def test_eligible_is_not_launch_permission(self):
        r=self.check();self.assertEqual(r["status"],"ELIGIBLE_FOR_PHYSICAL_CLAIM_ONLY");self.assertFalse(r["launch_allowed"])
    def test_current_installed_authority_stays_denied(self):
        lock=json.loads((ROOT/"authority/CURRENT.json").read_text())
        self.assertEqual(gate.validate_gen34_admission(lock,{}, {},None,PUB)["status"],"DENY")
    def test_activation_and_immutable_pins(self):
        for field,value in [("enabled",False),("source_sha256","0"*64),("driver_sha256","0"*64),
            ("generator_sha256","0"*64),("runtime_profile","ENGINEERING_WHEEL"),("max_seconds",3601),
            ("operations",["BUILD","EXPORT_PDF"]),("private_repository",b.REPO)]:
            with self.subTest(field=field):
                self.assertEqual(self.check(lambda l,p,r,a:l["gen34_r25r7_bridge"].update({field:value}))["status"],"DENY")
    def test_no_undeclared_profile_fields(self):
        p=profile();p["engineering_wheel_sha256"]="1"*64;self.assertTrue(guard.gen34_activation_errors(p))
    def test_readonly_public_state_denies(self):
        self.assertEqual(self.check(lambda l,p,r,a:l.update(execution_authorized_now=False))["status"],"DENY")
    def test_private_state_scope_denies(self):
        for key in ("build_authorized","private_payload_delivery_allowed","real_claim_authorized"):
            with self.subTest(key=key):self.assertEqual(self.check(lambda l,p,r,a:p["next_action_contract"].update({key:False}))["status"],"DENY")
    def test_authentication_binding_mismatch(self):
        for field in ("public_lock_sha256","private_execution_state_sha256","requested_action_id","action_kind","github_run_id","authorization_id"):
            with self.subTest(field=field):self.assertEqual(self.check(lambda l,p,r,a:a.update({field:"wrong"}))["status"],"DENY")
    def test_authorization_scope_mismatch(self):
        self.assertEqual(self.check(lambda l,p,r,a:a.update(target_scope_ids=[]))["status"],"DENY")
    def test_missing_reservation(self):
        self.assertEqual(self.check(lambda l,p,r,a:l.update(attempt_ledger=[]))["status"],"DENY")
    def test_reserved_run_cannot_be_redeemed_as_execute(self):
        self.assertEqual(self.check(lambda l,p,r,a:l["attempt_ledger"][0].update(owner_authorization_run_id=RUN))["status"],"DENY")
    def test_forbidden_historical_synthetic_and_code_runs(self):
        for run in ("40329927057","40761646972","40818118503"):
            def mutate(l,p,r,a):r["authorization_run_id"]=run;a.update(github_run_id=run,authorization_id=run)
            with self.subTest(run=run):self.assertEqual(self.check(mutate)["status"],"DENY")
    def test_failed_method_and_frozen_project_preserved(self):
        for ledger,prefix,value in [("method_fail","FAIL:",profile()["method_id"]),("frozen_project","FROZEN:","GLOBAL"),("blocked_project","BLOCKED:","GLOBAL")]:
            with self.subTest(ledger=ledger):self.assertEqual(self.check(lambda l,p,r,a:l["ledger_hashes"][ledger].append(gate.digest_id(prefix,value)))["status"],"DENY")

class OwnerArtifactTests(unittest.TestCase):
    def fixture(self):
        _,_,_,auth=authority();auth["issued_at_utc"]=dt.datetime.now(dt.timezone.utc).isoformat()
        raw=zip_bytes({"authorization.json":b.canonical(auth)})
        run={"id":int(RUN),"path":".github/workflows/authorize-next-action.yml","event":"workflow_dispatch","conclusion":"success","head_branch":"main","head_sha":HEAD,"run_attempt":1,"actor":{"login":b.OWNER},"triggering_actor":{"login":b.OWNER}}
        art={"id":123,"name":"publication-authorization-"+RUN,"expired":False,"digest":"sha256:"+b.sha(raw)}
        api=Mock();api.get.side_effect=lambda path:run if path=="/actions/runs/"+RUN else {"total_count":1,"artifacts":[art]};api.artifact.return_value=raw
        return api,run,art,auth
    def test_github_artifact_authenticated(self):
        api,_,_,_=self.fixture();self.assertEqual(b.authenticate_owner(api,RUN,HEAD)["github_run_id"],RUN)
    def test_wrong_actor_event_head_or_rerun(self):
        for field,value in [("actor",{"login":"attacker"}),("triggering_actor",{"login":"attacker"}),("event","push"),("run_attempt",2),("head_sha","0"*40)]:
            api,run,_,_=self.fixture();run[field]=value
            with self.subTest(field=field),self.assertRaises(b.Denied):b.authenticate_owner(api,RUN,HEAD)
            api.artifact.assert_not_called()
    def test_wrong_artifact_digest(self):
        api,_,art,_=self.fixture();art["digest"]="sha256:"+"0"*64
        with self.assertRaises(b.Denied):b.authenticate_owner(api,RUN,HEAD)
    def test_expired_artifact(self):
        api,_,art,_=self.fixture();art["expired"]=True
        with self.assertRaises(b.Denied):b.authenticate_owner(api,RUN,HEAD)
    def test_stale_auth_artifact(self):
        api,_,art,auth=self.fixture();auth["issued_at_utc"]=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=2)).isoformat()
        raw=zip_bytes({"authorization.json":b.canonical(auth)});api.artifact.return_value=raw;art["digest"]="sha256:"+b.sha(raw)
        with self.assertRaises(b.Denied):b.authenticate_owner(api,RUN,HEAD)

class CustodyTests(unittest.TestCase):
    def test_archive_traversal(self):
        for name in ("../source","/source","a\\b","a/../b","a//b"):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as td,self.assertRaises(b.Denied):b.safe_extract(zip_bytes({name:b"x"}),Path(td))
    def test_archive_symlink(self):
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,"w") as z:
            info=zipfile.ZipInfo("link");info.external_attr=(stat.S_IFLNK|0o777)<<16;z.writestr(info,"secret")
        with tempfile.TemporaryDirectory() as td,self.assertRaises(b.Denied):b.safe_extract(stream.getvalue(),Path(td))
    def test_archive_expansion_limit(self):
        with tempfile.TemporaryDirectory() as td,self.assertRaises(b.Denied):b.safe_extract(zip_bytes({"large":b"a"*1024}),Path(td),100)
    def test_bundle_digest_before_extraction(self):
        with tempfile.TemporaryDirectory() as td,self.assertRaises(b.Denied):b.prepare_payload(b"substitute",profile(),PRIV,Path(td))
        self.assertFalse((Path(td)/"payload").exists())
    def test_duplicate_json_is_rejected(self):
        with self.assertRaises(b.Denied):b.parse_json('{"a":1,"a":2}')
    def test_nonfinite_json_is_rejected(self):
        with self.assertRaises(b.Denied):b.parse_json('{"a":NaN}')
    def test_credentials_never_reach_driver_environment(self):
        with patch.dict(os.environ,{"GH_TOKEN":"secret1","GEN34_PRIVATE_TOKEN":"secret2","GEN34_RECEIPT_KEY_HEX":"secret3","PYTHONPATH":"evil"}):
            env=b.clean_env();self.assertNotIn("GH_TOKEN",env);self.assertNotIn("GEN34_PRIVATE_TOKEN",env);self.assertNotIn("GEN34_RECEIPT_KEY_HEX",env);self.assertNotIn("PYTHONPATH",env)
    def test_private_output_readback_larger_than_contents_api_limit(self):
        api=FakeGit(True);raw=b"PRIVATE-MANUSCRIPT"*100000
        out=b.store_private_output(api,{"output.docx":raw},"1"*64)
        self.assertEqual(out["file_sha256"]["output.docx"],b.sha(raw))
        self.assertTrue(all("/contents/" not in call[1] for call in api.calls))
    def test_public_output_destination_denied_before_writes(self):
        api=FakeGit(False)
        with self.assertRaises(b.Denied):b.store_private_output(api,{"output.docx":b"PRIVATE"},"1"*64)
        self.assertFalse(any(c[0]=="POST" for c in api.calls))

class ClaimAndTerminalTests(unittest.TestCase):
    def flow(self,api=None,private=None,runner=None,p=None,run=RUN,deadline=None):
        api=api or FakeGit();private=private or FakeGit(True);runner=runner or Mock(return_value={"output.docx":b"PRIVATE-MANUSCRIPT-UNIT-ONLY","driver-report.json":b"UNIT-ONLY"})
        with tempfile.TemporaryDirectory() as td:
            result=b.complete_claimed(api,private,p or profile(),run,"d"*64,HEAD,"90000002",KEY,Path(td),Path("fake-python"),Path(td),deadline or time.monotonic()+3000,runner)
        return result,api,private,runner
    def test_claim_driver_private_output_and_authenticated_durable_terminal(self):
        result,api,private,runner=self.flow();self.assertEqual(result["status"],"COMPLETED");runner.assert_called_once()
        self.assertEqual(len(api.refs),3)
        raw=b.committed_file(api,result["terminal_commit"],"receipt.json");receipt=b.parse_json(raw)
        expected={k:receipt[k] for k in ("issuer","attempt_key_sha256","dispatch_descriptor_sha256","claim_ref","claim_commit_sha","authorization_run_id")}
        self.assertTrue(b.verify_terminal_receipt(receipt,KEY,expected)["authenticated"])
        self.assertFalse(b.verify_terminal_receipt(receipt,KEY,expected,[receipt["nonce"]])["authenticated"])
        self.assertNotIn(b"PRIVATE-MANUSCRIPT-UNIT-ONLY",b"".join(api.blobs.values()))
        self.assertIn(b"PRIVATE-MANUSCRIPT-UNIT-ONLY",b"".join(private.blobs.values()))
    def test_same_authorization_cannot_launch_twice(self):
        _,api,private,_=self.flow();runner=Mock()
        with self.assertRaises(b.Denied):self.flow(api,private,runner)
        runner.assert_not_called()
    def test_same_authorization_cannot_claim_different_attempt(self):
        _,api,private,_=self.flow();p=profile();p["attempt_id"]="OTHER_ATTEMPT";runner=Mock()
        with self.assertRaises(b.Denied):self.flow(api,private,runner,p)
        runner.assert_not_called()
    def test_same_attempt_cannot_claim_new_authorization(self):
        _,api,private,_=self.flow();runner=Mock()
        with self.assertRaises(b.Denied):self.flow(api,private,runner,run="90000099")
        runner.assert_not_called()
    def test_unknown_claim_response_never_retried_or_launched(self):
        api=FakeGit();api.unknown_ref=b.claim_refs(profile(),RUN)[1];runner=Mock()
        with self.assertRaises(b.Denied):self.flow(api,FakeGit(True),runner)
        runner.assert_not_called()
        writes=[c for c in api.calls if c[:2]==("POST","/git/refs") and c[2]["ref"]==api.unknown_ref]
        self.assertEqual(len(writes),1)
        self.assertEqual(len(api.refs),2)
    def test_authority_drift_after_claim_emits_not_launched(self):
        api=FakeGit();api.drift=True;runner=Mock();result,_,_,_=self.flow(api=api,runner=runner)
        self.assertEqual(result["status"],"NOT_LAUNCHED");runner.assert_not_called()
    def test_exhausted_time_emits_not_launched(self):
        runner=Mock();r,_,_,_=self.flow(runner=runner,deadline=time.monotonic()+10)
        self.assertEqual(r["status"],"NOT_LAUNCHED");runner.assert_not_called()
    def test_driver_exception_consumes_claim_and_emits_failure_receipt(self):
        runner=Mock(side_effect=RuntimeError("PRIVATE TEXT"));r,api,_,_=self.flow(runner=runner)
        self.assertEqual(r["status"],"STARTED_NO_OUTPUT");self.assertIsNone(r["output_sha256"])
        self.assertNotIn(b"PRIVATE TEXT",b"".join(api.blobs.values()))
        self.assertEqual(len(api.refs),3)
    def test_private_storage_failure_cannot_report_completion(self):
        private=FakeGit(True);private.fail_private=True;r,api,_,_=self.flow(private=private)
        self.assertEqual(r["status"],"STARTED_NO_OUTPUT");self.assertIsNone(r["output_sha256"])
        self.assertEqual(len([c for c in private.calls if c[0]=="POST"]),1)
    def test_tampered_receipt_mac_rejected(self):
        p=profile();record={"attempt_ref":b.claim_refs(p,RUN)[1]};r=b.terminal_receipt(KEY,p,RUN,"d"*64,HEAD,record,"COMPLETED","e"*64)
        expected={k:r[k] for k in ("issuer","attempt_key_sha256","dispatch_descriptor_sha256","claim_ref","claim_commit_sha","authorization_run_id")}
        r["output_sha256"]="0"*64
        self.assertFalse(b.verify_terminal_receipt(r,KEY,expected)["authenticated"])

class DriverAndEntrypointTests(unittest.TestCase):
    def test_actual_driver_command_is_fixed_and_private_logs_are_captured(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);payload=root/"payload";payload.mkdir()
            for name in (b.GENERATOR,b.DRIVER,"source.jsonl"):(payload/name).write_bytes(b"unit fixture")
            pins={**b.GEN34_PINS,"generator_sha256":b.sha(b"unit fixture"),"driver_sha256":b.sha(b"unit fixture"),"source_sha256":b.sha(b"unit fixture")}
            def fake_run(command,**kwargs):
                self.assertIn(str(payload/b.DRIVER),command);self.assertIn(str(payload/b.GENERATOR),command)
                self.assertEqual(command[command.index("--start-part")+1],"1");self.assertEqual(command[command.index("--end-part")+1],"25")
                self.assertNotIn("GH_TOKEN",kwargs["env"]);self.assertTrue(kwargs["stdout"].name.endswith("driver-stdout.log"))
                raw=zip_bytes({"[Content_Types].xml":b"UNIT","word/document.xml":b"UNIT"});(root/"output.docx").write_bytes(raw)
                (root/"driver-report.json").write_text(json.dumps({"status":"PASS","source_sha256":pins["source_sha256"],"generator_sha256":pins["generator_sha256"],"output_sha256":b.sha(raw),"output_bytes":len(raw),"batch_parts":[1,25],"cumulative_records":21529,"batch_records":21529,"base_docx_sha256":None,"resume":None,"readback":{"zip_bad":None,"sections":1,"part_titles_present_through":25,"end_marker_present":True}}))
            with patch.object(b,"GEN34_PINS",pins),patch.object(b.subprocess,"run",side_effect=fake_run) as run:
                result=b.run_driver(Path("fixture-python"),payload,root,30)
            run.assert_called_once();self.assertIn("driver-report.json",result)
    def test_bad_output_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/"output.docx").write_bytes(b"bad");(root/"driver-report.json").write_text('{"status":"PASS","output_sha256":"bad"}')
            with patch.object(b.subprocess,"run"),self.assertRaises(b.Denied):b.run_driver(Path("fixture-python"),root,root,30)
    def test_entrypoint_never_prints_raw_exceptions_or_credentials(self):
        output=io.StringIO()
        with patch.object(sys,"argv",["bridge","--authorization-run-id",RUN]),patch.object(b,"GitHub",side_effect=RuntimeError("SECRET-PRIVATE-PAYLOAD")),contextlib.redirect_stdout(output):
            self.assertEqual(b.main(),2)
        self.assertNotIn("SECRET-PRIVATE-PAYLOAD",output.getvalue());self.assertFalse(json.loads(output.getvalue())["retry_allowed"])

class PlatformTests(unittest.TestCase):
    def fixture(self):
        env={"GITHUB_REPOSITORY":b.REPO,"GITHUB_REF":"refs/heads/main","GITHUB_EVENT_NAME":"workflow_dispatch",
             "GITHUB_RUN_ATTEMPT":"1","GITHUB_ACTOR":b.OWNER,"GITHUB_TRIGGERING_ACTOR":b.OWNER,"GITHUB_SHA":HEAD,"GITHUB_RUN_ID":"90000002"}
        main={"enforcement":"active","target":"branch","bypass_actors":[],"conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},
              "rules":[{"type":"pull_request"},{"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":True,"required_status_checks":[{"context":"publication-authority","integration_id":15368}]}}]}
        data={"/git/ref/heads/main":{"object":{"sha":HEAD}},
              "/actions/runs/90000002":{"head_sha":HEAD,"path":b.WORKFLOW,"run_attempt":1,"event":"workflow_dispatch","head_branch":"main","actor":{"login":b.OWNER},"triggering_actor":{"login":b.OWNER}},
              "/rulesets/24932377":copy.deepcopy(main),"/rulesets/24939466":copy.deepcopy(main),"/rulesets/26070404":rules(),
              "/environments/gen34-r25r7-production":{"deployment_branch_policy":{"protected_branches":False,"custom_branch_policies":True}},
              "/environments/gen34-r25r7-production/deployment-branch-policies":{"total_count":1,"branch_policies":[{"name":"main","type":"branch"}]}}
        api=Mock();api.get.side_effect=lambda path:data[path]
        return env,data,api
    def test_protected_main_and_environment_are_required(self):
        env,data,api=self.fixture();self.assertEqual(b.verify_platform(api,env,profile())[0],HEAD)
        for change in (lambda e,d:e.update(GITHUB_REF="refs/heads/untrusted"),
                       lambda e,d:e.update(GITHUB_RUN_ATTEMPT="2"),
                       lambda e,d:d["/rulesets/24932377"].update(bypass_actors=[{"actor_id":1}]),
                       lambda e,d:d["/rulesets/26070404"].update(enforcement="disabled"),
                       lambda e,d:d["/environments/gen34-r25r7-production/deployment-branch-policies"]["branch_policies"][0].update(name="*"),
                       lambda e,d:d["/environments/gen34-r25r7-production/deployment-branch-policies"]["branch_policies"][0].update(type="tag")):
            env,data,api=self.fixture();change(env,data)
            with self.assertRaises(b.Denied):b.verify_platform(api,env,profile())
    def test_activation_change_requires_governance_and_exact_contract(self):
        with tempfile.TemporaryDirectory() as td:
            cur={"generation":34,"ledger_hashes":{}};a=Path(td)/"a.json";c=Path(td)/"b.json";a.write_text(json.dumps(cur))
            prop={**cur,"generation":35,"previous_public_lock_sha256":b.file_sha(a),"gen34_r25r7_bridge":profile()}
            c.write_text(json.dumps(prop))
            self.assertIn("GEN34_ACTIVATION_CHANGE_REQUIRES_GOVERNANCE_UPGRADE",guard.validate_transition(a,c,{"action_kind":"AUTHORITY_UPDATE"})["reasons"])
            self.assertEqual(guard.validate_transition(a,c,{"action_kind":"GOVERNANCE_UPGRADE"})["status"],"PASS")
            prop["gen34_r25r7_bridge"]["source_sha256"]="0"*64;c.write_text(json.dumps(prop))
            self.assertEqual(guard.validate_transition(a,c,{"action_kind":"GOVERNANCE_UPGRADE"})["status"],"DENY")

class BundleContractTests(unittest.TestCase):
    def bundle(self,extra=False):
        names={b.GENERATOR:"generator_sha256",b.DRIVER:"driver_sha256","source.jsonl":"source_sha256","c1.json":"c1_sha256","grammar.txt":"grammar_sha256"}
        files={name:("UNIT ONLY "+name).encode() for name in names}
        files["ppges.zip"]=zip_bytes({"PPGES_v1.3.5/ppg_enforcement_engine_v1_3_5.py":b"UNIT ONLY"})
        pins={field:b.sha(files[name]) for name,field in names.items()};pins["ppges_sha256"]=b.sha(files["ppges.zip"])
        files["private-state.json"]=b.canonical({"unit":"only"});files["wheels/unit.whl"]=b"UNIT ONLY"
        files["dependency-lock.json"]=b.canonical({"schema":"GEN34_WHEELS/1.0","wheels":{"wheels/unit.whl":b.sha(files["wheels/unit.whl"])}})
        if extra:files["unexpected.py"]=b"UNIT ONLY"
        files["manifest.json"]=b.canonical({"schema":"GEN34_PRIVATE_BUNDLE/1.0","files":{k:b.sha(v) for k,v in files.items()}})
        raw=zip_bytes(files);p=profile();p.update(bundle_sha256=b.sha(raw),manifest_sha256=b.sha(files["manifest.json"]),dependency_lock_sha256=b.sha(files["dependency-lock.json"]))
        return raw,p,pins,b.sha(files["private-state.json"])
    def test_all_private_input_bytes_bound_before_dependency_execution(self):
        raw,p,pins,private_sha=self.bundle()
        with tempfile.TemporaryDirectory() as td,patch.object(b,"GEN34_PINS",pins):
            payload,state,deps=b.prepare_payload(raw,p,private_sha,Path(td))
            self.assertEqual(state,{"unit":"only"});self.assertTrue((payload/b.DRIVER).is_file())
    def test_unexpected_bundle_member_rejected(self):
        raw,p,pins,private_sha=self.bundle(extra=True)
        with tempfile.TemporaryDirectory() as td,patch.object(b,"GEN34_PINS",pins),self.assertRaises(b.Denied):b.prepare_payload(raw,p,private_sha,Path(td))
    def test_private_state_digest_mismatch_rejected(self):
        raw,p,pins,private_sha=self.bundle()
        with tempfile.TemporaryDirectory() as td,patch.object(b,"GEN34_PINS",pins),self.assertRaises(b.Denied):b.prepare_payload(raw,p,"0"*64,Path(td))
    def test_original_driver_digest_mismatch_rejected(self):
        raw,p,pins,private_sha=self.bundle();pins["driver_sha256"]="0"*64
        with tempfile.TemporaryDirectory() as td,patch.object(b,"GEN34_PINS",pins),self.assertRaises(b.Denied):b.prepare_payload(raw,p,private_sha,Path(td))

class ExactScopeTests(unittest.TestCase):
    def test_exact_scope_with_independent_base(self):
        base=os.environ.get("GEN34_BASE_ROOT")
        self.assertTrue(base,"Independent base checkout required for this test")
        req=json.loads((ROOT/"request/ACTION_REQUEST.json").read_text());base=Path(base)
        lock=json.loads((base/ci.LOCK).read_text());changes=ci.changed_paths(base,ROOT)
        self.assertEqual(set(changes),ci.GEN34_CODE_PATHS)
        self.assertEqual(ci.validate_gen34_code_scope(changes,req,lock,base),[])
        self.assertTrue(ci.validate_gen34_code_scope(changes+["authority/CURRENT.json"],req,lock,base))
        req["authorization_run_id"]=40761646972
        self.assertIn("GEN34_CODE_AUTHORIZATION_RUN_MISMATCH",ci.validate_gen34_code_scope(changes,req,lock,base))
    def test_workflow_has_no_public_artifact_or_secret_on_pr(self):
        runtime=(ROOT/b.WORKFLOW).read_text();qa=(ROOT/".github/workflows/gen34-r25r7-qa.yml").read_text()
        self.assertNotIn("upload-artifact",runtime);self.assertNotIn("secrets.",qa)
        self.assertIn("environment: gen34-r25r7-production",runtime)
        self.assertIn("persist-credentials: false",runtime)
        self.assertNotIn("pull_request_target",runtime)

if __name__=="__main__":unittest.main()
