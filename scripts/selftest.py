#!/usr/bin/env python3
import copy, hashlib, json, tempfile, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"gate"))
from publication_gate import validate
from transition_guard import validate_transition

LOCK=ROOT/"authority/CURRENT.json"; SIDE=ROOT/"authority/CURRENT.sha256"
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,o): Path(p).write_text(json.dumps(o,indent=2)+"\n",encoding="utf-8")

def base_req(s):
    return {"schema":"GLOBAL_PUBLICATION_PUBLIC_ACTION_REQUEST/1.0.0","request_id":"selftest","input_public_lock_sha256":sha(LOCK),"input_private_state_sha256":s["private_execution_state_sha256"],"requested_action_id":s["current_action"]["id"],"action_kind":"EXECUTE","mode":s["current_action"]["mode"],"project":"GLOBAL","method_id":None,"operations":["READ","VERIFY_HASH"],"target_scope_ids":[],"authorization_run_id":None,"user_explicit_authorization":True}

def main():
    s=json.loads(LOCK.read_text()); out=[]
    with tempfile.TemporaryDirectory() as td:
      td=Path(td)
      def case(name,req,expect,auth=None):
        p=td/(name+".json"); write(p,req); r=validate(LOCK,SIDE,p,auth); out.append((name,expect,r["status"],expect==r["status"],r["reasons"]))
      r=base_req(s); case("current-readonly",r,"ALLOW")
      x=copy.deepcopy(r); x["input_public_lock_sha256"]="0"*64; case("stale-public",x,"DENY")
      x=copy.deepcopy(r); x["input_private_state_sha256"]="0"*64; case("stale-private",x,"DENY")
      x=copy.deepcopy(r); x["operations"]=["BUILD"]; case("readonly-mutation",x,"DENY")
      x=copy.deepcopy(r); x["requested_action_id"]="wrong"; case("wrong-action",x,"DENY")

      auth={"schema":"GLOBAL_PUBLICATION_MANUAL_AUTHORIZATION/1.0.0","authorization_id":"1","public_lock_sha256":sha(LOCK),"private_execution_state_sha256":s["private_execution_state_sha256"],"requested_action_id":"NEXT-1","action_kind":"SET_NEXT_ACTION","project":"GLOBAL","operations":["SET_NEXT_ACTION"],"target_scope_ids":[],"manual_workflow":True,"github_actor":"owner","github_run_id":"1"}
      x={"schema":"GLOBAL_PUBLICATION_PUBLIC_ACTION_REQUEST/1.0.0","request_id":"set","input_public_lock_sha256":sha(LOCK),"input_private_state_sha256":s["private_execution_state_sha256"],"requested_action_id":"NEXT-1","action_kind":"SET_NEXT_ACTION","mode":"MUTATING","project":"GLOBAL","method_id":None,"operations":["SET_NEXT_ACTION"],"target_scope_ids":[],"authorization_run_id":"1","user_explicit_authorization":True}
      case("set-next-authorized",x,"ALLOW",auth)
      y=copy.deepcopy(auth); y["public_lock_sha256"]="0"*64; case("set-next-stale-auth",x,"DENY",y)

      cur=copy.deepcopy(s); cp=td/"cur.json"; write(cp,cur)
      prop=copy.deepcopy(cur); prop["generation"]=cur["generation"]+1; prop["previous_public_lock_sha256"]=sha(cp); prop["current_action"]={"id":"NEXT","mode":"READ_ONLY"}
      pp=td/"prop.json"; write(pp,prop)
      tr=validate_transition(cp,pp,{"action_kind":"SET_NEXT_ACTION"}); out.append(("transition-pass","PASS",tr["status"],tr["status"]=="PASS",tr["reasons"]))
      bad=copy.deepcopy(prop); bad["ledger_hashes"]["immutable_pass"]=bad["ledger_hashes"]["immutable_pass"][1:]
      bp=td/"bad.json"; write(bp,bad)
      tr=validate_transition(cp,bp,{"action_kind":"SET_NEXT_ACTION"}); out.append(("ledger-removal","DENY",tr["status"],tr["status"]=="DENY",tr["reasons"]))


      # Motion F deterministic acceptance suite: 17 core and 4 supplementary.
      # Synthetic lock snapshots only; the official public authority is never mutated.
      from ci_validate_pr import validate_motion_f_changed_paths, MOTION_F_ACTION
      from transition_guard import EVENT_SCHEMA
      def mark(name,expected,actual,reasons,required=None):
        ok=(expected==actual and (required is None or any(required in x for x in reasons)))
        out.append((name,expected,actual,ok,reasons))
      def ev(kind,owner,pin,aid="MOTION_F_TEST_01",cand=None,method="MOTION_F_SAFE_TEST"):
        return {"schema":EVENT_SCHEMA,"event":kind,"project_id":"GLOBAL",
                "method_id":method,"attempt_id":aid,
                "owner_authorization_run_id":str(owner),
                "reservation_source_public_sha256":pin,"candidate_sha256":cand}
      def simulation(label,source,event_factory=None,expected="PASS",required=None,
                     prop_patch=None,req_patch=None,record=True,override_prop=None):
        from_path=td/(label+"-from.json"); write(from_path,source)
        from_sha=sha(from_path)
        proposed=copy.deepcopy(source)
        proposed["generation"]=source["generation"]+1
        proposed["previous_public_lock_sha256"]=from_sha
        event=None
        if event_factory is not None:
            event=event_factory(from_sha)
            proposed["attempt_ledger"]=copy.deepcopy(source.get("attempt_ledger",[]))+[event]
        if prop_patch: prop_patch(proposed)
        if override_prop: proposed=override_prop
        to_path=td/(label+"-to.json"); write(to_path,proposed)
        request={"action_kind":"GOVERNANCE_UPGRADE",
                 "operations":["GOVERNANCE_UPGRADE","PATCH"],
                 "project":"GLOBAL","method_id":"MOTION_F_SAFE_TEST",
                 "attempt_id":event["attempt_id"] if event else "MOTION_F_TEST_01",
                 "authorization_run_id":str(event["owner_authorization_run_id"]) if event else "7001",
                 "input_public_lock_sha256":from_sha}
        if req_patch: req_patch(request)
        result=validate_transition(from_path,to_path,request)
        if record: mark(label,expected,result["status"],result["reasons"],required)
        return proposed,from_sha
      # A01, A02, A03, A04: one reservation and unique consumed Run.
      first,pin=simulation("A01_FIRST_RESERVATION",s,
                           lambda h: ev("RESERVE","7001",h),expected="PASS")
      simulation("A02_DUPLICATE_ATTEMPT_NEW_RUN",first,
                 lambda h: ev("RESERVE","7002",h),expected="DENY",
                 required="ATTEMPT_DUPLICATE_RESERVATION")
      simulation("A03_REUSE_RUN_NEW_ATTEMPT",first,
                 lambda h: ev("RESERVE","7001",h,aid="MOTION_F_TEST_02"),
                 expected="DENY",required="AUTHORIZATION_RUN_ALREADY_RESERVED")
      started,_=simulation("PREP_START",first,
                 lambda h: ev("START","7001",pin),record=False,
                 req_patch=lambda q: q.update(authorization_run_id="7003"))
      closed,_=simulation("A07_CLOSE_VALID_CANDIDATE",started,
                 lambda h: ev("CLOSE","7001",pin,cand="a"*64),
                 expected="PASS",
                 req_patch=lambda q: q.update(authorization_run_id="7004"))
      simulation("A04_REPLAY_CONSUMED_RUN",closed,
                 lambda h: ev("RESERVE","7001",h,aid="MOTION_F_TEST_03"),
                 expected="DENY",required="AUTHORIZATION_RUN_ALREADY_RESERVED")
      # A05, A06: unreserved work and stale Authority.
      unreserved=base_req(s)
      unreserved.update(action_kind="EXECUTE",operations=["BUILD"],mode="READ_ONLY",
                        method_id="MOTION_F_SAFE_TEST",attempt_id="UNRESERVED_ATTEMPT",
                        authorization_run_id="7005")
      p=td/"A05_UNRESERVED_EXECUTE.json";write(p,unreserved)
      got=validate(LOCK,SIDE,p)
      mark("A05_UNRESERVED_EXECUTE","DENY",got["status"],got["reasons"],
           "EXECUTE_REQUIRES_RESERVED_ATTEMPT")
      stale=base_req(s);stale["input_public_lock_sha256"]="0"*64
      p=td/"A06_STALE_SHA.json";write(p,stale)
      got=validate(LOCK,SIDE,p)
      mark("A06_STALE_SHA","DENY",got["status"],got["reasons"],
           "STALE_OR_WRONG_PUBLIC_LOCK_SHA")
      # A08-A10: conflicting Candidate, null Closure, and terminal no-reopen.
      simulation("A08_CONFLICTING_CANDIDATE",closed,
                 lambda h: ev("CLOSE","7001",pin,cand="b"*64),
                 expected="DENY",required="CLOSED_ATTEMPT_REOPEN_OR_REPLAY",
                 req_patch=lambda q: q.update(authorization_run_id="7006"))
      null_closed,_=simulation("A09_NULL_CLOSURE_TERMINAL",first,
                 lambda h: ev("CLOSE","7001",pin,cand=None),
                 expected="PASS",req_patch=lambda q: q.update(authorization_run_id="7007"))
      simulation("A10_CLOSED_REOPEN",closed,
                 lambda h: ev("START","7001",pin),
                 expected="DENY",required="CLOSED_ATTEMPT_REOPEN_OR_REPLAY",
                 req_patch=lambda q: q.update(authorization_run_id="7008"))
      # A11-A14: immutable prefix, historic GEN29 and competing-PR stale-base.
      simulation("A11_LEDGER_EDIT",first,expected="DENY",
                 required="ATTEMPT_LEDGER_IMMUTABLE_PREFIX_CHANGED",
                 prop_patch=lambda p: p.update(attempt_ledger=[]))
      simulation("A12_GEN29_RECEIPT_TAMPER",s,expected="DENY",
                 required="HISTORICAL_RECEIPT_MUTATED",
                 prop_patch=lambda p: p["gen29_attempt01_forensic_closeout_receipt"].update(status="REOPENED"))
      simulation("A13_HISTORIC_FAILURE_WEAKENING",s,expected="DENY",
                 required="LEDGER_REMOVAL_FORBIDDEN",
                 prop_patch=lambda p: p["ledger_hashes"]["method_fail"].pop())
      competing=copy.deepcopy(s)
      competing["generation"]=s["generation"]+1
      competing["previous_public_lock_sha256"]="0"*64
      simulation("A14_STALE_COMPETING_PR",first,override_prop=competing,
                 expected="DENY",required="PREDECESSOR_PUBLIC_LOCK_SHA_MISMATCH")
      # A15: forged authorization Run and scope cannot pass official gate.
      req=base_req(s)
      req.update(requested_action_id="MOCK_OWNER_GATE_ACTION",action_kind="GOVERNANCE_UPGRADE",
                 operations=["GOVERNANCE_UPGRADE","PATCH"],mode="MUTATING",
                 authorization_run_id="7010",target_scope_ids=["gate/publication_gate.py"])
      auth={"schema":"GLOBAL_PUBLICATION_MANUAL_AUTHORIZATION/1.0.0",
            "authorization_id":"7009","github_run_id":"7009",
            "public_lock_sha256":sha(LOCK),
            "private_execution_state_sha256":s["private_execution_state_sha256"],
            "requested_action_id":"MOCK_OWNER_GATE_ACTION","action_kind":"GOVERNANCE_UPGRADE",
            "project":"GLOBAL","operations":["GOVERNANCE_UPGRADE","PATCH"],
            "target_scope_ids":["UNAUTHORIZED_FILE"],"manual_workflow":True}
      p=td/"A15_FORGED_RUN_SCOPE.json";write(p,req)
      got=validate(LOCK,SIDE,p,auth)
      mark("A15_FORGED_RUN_SCOPE","DENY",got["status"],got["reasons"],
           "AUTHORIZATION_RUN_ID_MISMATCH")
      normal=base_req(s); p=td/"A16_READ_ONLY.json";write(p,normal)
      got=validate(LOCK,SIDE,p)
      mark("A16_READ_ONLY","ALLOW",got["status"],got["reasons"])
      simulation("A17_PREMATURE_GATE_ACTIVATION",s,expected="DENY",
                 required="ACTIVATION_REQUIRES_INDEPENDENT_TRUSTED_BASE_PROOF",
                 prop_patch=lambda p: p.update(runtime_gate_activation_verified=True))
      # T18-T21: canceled/no-candidate Closeout, SHA pin, activation, path allowlist.
      simulation("T18_NULL_CLOSEOUT_REPLAY",null_closed,
                 lambda h: ev("START","7001",pin),
                 expected="DENY",required="CLOSED_ATTEMPT_REOPEN_OR_REPLAY",
                 req_patch=lambda q: q.update(authorization_run_id="7011"))
      simulation("T19_WRONG_RESERVATION_SOURCE",s,
                 lambda h: ev("RESERVE","7012","0"*64,aid="MOTION_F_TEST_19"),
                 expected="DENY",required="RESERVATION_SOURCE_LOCK_SHA_MISMATCH")
      simulation("T20_PR_PASS_IS_NOT_ACTIVATION",s,expected="DENY",
                 required="IMPLEMENTATION_STATUS_REQUIRES_POST_MERGE_PROOF",
                 prop_patch=lambda p: p.update(gate_hardening_implemented=True))
      motion_f_req={"requested_action_id":MOTION_F_ACTION,"action_kind":"GOVERNANCE_UPGRADE",
           "target_scope_ids":["gate/publication_gate.py","gate/transition_guard.py",
                  "scripts/ci_validate_pr.py","scripts/selftest.py"],
           "operations":["GOVERNANCE_UPGRADE","PATCH"]}
      violations=validate_motion_f_changed_paths(
             ["gate/publication_gate.py",".github/workflows/authorize-next-action.yml"],
             motion_f_req,s)
      mark("T21_WORKFLOW_FILE_ALLOWLIST","DENY","DENY" if violations else "ALLOW",
           violations,"MOTION_F_FILE_ALLOWLIST_VIOLATION")

    report={"schema":"GLOBAL_PUBLICATION_PUBLIC_LOCK_SELFTEST/1.0.0","total":len(out),"passed":sum(1 for x in out if x[3]),"status":"PASS" if all(x[3] for x in out) else "FAIL","results":[{"id":a,"expected":b,"actual":c,"pass":d,"reasons":e} for a,b,c,d,e in out]}
    print(json.dumps(report,indent=2))
    return 0 if report["status"]=="PASS" else 1

if __name__=="__main__": raise SystemExit(main())
