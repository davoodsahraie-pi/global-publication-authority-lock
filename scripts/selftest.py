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
        # Synthetic Motion-F baseline tests now carry the durable event Run.
        # Historic records and production state are not migrated.
        if event is not None and event["event"] in {"START","CLOSE"}:
            event["event_authorization_run_id"]=request["authorization_run_id"]
            if event["event"]=="START" or (source.get("attempt_ledger",[]) and
                 source["attempt_ledger"][-1]["event"]=="START"):
                event["executor_id"]="MOTION_F_TEST_EXECUTOR"
                request["executor_id"]="MOTION_F_TEST_EXECUTOR"
            proposed["attempt_ledger"][-1]=event
            write(to_path,proposed)
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

      # Atomic completion: negative tests of the actual protected event protocol.
      # These are pure synthetic state inputs, never official claims.
      from transition_guard import attempt_snapshot
      def event_case(name,source,event,request_run,expected,required=None,executor=None):
        cp=td/(name+"-old.json"); write(cp,source)
        proposed=copy.deepcopy(source)
        proposed["generation"]=source["generation"]+1
        proposed["previous_public_lock_sha256"]=sha(cp)
        proposed["attempt_ledger"]=copy.deepcopy(source.get("attempt_ledger",[]))+[event]
        pp=td/(name+"-new.json"); write(pp,proposed)
        req={"action_kind":"GOVERNANCE_UPGRADE", "operations":["GOVERNANCE_UPGRADE","PATCH"],
             "project":"GLOBAL","method_id":"MOTION_F_SAFE_TEST",
             "attempt_id":event.get("attempt_id"),"authorization_run_id":request_run,
             "input_public_lock_sha256":sha(cp),"executor_id":executor}
        result=validate_transition(cp,pp,req)
        mark(name,expected,result["status"],result["reasons"],required)
      # A single reservation and START are already generated in the historical suite.
      def fresh(kind,auth,executor=None,candidate=None):
        result=ev(kind,"7001",pin,cand=candidate)
        if kind!="RESERVE":
            result["event_authorization_run_id"]=str(auth)
            if executor is not None: result["executor_id"]=executor
        return result
      event_case("AT01_START_REQUIRES_EVENT_RUN",first,
                 ev("START","7001",pin),"7030","DENY","ATTEMPT_EVENT_AUTH_RUN_INVALID")
      event_case("AT02_START_MATCHES_REQUEST_RUN",first,
                 fresh("START","7031","test-executor"),"7032","DENY","ATTEMPT_EVENT_AUTH_RUN_MISMATCH", "test-executor")
      event_case("AT03_START_REUSES_RESERVATION_RUN",first,
                 fresh("START","7001","test-executor"),"7001","DENY","AUTHORIZATION_RUN_ALREADY_CONSUMED", "test-executor")
      event_case("AT04_START_REQUIRES_EXECUTOR_ID",first,
                 fresh("START","7033"),"7033","DENY","START_EXECUTOR_ID_REQUIRED")
      event_case("AT05_START_EXECUTOR_MISMATCH",first,
                 fresh("START","7034","test-executor"),"7034","DENY","ATTEMPT_EXECUTOR_REQUEST_MISMATCH","wrong-executor")
      event_case("AT06_START_CLAIM_PASS",first,
                 fresh("START","7035","test-executor"),"7035","PASS",executor="test-executor")
      event_case("AT07_REPLAY_START",started,
                 fresh("START","7036","MOTION_F_TEST_EXECUTOR"),"7036","DENY","ATTEMPT_START_REPLAY","MOTION_F_TEST_EXECUTOR")
      event_case("AT08_CLOSE_EXECUTOR_MISMATCH",started,
                 fresh("CLOSE","7037","other-executor",candidate="a"*64),"7037","DENY","ATTEMPT_EXECUTOR_ID_CHANGED","other-executor")
      event_case("AT09_CLOSE_UNSTARTED_WITH_CANDIDATE",first,
                 fresh("CLOSE","7038",candidate="a"*64),"7038","DENY","UNSTARTED_ATTEMPT_HAS_CANDIDATE")
      event_case("AT10_CLOSE_REUSES_START_RUN",started,
                 fresh("CLOSE","7003","MOTION_F_TEST_EXECUTOR"),"7003","DENY","AUTHORIZATION_RUN_ALREADY_CONSUMED","MOTION_F_TEST_EXECUTOR")
      event_case("AT11_CLOSE_TERMINAL_PASS",started,
                 fresh("CLOSE","7039","MOTION_F_TEST_EXECUTOR",candidate="a"*64),"7039","PASS",executor="MOTION_F_TEST_EXECUTOR")
      event_case("AT12_HISTORIC_GEN29_RUN_REJECT",first,
                 fresh("START","40329927057","test-executor"),"40329927057","DENY","AUTHORIZATION_RUN_ALREADY_CONSUMED","test-executor")
      event_case("AT13_NULL_CLOSE_ONLY_UNSTARTED",first,
                 fresh("CLOSE","7040"),"7040","PASS")
      event_case("AT14_EVENT_EXECUTOR_MUST_MATCH_REQUEST",started,
                 fresh("CLOSE","7041","MOTION_F_TEST_EXECUTOR"),"7041","DENY","ATTEMPT_EXECUTOR_REQUEST_MISMATCH","other-executor")
      # Gate must fail closed even when a claim has been committed, because the
      # separately governed one-use external executor is not yet installed.
      synthetic=copy.deepcopy(s)
      synthetic["current_action"]={"id":"ATOMIC-SYNTHETIC-EXECUTE","mode":"MUTATING"}
      synthetic["execution_authorized_now"]=True
      for name,events,run,executor,required in [
          ("AT15_RESERVED_CANNOT_EXECUTE",first["attempt_ledger"],"7042","test-executor","EXECUTE_REQUIRES_COMMITTED_START_CLAIM"),
          ("AT16_CLAIMED_CANNOT_DISPATCH_WITHOUT_BROKER",started["attempt_ledger"],"7003","MOTION_F_TEST_EXECUTOR","EXECUTE_REQUIRES_DURABLE_ONE_USE_DISPATCH_RECEIPT"),
          ("AT17_WRONG_CLAIM_RUN",started["attempt_ledger"],"7043","MOTION_F_TEST_EXECUTOR","EXECUTE_AUTH_RUN_NOT_CLAIM_OWNER"),
          ("AT18_WRONG_EXECUTOR",started["attempt_ledger"],"7003","wrong-executor","EXECUTE_EXECUTOR_ID_MISMATCH")]:
        state=copy.deepcopy(synthetic);state["attempt_ledger"]=copy.deepcopy(events)
        loc=td/(name+"-lock.json");write(loc,state)
        side=td/(name+"-lock.sha256");side.write_text(sha(loc)+"  lock.json\n")
        rq={"schema":"GLOBAL_PUBLICATION_PUBLIC_ACTION_REQUEST/1.0.0","request_id":name,
            "input_public_lock_sha256":sha(loc),"input_private_state_sha256":state["private_execution_state_sha256"],
            "requested_action_id":"ATOMIC-SYNTHETIC-EXECUTE","action_kind":"EXECUTE","mode":"MUTATING",
            "project":"GLOBAL","method_id":"MOTION_F_SAFE_TEST","attempt_id":"MOTION_F_TEST_01",
            "operations":["BUILD"],"authorization_run_id":run,
            "target_scope_ids":[],"executor_id":executor,"user_explicit_authorization":True}
        path=td/(name+"-request.json");write(path,rq)
        got=validate(loc,side,path)
        mark(name,"DENY",got["status"],got["reasons"],required)
      # Non-string malformed source pins fail closed instead of throwing.
      try:
        bad_ev=fresh("START","7044","MOTION_F_TEST_EXECUTOR")
        bad_ev["reservation_source_public_sha256"]=None
        attempt_snapshot(first["attempt_ledger"]+[bad_ev])
        mark("AT19_NULL_PIN_DENY","DENY","ALLOW",["missing validation"])
      except ValueError as error:
        mark("AT19_NULL_PIN_DENY","DENY","DENY",[str(error)],"ATTEMPT_PROVENANCE_INVALID")


      # GEN32 DISPATCH v2 synthetic control-plane tests. No producer invocation.
      from transition_guard import DISPATCH_V2_SCHEMA, dispatch_v2_descriptor
      from ci_validate_pr import validate_dispatch_v2_changed_paths, DISPATCH_V2_ACTION, DISPATCH_V2_PATHS, DISPATCH_V2_SCOPES
      def v2_event(source,label,source_pub,source_priv,auth="8101",purpose="INDEPENDENT_ENGINEERING_FIXTURE"):
          entry={"schema":DISPATCH_V2_SCHEMA,"event":"DISPATCH","project_id":"GLOBAL",
                 "method_id":"MOTION_F_SAFE_TEST","attempt_id":"MOTION_F_TEST_01",
                 "owner_authorization_run_id":"7001",
                 "reservation_source_public_sha256":pin,
                 "event_authorization_run_id":auth,
                 "executor_id":"MOTION_F_TEST_EXECUTOR",
                 "dispatch_source_public_sha256":source_pub,
                 "dispatch_source_private_sha256":source_priv,
                 "purpose":purpose,"output_identity":"QUARANTINED_SYNTHETIC_OUTPUT",
                 "runtime_domain":"TRUSTED_CANDIDATE_TEST_ONLY",
                 "candidate_sha256":None}
          from transition_guard import DISPATCH_V2_SHA_FIELDS
          for f in DISPATCH_V2_SHA_FIELDS: entry[f]="a"*64
          entry["descriptor_sha256"]=dispatch_v2_descriptor(entry)
          return entry
      def v2_check(label,source,mutate=None,expect="PASS",required=None,auth="8101",request_executor="MOTION_F_TEST_EXECUTOR"):
          cp=td/(label+"-v2-source.json");write(cp,source)
          oldsha=sha(cp)
          event=v2_event(source,label,oldsha,source["private_execution_state_sha256"],auth=auth)
          if mutate: mutate(event)
          pp=td/(label+"-v2-new.json")
          proposed=copy.deepcopy(source)
          proposed["generation"]=source["generation"]+1
          proposed["previous_public_lock_sha256"]=oldsha
          proposed["attempt_ledger"]=copy.deepcopy(source.get("attempt_ledger",[]))+[event]
          write(pp,proposed)
          request={"action_kind":"GOVERNANCE_UPGRADE","operations":["GOVERNANCE_UPGRADE","PATCH"],
                   "project":"GLOBAL","method_id":"MOTION_F_SAFE_TEST","attempt_id":"MOTION_F_TEST_01",
                   "authorization_run_id":auth,"input_public_lock_sha256":oldsha,
                   "executor_id":request_executor}
          result=validate_transition(cp,pp,request)
          mark(label,expect,result["status"],result["reasons"],required)
          return proposed,event
      dispatched,original_dispatch=v2_check("DV01_VALID_CONTROL_PLANE_DISPATCH",started)
      v2_check("DV02_NO_START",first,expect="DENY",required="DISPATCH_REQUIRES_STARTED_ATTEMPT")
      v2_check("DV03_DUPLICATE_DISPATCH",dispatched,auth="8102",expect="DENY",required="DISPATCH_REQUIRES_STARTED_ATTEMPT")
      v2_check("DV04_REUSE_START_RUN",started,auth="7003",expect="DENY",required="AUTHORIZATION_RUN_ALREADY_CONSUMED")
      def change_pinned_sha(e,field):
          e[field]="0"*64
          e["descriptor_sha256"]=dispatch_v2_descriptor(e)
      v2_check("DV05_WRONG_PUBLIC_SHA",started,mutate=lambda e:change_pinned_sha(e,"dispatch_source_public_sha256"),expect="DENY",required="DISPATCH_PREDECESSOR_PUBLIC_SHA_MISMATCH")
      v2_check("DV06_WRONG_PRIVATE_SHA",started,mutate=lambda e:change_pinned_sha(e,"dispatch_source_private_sha256"),expect="DENY",required="DISPATCH_PREDECESSOR_PRIVATE_SHA_MISMATCH")
      v2_check("DV07_EXECUTOR_MISMATCH",started,request_executor="wrong",expect="DENY",required="DISPATCH_EXECUTOR_REQUEST_MISMATCH")
      v2_check("DV08_MATERIAL_HASH_MISSING",started,mutate=lambda e:e.update(c1_sha256=None),expect="DENY",required="DISPATCH_MATERIAL_SHA_INVALID")
      v2_check("DV09_DESCRIPTOR_FORGERY",started,mutate=lambda e:e.update(descriptor_sha256="0"*64),expect="DENY",required="DISPATCH_DESCRIPTOR_INVALID")
      v2_check("DV10_RUN_REPLAY",started,auth="7001",expect="DENY",required="AUTHORIZATION_RUN_ALREADY_CONSUMED")
      # A v1 close must not silently close a v2-dispatched attempt.
      event_case("DV11_V1_CLOSE_CANNOT_CLOSE_V2",dispatched,
                 fresh("CLOSE","8103","MOTION_F_TEST_EXECUTOR"),"8103",
                 "DENY","DISPATCHED_ATTEMPT_REQUIRES_V2_CLOSE","MOTION_F_TEST_EXECUTOR")
      valid_changes=list(DISPATCH_V2_PATHS)
      scoped={"requested_action_id":DISPATCH_V2_ACTION,"action_kind":"GOVERNANCE_UPGRADE",
              "operations":["GOVERNANCE_UPGRADE","PATCH"],
              "target_scope_ids":list(DISPATCH_V2_SCOPES)}
      bad=validate_dispatch_v2_changed_paths(valid_changes+[".github/workflows/authorize-next-action.yml"],scoped,s,ROOT)
      mark("DV12_WORKFLOW_OUT_OF_SCOPE","DENY","DENY" if bad else "ALLOW",bad,"DISPATCH_V2_EXACT_FIVE_PATHS_REQUIRED")
      # The live head carries patched files; it is never its own trusted preimage.
      # Positive preimage validation is performed by CI against separate base checkout.
      missing_base=validate_dispatch_v2_changed_paths(valid_changes,scoped,s,None)
      mark("DV13_TRUSTED_BASE_REQUIRED","DENY","DENY" if missing_base else "ALLOW",missing_base,
           "DISPATCH_V2_TRUSTED_BASE_REQUIRED")
      # A control-plane event never authorizes direct CLI execution.
      synthetic=copy.deepcopy(s)
      synthetic["current_action"]={"id":"DV14_NOT_LAUNCHABLE","mode":"MUTATING"}
      synthetic["execution_authorized_now"]=True
      synthetic["attempt_ledger"]=dispatched["attempt_ledger"]
      lock=td/"DV14-lock.json";write(lock,synthetic)
      side=td/"DV14-lock.sha256";side.write_text(sha(lock)+"  lock.json\n")
      rq={"schema":"GLOBAL_PUBLICATION_PUBLIC_ACTION_REQUEST/1.0.0","request_id":"DV14",
          "input_public_lock_sha256":sha(lock),"input_private_state_sha256":synthetic["private_execution_state_sha256"],
          "requested_action_id":"DV14_NOT_LAUNCHABLE","action_kind":"EXECUTE","mode":"MUTATING",
          "project":"GLOBAL","method_id":"MOTION_F_SAFE_TEST","attempt_id":"MOTION_F_TEST_01",
          "operations":["BUILD"],"authorization_run_id":"8101",
          "target_scope_ids":[],"executor_id":"MOTION_F_TEST_EXECUTOR","user_explicit_authorization":True}
      rqpath=td/"DV14-request.json";write(rqpath,rq)
      got=validate(lock,side,rqpath)
      mark("DV14_NO_BROKER_NO_LAUNCH","DENY",got["status"],got["reasons"],"EXECUTE_REQUIRES_DURABLE_ONE_USE_DISPATCH_RECEIPT")
      mark("GEN33_NO_LAUNCH_CODE_ONLY","DENY",got["status"],got["reasons"],"GEN33_BROKER_CODE_ONLY_NOT_ACTIVATED")
      # Synthetic 64-hex receipt is NOT an authenticated Broker attestation.
      # No Broker is installed in the approved control-plane-only patch.
      forged_close=ev("CLOSE","7001",pin,cand=None)
      forged_close.update(schema=DISPATCH_V2_SCHEMA,
           event_authorization_run_id="8104",
           executor_id="MOTION_F_TEST_EXECUTOR",
           terminal_broker_receipt_sha256="c"*64,
           terminal_result="NOT_LAUNCHED",
           dispatch_descriptor_sha256=original_dispatch["descriptor_sha256"])
      event_case("DV15_FORGED_BROKER_RECEIPT_REJECTED",dispatched,
           forged_close,"8104","DENY",
           "V2_CLOSE_REQUIRES_AUTHENTICATED_BROKER_RECEIPT",
           executor="MOTION_F_TEST_EXECUTOR")

    report={"schema":"GLOBAL_PUBLICATION_PUBLIC_LOCK_SELFTEST/1.0.0","total":len(out),"passed":sum(1 for x in out if x[3]),"status":"PASS" if all(x[3] for x in out) else "FAIL","results":[{"id":a,"expected":b,"actual":c,"pass":d,"reasons":e} for a,b,c,d,e in out]}
    print(json.dumps(report,indent=2))
    return 0 if report["status"]=="PASS" else 1

if __name__=="__main__": raise SystemExit(main())
