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

    report={"schema":"GLOBAL_PUBLICATION_PUBLIC_LOCK_SELFTEST/1.0.0","total":len(out),"passed":sum(1 for x in out if x[3]),"status":"PASS" if all(x[3] for x in out) else "FAIL","results":[{"id":a,"expected":b,"actual":c,"pass":d,"reasons":e} for a,b,c,d,e in out]}
    print(json.dumps(report,indent=2))
    return 0 if report["status"]=="PASS" else 1

if __name__=="__main__": raise SystemExit(main())
