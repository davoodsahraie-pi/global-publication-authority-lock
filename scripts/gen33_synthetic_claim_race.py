#!/usr/bin/env python3
"""GEN33 synthetic-only Git tag race. No Producer, no manuscript or output.

CODE INSTALLATION IS NOT EXECUTION AUTHORIZATION. Every manual claim run must
have its own *later*, fresh owner-issued authorization artifact, bound to the
same protected main SHA. Two independent jobs can each POST once to the same
immutable claim ref; all unknown outcomes fail closed without retries.
"""
from __future__ import annotations
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone

REPO="davoodsahraie-pi/global-publication-authority-lock"
OWNER="davoodsahraie-pi"
RULESET_ID=26070404
RULESET_NODE_ID="RRS_lACqUmVwb3NpdG9yec5UXi5YzgGNzYQ"
RULESET_UPDATED_AT="2026-10-28T22:54:47.017+03:30"
RULESET_NAME="GEN33-PROTECTED-CLAIM-IMMUTABLE"
REF_PREFIX="refs/tags/gen33-execution-claim/"
REF_PATTERN=REF_PREFIX+"*"
PUBLIC_SHA="08c2c4c23f1223c7a05554ac81f5f1bac948ac805d28503ca1b0be890b5474fa"
PRIVATE_SHA="dfe3488ff09feba990938953c0caab822a01b90c32cc687d11c08f80d0818ed1"
OWNER_ACTION="GLOBAL_PUBLICATION_GEN33_SYNTHETIC_CLAIM_RACE_V1_EXECUTE_NO_PRODUCER"
SCOPES=["GEN33_SYNTHETIC_GIT_TAG_CLAIM_ONLY","RULESET_ID_26070404",
        "NO_PRODUCER_NO_PRIVATE_PAYLOAD_NO_DOCX_PDF","GEN29_ATTEMPT01_NO_RETRY"]
WORKFLOW=".github/workflows/gen33-synthetic-claim-race.yml"
HEX40=re.compile(r"^[0-9a-f]{40}$")
API_ROOT="https://api.github.com/repos/"+REPO

class Deny(RuntimeError): pass

def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=True,
                      allow_nan=False).encode("ascii")

def ref_for_owner_run(run_id):
    if not isinstance(run_id,str) or not re.fullmatch(r"[1-9][0-9]{4,19}",run_id):
        raise Deny("OWNER_RUN_ID_INVALID")
    identity=["GLOBAL","GEN33_SYNTHETIC_TAG_RACE_NO_PRODUCER","AUTH_"+run_id]
    return REF_PREFIX+hashlib.sha256(canonical(identity)).hexdigest()

def same_time(first,second):
    try:
        dt=lambda v: datetime.fromisoformat(v.replace("Z","+00:00")).astimezone(timezone.utc)
        return dt(first)==dt(second)
    except (TypeError,AttributeError,ValueError):return False

def ruleset_check(rule):
    if not isinstance(rule,dict):raise Deny("RULESET_UNAVAILABLE")
    required={"id":RULESET_ID,"node_id":RULESET_NODE_ID,"name":RULESET_NAME,
              "target":"tag","source_type":"Repository","source":REPO,
              "enforcement":"active"}
    for key,val in required.items():
        if rule.get(key)!=val:raise Deny("RULESET_"+key.upper()+"_DRIFT")
    if not same_time(rule.get("updated_at"),RULESET_UPDATED_AT):
        raise Deny("RULESET_VERSION_DRIFT")
    if rule.get("conditions")!={"ref_name":{"include":[REF_PATTERN],"exclude":[]}}:
        raise Deny("RULESET_REF_PATTERN_DRIFT")
    rules=rule.get("rules")
    if not isinstance(rules,list) or len(rules)!=3 or not all(isinstance(x,dict) for x in rules):
        raise Deny("RULESET_RULES_INVALID")
    if {x.get("type") for x in rules}!={"deletion","non_fast_forward","update"}:
        raise Deny("RULESET_RULES_DRIFT")
    # The owner independently verified zero bypass on this exact immutable
    # ruleset version. GitHub may hide bypass_actors from the Actions token.
    # Redaction alone is NOT fresh independent proof of zero bypass.
    if "bypass_actors" in rule and rule["bypass_actors"]!=[]:
        raise Deny("RULESET_BYPASS_FOUND")
    if "current_user_can_bypass" in rule and rule["current_user_can_bypass"]!="never":
        raise Deny("RULESET_ACTOR_BYPASS_FOUND")
    return "PINNED_OWNER_RULESET_VERSION_MATCH"

def classify(status,data,ref,commit):
    if status==201 and isinstance(data,dict) and data.get("ref")==ref:
        obj=data.get("object")
        if isinstance(obj,dict) and obj.get("sha")==commit and obj.get("type")=="commit":
            return "WON_SYNTHETIC_ONLY"
    if status in (409,422):return "CONFLICT_NO_WIN"
    return "UNKNOWN_NO_RETRY"

def verify_local_authority(root):
    root=Path(root)
    content=(root/"authority/CURRENT.json").read_bytes()
    if hashlib.sha256(content).hexdigest()!=PUBLIC_SHA:raise Deny("PUBLIC_LOCK_CHANGED")
    if (root/"authority/CURRENT.sha256").read_text().split()[0]!=PUBLIC_SHA:
        raise Deny("SIDECAR_CHANGED")
    state=json.loads(content)
    if state.get("generation")!=33 or state.get("private_execution_state_sha256")!=PRIVATE_SHA:
        raise Deny("PRIVATE_STATE_OR_GENERATION_CHANGED")
    if (state.get("current_action") or {}).get("mode")!="READ_ONLY" or state.get("execution_authorized_now") is not False:
        raise Deny("REAL_EXECUTION_MUST_REMAIN_DISABLED")
    if (state.get("gen29_attempt01_forensic_closeout_receipt") or {}).get("status")!="CONSUMED_CLOSED":
        raise Deny("GEN29_CLOSEOUT_CHANGED")

def verify_runner(env):
    if env.get("GITHUB_REPOSITORY")!=REPO or env.get("GITHUB_ACTOR","").lower()!=OWNER:
        raise Deny("RUNNER_REPO_OR_ACTOR")
    if env.get("GITHUB_EVENT_NAME")!="workflow_dispatch" or env.get("GITHUB_REF")!="refs/heads/main":
        raise Deny("RUNNER_NOT_MANUAL_MAIN")
    if env.get("GITHUB_RUN_ATTEMPT")!="1":
        raise Deny("RUNNER_RERUN_FORBIDDEN")
    if env.get("GITHUB_WORKFLOW_REF")!=REPO+"/"+WORKFLOW+"@refs/heads/main":
        raise Deny("RUNNER_WORKFLOW_REF_MISMATCH")
    commit=env.get("GITHUB_SHA","")
    if not HEX40.fullmatch(commit):raise Deny("RUNNER_COMMIT_INVALID")
    return commit

def verify_owner_artifact(auth,run_id):
    if not isinstance(auth,dict):raise Deny("OWNER_AUTH_NOT_JSON_OBJECT")
    expect={"schema":"GLOBAL_PUBLICATION_MANUAL_AUTHORIZATION/1.0.0",
       "authorization_id":run_id,"github_run_id":run_id,"github_actor":OWNER,
       "manual_workflow":True,"public_lock_sha256":PUBLIC_SHA,
       "private_execution_state_sha256":PRIVATE_SHA,
       "requested_action_id":OWNER_ACTION,"action_kind":"GOVERNANCE_UPGRADE",
       "project":"GLOBAL","operations":["GOVERNANCE_UPGRADE"],"target_scope_ids":SCOPES}
    for key,val in expect.items():
        if auth.get(key)!=val:raise Deny("OWNER_AUTH_MISMATCH_"+key.upper())
    return True

class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        next_req=super().redirect_request(req,fp,code,msg,headers,newurl)
        if next_req is not None and urllib.parse.urlsplit(newurl).hostname!="api.github.com":
            next_req.headers.pop("Authorization",None)
            next_req.unredirected_hdrs.pop("Authorization",None)
        return next_req

def api(method,path,token,payload=None,binary=False):
    if not token:raise Deny("TOKEN_REQUIRED")
    body=None if payload is None else canonical(payload)
    request=urllib.request.Request(API_ROOT+path,data=body,method=method,
        headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json",
        "X-GitHub-Api-Version":"2022-11-28","User-Agent":"gen33-synthetic-only",
        "Content-Type":"application/json"})
    opener=urllib.request.build_opener(SafeRedirect())
    try:
        with opener.open(request,timeout=15) as response:
            status=response.status
            raw=response.read(2_000_000 if binary else 131072)
    except urllib.error.HTTPError as error:
        status=error.code
        raw=error.read(65536)
    if binary:return status,raw
    try:return status,json.loads(raw.decode("utf-8")) if raw else {}
    except (ValueError,UnicodeError):return status,None

def auth_remote(token,run_id,sha):
    status,run=api("GET","/actions/runs/"+run_id,token)
    if status!=200 or not isinstance(run,dict):raise Deny("OWNER_RUN_NOT_FOUND")
    if (run.get("conclusion")!="success" or run.get("status")!="completed" or
       run.get("event")!="workflow_dispatch" or run.get("path")!=".github/workflows/authorize-next-action.yml" or
       run.get("head_branch")!="main" or run.get("head_sha")!=sha or
       run.get("run_attempt")!=1 or (run.get("actor") or {}).get("login","").lower()!=OWNER):
        raise Deny("OWNER_RUN_PROVENANCE_MISMATCH")
    status,results=api("GET","/actions/runs/"+run_id+"/artifacts?per_page=100",token)
    if status!=200 or not isinstance(results,dict):raise Deny("OWNER_ARTIFACTS_UNAVAILABLE")
    matches=[x for x in results.get("artifacts",[])
             if x.get("name")=="publication-authorization-"+run_id and not x.get("expired")]
    if len(matches)!=1 or not isinstance(matches[0].get("id"),int):
        raise Deny("OWNER_ARTIFACT_AMBIGUOUS_OR_MISSING")
    status,archive=api("GET","/actions/artifacts/"+str(matches[0]["id"])+"/zip",token,binary=True)
    if status!=200:raise Deny("OWNER_AUTH_ZIP_UNAVAILABLE")
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            if z.namelist()!=["authorization.json"]:raise Deny("OWNER_ZIP_UNEXPECTED_MEMBERS")
            info=z.getinfo("authorization.json")
            if info.file_size>8192:raise Deny("OWNER_AUTH_TOO_LARGE")
            auth=json.loads(z.read("authorization.json").decode("utf-8"))
    except (zipfile.BadZipFile,KeyError,ValueError,UnicodeError) as error:
        raise Deny("OWNER_AUTH_ZIP_INVALID") from error
    verify_owner_artifact(auth,run_id)

def protected_preflight(env,token,run_id,root,require_absent=False):
    sha=verify_runner(env)
    verify_local_authority(root)
    if not isinstance(run_id,str) or not re.fullmatch(r"[1-9][0-9]{4,19}",run_id):
        raise Deny("FRESH_OWNER_RUN_REQUIRED")
    auth_remote(token,run_id,sha)
    status,rule=api("GET","/rulesets/"+str(RULESET_ID),token)
    if status!=200:raise Deny("RULESET_GET_FAILED")
    ruleset_check(rule)
    ref=ref_for_owner_run(run_id)
    # Only the standalone preflight job checks absence; claim competitors must\n    # both POST once and receive one 201 and one 422, even if scheduled later.
    if require_absent:
        status,existing=api("GET","/git/ref/"+ref[len("refs/"):],token)
        if status==200:raise Deny("CLAIM_ALREADY_PRESENT_NO_RETRY")
        if status!=404:raise Deny("CLAIM_PREEXISTENCE_UNKNOWN")
    return sha,ref

def output(value):
    dest=os.environ.get("GITHUB_OUTPUT")
    if dest:
        with Path(dest).open("a",encoding="utf-8") as f:f.write("outcome="+value+"\n")

def stage(mode,root=None,env=None,token=None,run_id=None):
    env=os.environ if env is None else env
    token=env.get("GH_TOKEN","") if token is None else token
    run_id=env.get("OWNER_AUTH_RUN_ID","") if run_id is None else run_id
    root=Path(__file__).resolve().parents[1] if root is None else root
    try:
        commit,ref=protected_preflight(env,token,run_id,root,require_absent=(mode=="preflight"))
        if mode=="preflight":
            print("GEN33_SYNTHETIC_PREFLIGHT_PASS_NO_CLAIM")
            return 0
        if mode=="claim":
            # Exactly ONE POST. No retry on network errors or any outcome.
            status,data=api("POST","/git/refs",token,{"ref":ref,"sha":commit})
            outcome=classify(status,data,ref,commit)
            output(outcome)
            print("GEN33_SYNTHETIC_CLAIM="+outcome+" HTTP="+str(status))
            return 0 if outcome in ("WON_SYNTHETIC_ONLY","CONFLICT_NO_WIN") else 3
        if mode=="verify":
            if env.get("PREFLIGHT")!="success" or sorted(
                (env.get("OUTCOME_A"),env.get("OUTCOME_B"))
            )!=["CONFLICT_NO_WIN","WON_SYNTHETIC_ONLY"]:
                raise Deny("COMPETITOR_OUTCOME_NOT_ONE_WIN_ONE_CONFLICT")
            status,data=api("GET","/git/ref/"+ref[len("refs/"):],token)
            if (status!=200 or not isinstance(data,dict) or
                data.get("ref")!=ref or (data.get("object") or {}).get("sha")!=commit):
                raise Deny("FINAL_REF_MISMATCH")
            print("GEN33_SYNTHETIC_RACE_ONE_WIN_ONE_DENY_NO_PRODUCER")
            return 0
        raise Deny("UNKNOWN_MODE")
    except (Deny,OSError,ValueError,urllib.error.URLError,TimeoutError) as exc:
        output("UNKNOWN_NO_RETRY" if mode=="claim" else "DENY")
        print("GEN33_FAIL_CLOSED "+(str(exc) if isinstance(exc,Deny) else type(exc).__name__))
        return 3

def main():
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("mode",choices=("selftest","preflight","claim","verify"))
    args=parser.parse_args()
    if args.mode=="selftest":
        print(json.dumps({"schema":"GEN33_SYNTHETIC_RACE/1.0","active":False,
                          "physical_claim_executed":False,"producer_enabled":False,
                          "test_only":True}))
        return 0
    return stage(args.mode)

if __name__=="__main__":
    sys.exit(main())
