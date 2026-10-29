#!/usr/bin/env python3
"""Connect the protected Broker to the unchanged original R25R7 Driver.

Installation is code-only. No source/credential delivery or execution is
possible until protected public AND private authority explicitly enable this
contract and a separate owner EXECUTE artifact matches them. Legacy GEN33
proof functions and legacy direct-EXECUTE denial remain unchanged.

Input bundle (private Git blob): manifest.json, private-state.json, source.jsonl,
the original named Generator/Driver, c1.json, grammar.txt, ppges.zip,
dependency-lock.json and hash-pinned wheels/*.whl. Manifest lists every file
except itself. Dependency lock is {"schema":"GEN34_WHEELS/1.0","wheels":
{"wheels/<filename>.whl":"<sha256>"}}. No network package installation.

Secrets must be Environment secrets, NOT repository secrets: GEN34_PRIVATE_TOKEN
(Contents read/write on the named private custody repository only) and
GEN34_RECEIPT_KEY_HEX (32 random bytes as 64 hex characters). The environment's
deployment-branch policy must allow only main. Public logs contain fixed codes
and hashes only. No public Actions artifacts are uploaded by this workflow.
"""
import argparse
import base64
import datetime as dt
import hashlib
import hmac
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"gate"))
sys.path.insert(0,str(ROOT/"broker"))
from publication_gate import validate_gen34_admission, REQ_SCHEMA
from transition_guard import GEN34_PINS, gen34_activation_errors, gen34_descriptor
from gen33_source_bound_broker import REAL_NAMESPACE, expected_claim_ref
from gen33_live_claim import verify_ruleset
from gen33_receipt_verifier import canonical, verify_terminal_receipt, RECEIPT_SCHEMA

REPO="davoodsahraie-pi/global-publication-authority-lock"
PRIVATE_REPO="davoodsahraie-pi/global-publication-authority"
OWNER="davoodsahraie-pi"
WORKFLOW=".github/workflows/gen34-r25r7-producer.yml"
ISSUER=REPO+"/"+WORKFLOW
GENERATOR="DJANGO_PPGES135_GENERATOR_R25R7.py"
DRIVER="R25R7_CUMULATIVE_BUILD_DRIVER.py"
MAX_BUNDLE=256*1024*1024
HEX40=re.compile(r"^[0-9a-f]{40}$")
HEX64=re.compile(r"^[0-9a-f]{64}$")

class Denied(RuntimeError):
    """Only fixed, nonsecret codes may be exposed by the entrypoint."""

def require(condition,code):
    if not condition: raise Denied(code)

def sha(data): return hashlib.sha256(data).hexdigest()
def file_sha(path): return sha(Path(path).read_bytes())
def git_blob_sha(data): return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()

def parse_json(data):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,"DUPLICATE_JSON_KEY")
            result[key]=value
        return result
    def bad(_): raise Denied("NONFINITE_JSON")
    return json.loads(data,object_pairs_hook=pairs,parse_constant=bad)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None

class GitHub:
    """One HTTP call per mutation. Never automatically retry or forward tokens."""
    def __init__(self,repo,token):
        require(repo in {REPO,PRIVATE_REPO},"REPOSITORY_NOT_ALLOWED")
        require(isinstance(token,str) and bool(token),"CREDENTIAL_UNAVAILABLE")
        self.repo=repo; self.token=token
        self.opener=urllib.request.build_opener(NoRedirect)

    def request(self,method,path,data=None):
        require((path=="" or path.startswith("/")) and ".." not in path and "\\" not in path,"API_PATH_INVALID")
        url="https://api.github.com/repos/"+self.repo+path
        payload=None if data is None else canonical(data)
        req=urllib.request.Request(url,data=payload,method=method,headers={
            "Authorization":"Bearer "+self.token,"Accept":"application/vnd.github+json",
            "X-GitHub-Api-Version":"2022-11-28","User-Agent":"gen34-r25r7-bridge",
            "Content-Type":"application/json"})
        try:
            with self.opener.open(req,timeout=30) as response:
                raw=response.read(MAX_BUNDLE*2+1)
                require(len(raw)<=MAX_BUNDLE*2,"API_RESPONSE_TOO_LARGE")
                return response.status,parse_json(raw) if raw else None
        except urllib.error.HTTPError as exc:
            # Never include URL, headers, response text or private contents.
            raise Denied("HTTP_"+str(exc.code)) from None
        except (TimeoutError,urllib.error.URLError):
            raise Denied("HTTP_OUTCOME_UNKNOWN_NO_RETRY") from None

    def get(self,path):
        code,result=self.request("GET",path)
        require(code==200,"GET_UNEXPECTED_STATUS")
        return result

    def post(self,path,data):
        code,result=self.request("POST",path,data)
        require(code==201,"WRITE_OUTCOME_UNKNOWN_NO_RETRY")
        return result

    def artifact(self,artifact_id):
        require(self.repo==REPO and type(artifact_id) is int,"ARTIFACT_ID_INVALID")
        req=urllib.request.Request("https://api.github.com/repos/"+REPO+
            "/actions/artifacts/"+str(artifact_id)+"/zip",headers={
                "Authorization":"Bearer "+self.token,"User-Agent":"gen34-r25r7-bridge"})
        try:
            self.opener.open(req,timeout=30)
        except urllib.error.HTTPError as exc:
            require(exc.code in {302,303,307},"ARTIFACT_REDIRECT_REQUIRED")
            location=exc.headers.get("Location","")
        else:
            raise Denied("ARTIFACT_REDIRECT_REQUIRED")
        u=urllib.parse.urlparse(location)
        require(u.scheme=="https" and not u.username and not u.password and u.port in {None,443},"ARTIFACT_REDIRECT_INVALID")
        host=u.hostname or ""
        require(host.endswith((".blob.core.windows.net",".actions.githubusercontent.com",".amazonaws.com")),"ARTIFACT_STORAGE_HOST_INVALID")
        # No Authorization on cross-host storage; no second redirect accepted.
        with self.opener.open(urllib.request.Request(location,headers={"User-Agent":"gen34-r25r7-bridge"}),timeout=30) as response:
            require(response.status==200,"ARTIFACT_DOWNLOAD_FAILED")
            data=response.read(1024*1024+1)
        require(len(data)<=1024*1024,"AUTH_ARTIFACT_TOO_LARGE")
        return data

def blob_bytes(api,oid):
    require(isinstance(oid,str) and HEX40.fullmatch(oid),"GIT_BLOB_ID_INVALID")
    obj=api.get("/git/blobs/"+oid)
    require(obj.get("sha")==oid and obj.get("encoding")=="base64","GIT_BLOB_RESPONSE_INVALID")
    raw=base64.b64decode(obj["content"].replace("\n",""),validate=True)
    require(len(raw)<=MAX_BUNDLE and git_blob_sha(raw)==oid,"GIT_BLOB_READBACK_MISMATCH")
    return raw

def committed_file(api,commit,path):
    require(isinstance(commit,str) and HEX40.fullmatch(commit),"COMMIT_ID_INVALID")
    tree_sha=api.get("/git/commits/"+commit)["tree"]["sha"]
    require(HEX40.fullmatch(str(tree_sha)),"TREE_ID_INVALID")
    tree=api.get("/git/trees/"+tree_sha+"?recursive=1")
    require(tree.get("truncated") is False,"COMMITTED_TREE_TRUNCATED")
    matches=[x for x in tree.get("tree",[]) if x.get("path")==path]
    require(len(matches)==1 and matches[0].get("type")=="blob" and matches[0].get("mode")=="100644","COMMITTED_FILE_INVALID")
    return blob_bytes(api,matches[0]["sha"])

def authenticate_owner(api,run_id,head_sha):
    require(isinstance(run_id,str) and run_id.isdigit(),"AUTH_RUN_ID_INVALID")
    require(run_id not in {"40329927057","40761646972","40818118503"},"NONEXECUTION_RUN_FORBIDDEN")
    run=api.get("/actions/runs/"+run_id)
    require(run.get("id")==int(run_id) and run.get("path")==".github/workflows/authorize-next-action.yml" and
        run.get("event")=="workflow_dispatch" and run.get("conclusion")=="success" and
        run.get("head_branch")=="main" and run.get("head_sha")==head_sha and
        run.get("run_attempt")==1 and run.get("actor",{}).get("login")==OWNER and
        run.get("triggering_actor",{}).get("login")==OWNER,"OWNER_AUTH_PROVENANCE_INVALID")
    arts=api.get("/actions/runs/"+run_id+"/artifacts?per_page=100")
    require(arts.get("total_count")==len(arts.get("artifacts",[])),"AUTH_ARTIFACT_PAGINATION_UNEXPECTED")
    matches=[x for x in arts["artifacts"] if x.get("name")=="publication-authorization-"+run_id]
    require(len(matches)==1 and matches[0].get("expired") is False,"AUTH_ARTIFACT_UNAVAILABLE")
    artifact=matches[0]; raw=api.artifact(artifact["id"])
    require(artifact.get("digest")=="sha256:"+sha(raw),"AUTH_ARCHIVE_DIGEST_MISMATCH")
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        require(z.namelist()==["authorization.json"] and z.getinfo("authorization.json").file_size<65536,"AUTH_ARCHIVE_INVALID")
        auth=parse_json(z.read("authorization.json"))
    require(auth.get("github_actor")==OWNER and auth.get("github_run_id")==run_id and auth.get("authorization_id")==run_id and auth.get("manual_workflow") is True,"AUTH_ARTIFACT_IDENTITY_INVALID")
    issued=dt.datetime.fromisoformat(auth["issued_at_utc"])
    require(issued.tzinfo is not None and 0<=(dt.datetime.now(dt.timezone.utc)-issued).total_seconds()<=86400,"AUTHORIZATION_NOT_FRESH")
    return auth

def verify_platform(api,env,profile):
    require(env.get("GITHUB_REPOSITORY")==REPO and env.get("GITHUB_REF")=="refs/heads/main" and
        env.get("GITHUB_EVENT_NAME")=="workflow_dispatch" and env.get("GITHUB_RUN_ATTEMPT")=="1" and
        env.get("GITHUB_ACTOR")==OWNER and env.get("GITHUB_TRIGGERING_ACTOR")==OWNER,"RUNNER_PROVENANCE_INVALID")
    head=api.get("/git/ref/heads/main")["object"]["sha"]
    require(head==env.get("GITHUB_SHA") and HEX40.fullmatch(head),"RUNNER_NOT_CURRENT_PROTECTED_MAIN")
    run=api.get("/actions/runs/"+env["GITHUB_RUN_ID"])
    require(run.get("head_sha")==head and run.get("path")==WORKFLOW and run.get("run_attempt")==1 and
        run.get("event")=="workflow_dispatch" and run.get("head_branch")=="main" and
        run.get("actor",{}).get("login")==OWNER and run.get("triggering_actor",{}).get("login")==OWNER,"RUNNER_API_PROVENANCE_INVALID")
    for ident in (24932377,24939466):
        rules=api.get("/rulesets/"+str(ident))
        require(rules.get("enforcement")=="active" and rules.get("target")=="branch" and rules.get("bypass_actors")==[] and
            rules.get("conditions",{}).get("ref_name")=={"include":["~DEFAULT_BRANCH"],"exclude":[]},"MAIN_PROTECTION_INVALID")
        kinds={x["type"]:x for x in rules.get("rules",[])}
        checks=kinds.get("required_status_checks",{}).get("parameters",{})
        require("pull_request" in kinds and any(x.get("context")=="publication-authority" and x.get("integration_id")==15368 for x in checks.get("required_status_checks",[])),"MAIN_REQUIRED_CHECK_MISSING")
        if ident==24932377: require(checks.get("strict_required_status_checks_policy") is True,"MAIN_STRICT_CHECK_MISSING")
    protection=api.get("/rulesets/26070404")
    require(protection.get("id")==26070404 and verify_ruleset(protection)[0],"CLAIM_PROTECTION_INVALID")
    environment=api.get("/environments/"+profile["environment"])
    require(environment.get("deployment_branch_policy")=={"protected_branches":False,"custom_branch_policies":True},"ENVIRONMENT_BRANCH_RESTRICTION_REQUIRED")
    branches=api.get("/environments/"+profile["environment"]+"/deployment-branch-policies")
    policies=branches.get("branch_policies",[])
    require(branches.get("total_count")==1 and len(policies)==1 and policies[0].get("name")=="main" and policies[0].get("type")=="branch","ENVIRONMENT_ONLY_MAIN_REQUIRED")
    return head,protection

def safe_extract(raw,destination,limit=512*1024*1024):
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        require(len(z.infolist())<=128,"BUNDLE_TOO_MANY_MEMBERS")
        seen=set(); total=0
        for info in z.infolist():
            name=info.filename; p=PurePosixPath(name); mode=info.external_attr>>16
            require(name not in seen and name and not p.is_absolute() and ".." not in p.parts and
                "\\" not in name and not info.is_dir() and not stat.S_ISLNK(mode) and not info.flag_bits&1,"UNSAFE_ZIP_MEMBER")
            require(str(p)==name and all(x not in {"","."} for x in p.parts),"NONCANONICAL_ZIP_MEMBER")
            total+=info.file_size; require(total<=limit,"BUNDLE_EXPANSION_LIMIT")
            seen.add(name)
        for info in z.infolist():
            path=destination/info.filename;path.parent.mkdir(parents=True,exist_ok=True)
            with path.open("xb") as f: f.write(z.read(info))
    return seen

def prepare_payload(raw,profile,private_sha,work):
    require(sha(raw)==profile["bundle_sha256"],"PRIVATE_BUNDLE_SHA_MISMATCH")
    payload=work/"payload";payload.mkdir()
    names=safe_extract(raw,payload)
    manifest_raw=(payload/"manifest.json").read_bytes()
    require(sha(manifest_raw)==profile["manifest_sha256"],"MANIFEST_SHA_MISMATCH")
    manifest=parse_json(manifest_raw)
    require(set(manifest)=={"schema","files"} and manifest["schema"]=="GEN34_PRIVATE_BUNDLE/1.0" and isinstance(manifest["files"],dict),"MANIFEST_INVALID")
    require(set(manifest["files"])==names-{"manifest.json"},"MANIFEST_MEMBERS_MISMATCH")
    for name,digest in manifest["files"].items():
        require(isinstance(digest,str) and HEX64.fullmatch(digest) and file_sha(payload/name)==digest,"PAYLOAD_FILE_SHA_MISMATCH")
    fixed={GENERATOR:GEN34_PINS["generator_sha256"],DRIVER:GEN34_PINS["driver_sha256"],
        "source.jsonl":GEN34_PINS["source_sha256"],"c1.json":GEN34_PINS["c1_sha256"],
        "ppges.zip":GEN34_PINS["ppges_sha256"],"grammar.txt":GEN34_PINS["grammar_sha256"],
        "private-state.json":private_sha,"dependency-lock.json":profile["dependency_lock_sha256"]}
    require(all(manifest["files"].get(k)==v for k,v in fixed.items()),"ORIGINAL_INPUT_OR_STATE_MISMATCH")
    deps=parse_json((payload/"dependency-lock.json").read_bytes())
    require(set(deps)=={"schema","wheels"} and deps["schema"]=="GEN34_WHEELS/1.0" and isinstance(deps["wheels"],dict) and 1<=len(deps["wheels"])<=8,"DEPENDENCY_LOCK_INVALID")
    for name,digest in deps["wheels"].items():
        require(re.fullmatch(r"wheels/[A-Za-z0-9_.+-]+\.whl",name) and digest==manifest["files"].get(name),"WHEEL_NOT_HASH_BOUND")
    require(names==set(fixed)|set(deps["wheels"])|{"manifest.json"},"UNEXPECTED_PRIVATE_MEMBER")
    ppges=payload/"ppges";ppges.mkdir()
    safe_extract((payload/"ppges.zip").read_bytes(),ppges,8*1024*1024)
    require((ppges/"PPGES_v1.3.5/ppg_enforcement_engine_v1_3_5.py").is_file(),"ORIGINAL_PPGES_ENGINE_MISSING")
    return payload,parse_json((payload/"private-state.json").read_bytes()),deps

def clean_env():
    return {"PATH":os.environ.get("PATH","/usr/bin:/bin"),"LANG":"C.UTF-8",
            "PYTHONNOUSERSITE":"1","PIP_DISABLE_PIP_VERSION_CHECK":"1",
            "PIP_NO_INDEX":"1","PIP_CONFIG_FILE":os.devnull}

def prepare_python(payload,deps,work):
    venv=work/"venv"
    with (work/"dependency-setup.log").open("wb") as log:
        subprocess.run([sys.executable,"-I","-m","venv",str(venv)],env=clean_env(),cwd=work,stdout=log,stderr=log,check=True,timeout=120)
        python=venv/"bin/python"
        wheels=[str(payload/name) for name in sorted(deps["wheels"])]
        subprocess.run([str(python),"-I","-m","pip","install","--no-index","--no-deps","--no-cache-dir",*wheels],env=clean_env(),cwd=work,stdout=log,stderr=log,check=True,timeout=120)
    return python

def create_commit(api,files,message,parent=None):
    entries=[]
    for name,data in sorted(files.items()):
        obj=api.post("/git/blobs",{"content":base64.b64encode(data).decode("ascii"),"encoding":"base64"})
        require(obj.get("sha")==git_blob_sha(data),"BLOB_WRITE_READBACK_ID_MISMATCH")
        require(blob_bytes(api,obj["sha"])==data,"BLOB_WRITE_READBACK_BYTES_MISMATCH")
        entries.append({"path":name,"mode":"100644","type":"blob","sha":obj["sha"]})
    tree=api.post("/git/trees",{"tree":entries})
    require(HEX40.fullmatch(str(tree.get("sha",""))),"TREE_WRITE_INVALID")
    obj=api.post("/git/commits",{"message":message,"tree":tree["sha"],"parents":[] if parent is None else [parent]})
    require(HEX40.fullmatch(str(obj.get("sha",""))),"COMMIT_WRITE_INVALID")
    observed=api.get("/git/commits/"+obj["sha"])
    require(observed.get("tree",{}).get("sha")==tree["sha"] and [x["sha"] for x in observed.get("parents",[])]==([] if parent is None else [parent]),"COMMIT_READBACK_INVALID")
    return obj["sha"]

def create_once(api,ref,commit):
    response=api.post("/git/refs",{"ref":ref,"sha":commit})
    require(response.get("ref")==ref and response.get("object",{}).get("type")=="commit" and response["object"].get("sha")==commit,"REF_CREATE_AMBIGUOUS_NO_RETRY")
    observed=api.get("/git/ref/"+ref.removeprefix("refs/"))
    require(observed.get("ref")==ref and observed.get("object",{}).get("type")=="commit" and observed["object"]["sha"]==commit,"REF_READBACK_MISMATCH_NO_RETRY")

def claim_refs(profile,run_id):
    attempt=expected_claim_ref(profile["project"],profile["method_id"],profile["attempt_id"])
    run=REAL_NAMESPACE+sha(canonical(["GEN34_OWNER_EXECUTE_RUN",str(run_id)]))
    terminal=REAL_NAMESPACE+sha(canonical(["GEN34_TERMINAL",attempt]))
    return run,attempt,terminal

def redeem(api,profile,run_id,descriptor,head,runner_id):
    run_ref,attempt_ref,terminal_ref=claim_refs(profile,run_id)
    record={"schema":"GEN34_CLAIM/1.0","descriptor_sha256":descriptor,
        "authorization_run_id":run_id,"runner_run_id":runner_id,"runtime_commit":head,
        "run_ref":run_ref,"attempt_ref":attempt_ref,"terminal_ref":terminal_ref}
    commit=create_commit(api,{"claim.json":canonical(record)},"GEN34 immutable execution claim",head)
    # Deliberately not a transaction: a partial claim is terminally consumed.
    # Any conflict/timeout/ambiguity stops without retry or Driver launch.
    create_once(api,run_ref,commit)
    create_once(api,attempt_ref,commit)
    return commit,record

def run_driver(python,payload,work,seconds):
    output=work/"output.docx";report=work/"driver-report.json"
    command=[str(python),"-I","-B",str(payload/DRIVER),"--source",str(payload/"source.jsonl"),
        "--generator",str(payload/GENERATOR),"--ppges-root",str(payload/"ppges/PPGES_v1.3.5"),
        "--start-part","1","--end-part","25","--out",str(output),"--report",str(report)]
    with (work/"driver-stdout.log").open("wb") as stdout,(work/"driver-stderr.log").open("wb") as stderr:
        subprocess.run(command,env=clean_env(),cwd=work,stdout=stdout,stderr=stderr,check=True,timeout=seconds)
    raw=output.read_bytes();r=parse_json(report.read_bytes())
    require(r.get("status")=="PASS" and r.get("source_sha256")==GEN34_PINS["source_sha256"] and
        r.get("generator_sha256")==GEN34_PINS["generator_sha256"] and r.get("output_sha256")==sha(raw) and
        r.get("output_bytes")==len(raw) and r.get("batch_parts")==[1,25] and r.get("cumulative_records")==21529 and
        r.get("batch_records")==21529 and r.get("base_docx_sha256") is None and r.get("resume") is None,"DRIVER_REPORT_OR_OUTPUT_INVALID")
    rb=r.get("readback",{})
    require(rb.get("zip_bad") is None and rb.get("sections")==1 and rb.get("part_titles_present_through")==25 and rb.get("end_marker_present") is True,"DRIVER_READBACK_FAILED")
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        require(z.testzip() is None and {"[Content_Types].xml","word/document.xml"}.issubset(z.namelist()),"OUTPUT_OPC_INVALID")
    require(file_sha(payload/GENERATOR)==GEN34_PINS["generator_sha256"] and file_sha(payload/DRIVER)==GEN34_PINS["driver_sha256"] and file_sha(payload/"source.jsonl")==GEN34_PINS["source_sha256"],"INPUT_CHANGED_DURING_DRIVER")
    return {"output.docx":raw,"driver-report.json":report.read_bytes(),
        "driver-stdout.log":(work/"driver-stdout.log").read_bytes(),"driver-stderr.log":(work/"driver-stderr.log").read_bytes()}

def store_private_output(private_api,files,descriptor):
    require(private_api.get("").get("private") is True,"OUTPUT_DESTINATION_NOT_PRIVATE")
    commit=create_commit(private_api,files,"GEN34 private Driver output")
    ref="refs/tags/gen34-r25r7-output-"+descriptor
    create_once(private_api,ref,commit)
    for name,data in files.items():
        require(committed_file(private_api,commit,name)==data,"PRIVATE_OUTPUT_READBACK_FAILED")
    return {"private_commit":commit,"private_ref":ref,
            "file_sha256":{name:sha(data) for name,data in files.items()}}

def terminal_receipt(key,profile,run_id,descriptor,claim_commit,record,result,output_sha):
    receipt={"schema":RECEIPT_SCHEMA,"issuer":ISSUER,
        "attempt_key_sha256":record["attempt_ref"].removeprefix(REAL_NAMESPACE),
        "dispatch_descriptor_sha256":descriptor,"claim_ref":record["attempt_ref"],
        "claim_commit_sha":claim_commit,"terminal_result":result,"output_sha256":output_sha,
        "authorization_run_id":run_id,"nonce":sha(canonical(["GEN34_TERMINAL_NONCE",claim_commit,descriptor]))}
    receipt["mac_sha256"]=hmac.new(key,canonical(receipt),hashlib.sha256).hexdigest()
    return receipt

def persist_terminal(api,receipt,record,key,output_binding,profile):
    expected={k:receipt[k] for k in ("issuer","attempt_key_sha256","dispatch_descriptor_sha256","claim_ref","claim_commit_sha","authorization_run_id")}
    require(verify_terminal_receipt(receipt,key,expected)["authenticated"],"RECEIPT_LOCAL_AUTHENTICATION_FAILED")
    files={"receipt.json":canonical(receipt),"binding.json":canonical({
        "schema":"GEN34_TERMINAL_BINDING/1.0","source_sha256":GEN34_PINS["source_sha256"],
        "profile_sha256":sha(canonical(profile)),"output":output_binding,
        "claim":record,"receipt_sha256":sha(canonical(receipt))})}
    commit=create_commit(api,files,"GEN34 immutable terminal receipt",receipt["claim_commit_sha"])
    create_once(api,record["terminal_ref"],commit)
    raw=committed_file(api,commit,"receipt.json")
    require(raw==canonical(receipt) and verify_terminal_receipt(parse_json(raw),key,expected)["authenticated"],"DURABLE_RECEIPT_AUTHENTICATION_FAILED")
    require(committed_file(api,commit,"binding.json")==files["binding.json"],"DURABLE_BINDING_READBACK_FAILED")
    return commit

def complete_claimed(api,private_api,profile,auth_run,descriptor,head,runner_id,key,payload,python,work,deadline,runner=run_driver):
    claim_commit,record=redeem(api,profile,auth_run,descriptor,head,runner_id)
    result="NOT_LAUNCHED";output_binding=None;output_sha=None;launch_started=False
    try:
        # Revalidate protection and authority after the one-use mutation and
        # immediately before any producer subprocess. Drift consumes, never retries.
        require(api.get("/git/ref/heads/main")["object"]["sha"]==head,"AUTHORITY_DRIFT_AFTER_CLAIM")
        require(verify_ruleset(api.get("/rulesets/26070404"))[0],"CLAIM_PROTECTION_LOST")
        remaining=int(deadline-time.monotonic())
        require(remaining>60,"TIME_BUDGET_EXHAUSTED")
        launch_started=True
        files=runner(python,payload,work,min(profile["max_seconds"],remaining-45))
        output_binding=store_private_output(private_api,files,descriptor)
        output_sha=output_binding["file_sha256"]["output.docx"]
        result="COMPLETED"
    except Exception:
        # Never publish subprocess output or raw exceptions. The original claim
        # remains immutable even when durable receipt storage itself fails.
        result="STARTED_NO_OUTPUT" if launch_started else "NOT_LAUNCHED"
        output_binding=None;output_sha=None
    receipt=terminal_receipt(key,profile,auth_run,descriptor,claim_commit,record,result,output_sha)
    terminal_commit=persist_terminal(api,receipt,record,key,output_binding,profile)
    return {"status":result,"receipt_sha256":sha(canonical(receipt)),
            "terminal_commit":terminal_commit,"terminal_ref":record["terminal_ref"],"output_sha256":output_sha}

def execute(api,private_api,env,authorization_run_id,key_hex,work):
    started=time.monotonic();deadline=started+3300
    raw=(ROOT/"authority/CURRENT.json").read_bytes(); lock=parse_json(raw);public_sha=sha(raw)
    require((ROOT/"authority/CURRENT.sha256").read_text().split()[0]==public_sha,"PUBLIC_SIDECAR_MISMATCH")
    profile=lock.get("gen34_r25r7_bridge")
    require(not gen34_activation_errors(profile),"GEN34_PROTECTED_ACTIVATION_REQUIRED")
    require(lock.get("execution_authorized_now") is True and lock.get("current_action")=={"id":profile["action_id"],"mode":"MUTATING"},"GEN34_AUTHORITY_READ_ONLY")
    require(file_sha(ROOT/"broker/gen34_r25r7_bridge.py")==profile["runtime_code_sha256"] and file_sha(ROOT/WORKFLOW)==profile["runtime_workflow_sha256"],"RUNTIME_BYTE_PIN_MISMATCH")
    head,protection=verify_platform(api,env,profile)
    require(committed_file(api,head,"authority/CURRENT.json")==raw,"LIVE_AUTHORITY_BYTE_MISMATCH")
    auth=authenticate_owner(api,authorization_run_id,head)
    # Authenticate and bind before touching a private manuscript blob.
    request={"schema":REQ_SCHEMA,"requested_action_id":profile["action_id"],"action_kind":"EXECUTE",
        "mode":"MUTATING","user_explicit_authorization":True,"authorization_run_id":authorization_run_id,
        "input_public_lock_sha256":public_sha,"input_private_state_sha256":lock["private_execution_state_sha256"],
        **{k:profile[k] for k in ("project","method_id","attempt_id","executor_id","operations","target_scope_ids")}}
    from publication_gate import validate_authorization
    require(not validate_authorization(auth,request,public_sha,lock["private_execution_state_sha256"]),"OWNER_EXECUTE_BINDING_MISMATCH")
    require(re.fullmatch(r"[0-9a-fA-F]{64}",key_hex or ""),"RECEIPT_KEY_UNAVAILABLE")
    key=bytes.fromhex(key_hex);require(sha(key)==profile["receipt_key_sha256"],"RECEIPT_KEY_IDENTITY_MISMATCH")
    require(private_api.get("").get("private") is True,"INPUT_DESTINATION_NOT_PRIVATE")
    raw_bundle=blob_bytes(private_api,profile["bundle_blob_sha"])
    payload,private_state,deps=prepare_payload(raw_bundle,profile,lock["private_execution_state_sha256"],work)
    admission=validate_gen34_admission(lock,private_state,request,auth,public_sha)
    require(admission["status"]=="ELIGIBLE_FOR_PHYSICAL_CLAIM_ONLY","EXECUTION_ADMISSION_DENIED")
    python=prepare_python(payload,deps,work)
    require(api.get("/rulesets/26070404")==protection,"RULESET_CHANGED_BEFORE_CLAIM")
    require(api.get("/git/ref/heads/main")["object"]["sha"]==head,"AUTHORITY_CHANGED_BEFORE_CLAIM")
    descriptor=gen34_descriptor(profile,public_sha,lock["private_execution_state_sha256"],authorization_run_id)
    return complete_claimed(api,private_api,profile,authorization_run_id,descriptor,head,env["GITHUB_RUN_ID"],key,payload,python,work,deadline)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--authorization-run-id",required=True)
    args=parser.parse_args()
    # Do not echo args, credentials, exceptions, subprocess logs or bundle paths.
    try:
        api=GitHub(REPO,os.environ.get("GH_TOKEN",""))
        private_api=GitHub(PRIVATE_REPO,os.environ.get("GEN34_PRIVATE_TOKEN",""))
        os.umask(0o077)
        with tempfile.TemporaryDirectory(prefix="gen34-r25r7-") as directory:
            result=execute(api,private_api,dict(os.environ),args.authorization_run_id,
                           os.environ.get("GEN34_RECEIPT_KEY_HEX",""),Path(directory))
        print(json.dumps(result,sort_keys=True))
        return 0 if result["status"]=="COMPLETED" else 3
    except BaseException:
        print('{"status":"DENIED_OR_UNKNOWN","retry_allowed":false,"detail":"Inspect protected claims before any owner decision; no automatic replay."}')
        return 2

if __name__=="__main__": raise SystemExit(main())
