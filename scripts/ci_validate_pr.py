#!/usr/bin/env python3
import argparse, hashlib, io, json, os, urllib.request, zipfile
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"gate"))
from publication_gate import validate as gate_validate, load_json
from transition_guard import validate_transition

LOCK="authority/CURRENT.json"
SIDE="authority/CURRENT.sha256"
REQ="request/ACTION_REQUEST.json"
TRANS="request/STATE_TRANSITION.json"

PROTECTED_RUNTIME_PREFIXES=(".github/workflows/","gate/","scripts/","policy/","ruleset/")
PROTECTED_RUNTIME_FILES={".github/CODEOWNERS","README.md"}
READONLY_CHANGE_PREFIXES=("reports/","request/")
MUTATING_OPS={"BUILD","PATCH","RENDER","EXPORT_PDF","GENERATE_DOCX","GENERATE_PDF","PROMOTE","QUALIFY","WRITE_CURRENT","UPDATE_POINTER","SOURCE_REBUILD","REQUALIFY","REIMPLEMENT","DELETE","MOVE","RENAME","UPLOAD_OFFICIAL","STATE_TRANSITION","AUTHORITY_UPDATE","ACTIVATE_BACKEND","SET_NEXT_ACTION","GOVERNANCE_UPGRADE"}


# Motion F intentionally excludes workflow, renderer, documents and state promotion.
MOTION_F_ACTION="GLOBAL_PUBLICATION_GEN32_MOTION_F_TRUSTED_GATE_IMPLEMENTATION_AND_TESTS"
MOTION_F_CODE_FILES={
    "gate/publication_gate.py","gate/transition_guard.py",
    "scripts/ci_validate_pr.py","scripts/selftest.py"
}
MOTION_F_ALLOWED_CHANGES=MOTION_F_CODE_FILES|{"request/ACTION_REQUEST.json"}
ATOMIC_ACTION="GLOBAL_PUBLICATION_GEN32_ATOMIC_GATE_COMPLETION_BOUNDED_IMPLEMENTATION"
ATOMIC_SCOPES={"GEN32_ATOMIC_GATE_COMPLETION_ISSUE53",
               "GEN32_CLAIM_START_SINGLE_USE_AUTHORIZATION",
               "GEN32_IMMUTABLE_CLOSE_GEN29_PRESERVATION",
               "GEN32_COMPETING_PR_AND_REPLAY_NEGATIVE_TESTS",
               "GEN32_NO_WORKFLOW_ASSEMBLER_RENDERER_METHOD_CANDIDATE_PILOT_BOOK"}
# Exact live protected-main preimages for this one authorized implementation.
# A second PR/replay after the first merge cannot use the same authorized scope.
ATOMIC_BASE_BLOBS={
    "gate/publication_gate.py":"f16fa9b8da6e2026388174fda9b3d02941f488e0",
    "gate/transition_guard.py":"032523261d1e06779c20b7c8ef1d2b6b840a82b9",
    "scripts/ci_validate_pr.py":"7a2bbf2bb3687f5c49e1bdceeff1dd28ed0f87d3",
    "scripts/selftest.py":"91066fec6fba3d2a069a4d30b24a4f3b74136102"
}

def git_blob_file(path):
    data=Path(path).read_bytes()
    return hashlib.sha1(b"blob "+str(len(data)).encode("ascii")+b"\0"+data).hexdigest()

def validate_atomic_changed_paths(changes,request,base_lock,base_root=None):
    if request.get("requested_action_id")!=ATOMIC_ACTION: return []
    reasons=[]
    if request.get("action_kind")!="GOVERNANCE_UPGRADE":
        reasons.append("ATOMIC_REQUIRES_GOVERNANCE_UPGRADE")
    if set(changes)-MOTION_F_ALLOWED_CHANGES:
        reasons.append("ATOMIC_FILE_ALLOWLIST_VIOLATION")
    if set(request.get("operations") or [])!={"GOVERNANCE_UPGRADE","PATCH"}:
        reasons.append("ATOMIC_OPERATIONS_NOT_EXACT")
    if not (MOTION_F_CODE_FILES|ATOMIC_SCOPES).issubset(set(request.get("target_scope_ids") or [])):
        reasons.append("ATOMIC_SCOPE_INCOMPLETE")
    if base_lock.get("generation")!=32 or base_lock.get("current_action",{}).get("mode")!="READ_ONLY":
        reasons.append("ATOMIC_WRONG_BASE_LOCK")
    if set(changes)!=MOTION_F_ALLOWED_CHANGES:
        reasons.append("ATOMIC_EXACT_FIVE_PATHS_REQUIRED")
    if base_root is None:
        reasons.append("ATOMIC_TRUSTED_BASE_REQUIRED")
    else:
        for rel,expected in ATOMIC_BASE_BLOBS.items():
            if git_blob_file(Path(base_root)/rel)!=expected:
                reasons.append("ATOMIC_BASE_BLOB_MISMATCH:"+rel)
    return reasons

def validate_motion_f_changed_paths(changes,request,base_lock):
    if request.get("requested_action_id")!=MOTION_F_ACTION:
        return []
    reasons=[]
    if request.get("action_kind")!="GOVERNANCE_UPGRADE":
        reasons.append("MOTION_F_REQUIRES_GOVERNANCE_UPGRADE")
    if set(changes)-MOTION_F_ALLOWED_CHANGES:
        reasons.append("MOTION_F_FILE_ALLOWLIST_VIOLATION:"+",".join(sorted(set(changes)-MOTION_F_ALLOWED_CHANGES)))
    if not MOTION_F_CODE_FILES.issubset(set(request.get("target_scope_ids") or [])):
        reasons.append("MOTION_F_CODE_SCOPE_INCOMPLETE")
    if set(request.get("operations") or [])!={"GOVERNANCE_UPGRADE","PATCH"}:
        reasons.append("MOTION_F_OPERATIONS_NOT_EXACT")
    if base_lock.get("generation")!=32:
        reasons.append("MOTION_F_BASE_GENERATION_NOT_32")
    if base_lock.get("current_action",{}).get("mode")!="READ_ONLY":
        reasons.append("MOTION_F_UNEXPECTED_BASE_ACTION_MODE")
    return reasons

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def tree(root):
    out={}; root=Path(root)
    for p in root.rglob("*"):
        if not p.is_file(): continue
        rel=p.relative_to(root).as_posix()
        if ".git/" in rel or "__pycache__" in p.parts or p.suffix==".pyc":
            continue
        out[rel]=sha(p)
    return out

def changed_paths(base,head):
    a,b=tree(base),tree(head)
    return sorted(k for k in set(a)|set(b) if a.get(k)!=b.get(k))

def api_json(url,token):
    req=urllib.request.Request(url,headers={"Authorization":f"Bearer {token}","Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","User-Agent":"global-publication-authority-lock"})
    with urllib.request.urlopen(req,timeout=30) as r:
        return json.load(r)

def api_bytes(url,token):
    # GitHub's artifact archive endpoint redirects to a short-lived signed
    # cross-domain storage URL. Authenticate only the GitHub API request.
    # Never forward the GitHub bearer token to the signed storage host.
    import urllib.error, urllib.parse

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    headers={
        "Authorization":f"Bearer {token}",
        "Accept":"application/vnd.github+json",
        "X-GitHub-Api-Version":"2022-11-28",
        "User-Agent":"global-publication-authority-lock",
    }
    opener=urllib.request.build_opener(_NoRedirect)
    req=urllib.request.Request(url,headers=headers)
    try:
        with opener.open(req,timeout=30) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if e.code not in (301,302,303,307,308):
            raise
        location=e.headers.get("Location")
        if not location:
            raise ValueError("artifact redirect missing Location header")

    parsed=urllib.parse.urlparse(location)
    if parsed.scheme!="https" or not parsed.netloc:
        raise ValueError("artifact redirect is not a valid HTTPS URL")
    req2=urllib.request.Request(
        location,
        headers={"User-Agent":"global-publication-authority-lock"}
    )
    with urllib.request.urlopen(req2,timeout=30) as r:
        return r.read()

def fetch_manual_authorization(run_id):
    token=os.environ["GH_TOKEN"]; repo=os.environ["GITHUB_REPOSITORY"]; owner=os.environ["GITHUB_REPOSITORY_OWNER"]
    if not str(run_id).isdigit(): raise ValueError("authorization_run_id must be numeric")
    run=api_json(f"https://api.github.com/repos/{repo}/actions/runs/{run_id}",token)
    if run.get("event")!="workflow_dispatch": raise ValueError("authorization run was not workflow_dispatch")
    if run.get("conclusion")!="success": raise ValueError("authorization run did not succeed")
    if run.get("path")!=".github/workflows/authorize-next-action.yml": raise ValueError("authorization run used wrong workflow")
    if run.get("head_branch")!="main": raise ValueError("authorization workflow did not run from main")
    if ((run.get("actor") or {}).get("login") or "").lower()!=owner.lower(): raise ValueError("authorization actor is not repository owner")

    arts=api_json(f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/artifacts",token).get("artifacts") or []
    expected=f"publication-authorization-{run_id}"
    art=next((a for a in arts if a.get("name")==expected and not a.get("expired")),None)
    if not art: raise ValueError("authorization artifact missing or expired")
    data=api_bytes(f"https://api.github.com/repos/{repo}/actions/artifacts/{art['id']}/zip",token)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        if "authorization.json" not in z.namelist(): raise ValueError("authorization.json absent from artifact")
        auth=json.loads(z.read("authorization.json").decode("utf-8"))
    if str(auth.get("github_run_id"))!=str(run_id): raise ValueError("authorization artifact run ID mismatch")
    if (auth.get("github_actor") or "").lower()!=owner.lower(): raise ValueError("authorization artifact actor mismatch")
    return auth

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--base",required=True); ap.add_argument("--head",required=True)
    args=ap.parse_args(); base=Path(args.base); head=Path(args.head); reasons=[]
    changes=changed_paths(base,head)
    print("Changed paths:"); [print(" -",x) for x in changes]

    for root,label in ((base,"base"),(head,"head")):
        if not (root/LOCK).exists() or not (root/SIDE).exists():
            reasons.append(f"MISSING_PUBLIC_LOCK_OR_SIDECAR:{label}")
        else:
            pinned=(root/SIDE).read_text(encoding="utf-8").strip().split()[0]
            if pinned!=sha(root/LOCK): reasons.append(f"PUBLIC_LOCK_SIDECAR_MISMATCH:{label}")
    if reasons:
        [print("DENY:",x) for x in reasons]; return 2

    base_lock_sha=sha(base/LOCK); head_lock_sha=sha(head/LOCK)
    lock_changed=base_lock_sha!=head_lock_sha

    if not (head/REQ).exists():
        reasons.append("ACTION_REQUEST_REQUIRED_FOR_ANY_OFFICIAL_PR"); req={}
    else:
        req=load_json(head/REQ)

    ops=[]
    for x in req.get("operations") or []:
        ops.append(x if isinstance(x,str) else x.get("type"))
    needs_auth=req.get("action_kind") in {"SET_NEXT_ACTION","GOVERNANCE_UPGRADE"} or any(x in MUTATING_OPS for x in ops)

    auth=None
    if needs_auth:
        try:
            auth=fetch_manual_authorization(req.get("authorization_run_id"))
            print("Manual authorization workflow run:",req.get("authorization_run_id"))
        except Exception as e:
            reasons.append("MANUAL_AUTHORIZATION_INVALID:"+str(e))

    if (head/REQ).exists():
        gres=gate_validate(base/LOCK,base/SIDE,head/REQ,auth)
        print(json.dumps(gres,indent=2))
        if gres["status"]!="ALLOW": reasons += ["GATE:"+x for x in gres.get("reasons",[])]

    reasons += validate_motion_f_changed_paths(changes,req,load_json(base/LOCK))
    reasons += validate_atomic_changed_paths(changes,req,load_json(base/LOCK),base)

    runtime_changed=[p for p in changes if p in PROTECTED_RUNTIME_FILES or p.startswith(PROTECTED_RUNTIME_PREFIXES)]
    if runtime_changed and req.get("action_kind")!="GOVERNANCE_UPGRADE":
        reasons.append("TRUSTED_RUNTIME_CHANGE_REQUIRES_GOVERNANCE_UPGRADE")

    if lock_changed:
        if not (head/TRANS).exists():
            reasons.append("STATE_TRANSITION_RECORD_REQUIRED")
        else:
            tres=validate_transition(base/LOCK,head/LOCK,req)
            print(json.dumps(tres,indent=2))
            if tres["status"]!="PASS": reasons += ["TRANSITION:"+x for x in tres.get("reasons",[])]
        if req.get("action_kind") not in {"SET_NEXT_ACTION","GOVERNANCE_UPGRADE"} and "STATE_TRANSITION" not in ops:
            reasons.append("LOCK_CHANGED_WITHOUT_STATE_TRANSITION_OPERATION")
    else:
        illegal=[p for p in changes if not (p.startswith(READONLY_CHANGE_PREFIXES) or p==REQ)]
        if illegal and not runtime_changed:
            reasons.append("LOCK_UNCHANGED_ILLEGAL_PATH_CHANGE:"+",".join(illegal))

    if reasons:
        print("PUBLICATION AUTHORITY: DENY")
        for r in sorted(set(reasons)): print("DENY:",r)
        return 3
    print("PUBLICATION AUTHORITY: PASS")
    return 0

if __name__=="__main__": raise SystemExit(main())
