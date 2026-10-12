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
    # GitHub artifact downloads return a short-lived cross-domain 302.
    # Do not forward the GitHub Authorization header to Azure/S3: the
    # pre-signed redirect URL authenticates itself and rejects that header.
    import urllib.error
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    headers={"Authorization":f"Bearer {token}","Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","User-Agent":"global-publication-authority-lock"}
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
    req2=urllib.request.Request(location,headers={"User-Agent":"global-publication-authority-lock"})
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
