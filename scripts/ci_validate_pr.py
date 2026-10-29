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

# GEN33 code-only Broker approval: exact immutable base and exact 9-file diff.
GEN33_BROKER_ACTION="GLOBAL_PUBLICATION_GEN33_SOURCE_BOUND_BROKER_IMPLEMENTATION_V1_CODE_ONLY"
GEN33_BROKER_ALLOWED_PATHS={
    "broker/gen33_source_bound_broker.py", "broker/gen33_receipt_verifier.py",
    "tests/test_gen33_broker.py", ".github/workflows/gen33-broker-qa.yml",
    "gate/publication_gate.py", "gate/transition_guard.py",
    "scripts/ci_validate_pr.py", "scripts/selftest.py", "request/ACTION_REQUEST.json"
}
GEN33_BROKER_PREIMAGES={
    "gate/publication_gate.py":"6d7780d034b4f1eb7d6b1699ad17228ee27ddefb",
    "gate/transition_guard.py":"d2fa8ebc9504d1d24852cc79a6d8692669fabffc",
    "scripts/ci_validate_pr.py":"b2b9575feb89ad3fd5ff8e0edb73b9a141306991",
    "scripts/selftest.py":"34570f848a64f55899f3054861f350a39eb43e33"
}
GEN33_BROKER_SHA="08c2c4c23f1223c7a05554ac81f5f1bac948ac805d28503ca1b0be890b5474fa"
GEN33_BROKER_PRIVATE_SHA="dfe3488ff09feba990938953c0caab822a01b90c32cc687d11c08f80d0818ed1"

def validate_gen33_broker_scope(changes,req,base_lock,base_root):
    if req.get("requested_action_id")!=GEN33_BROKER_ACTION: return []
    reasons=[]
    if (req.get("action_kind")!="GOVERNANCE_UPGRADE" or
            set(req.get("operations") or [])!={"GOVERNANCE_UPGRADE","PATCH"}):
        reasons.append("GEN33_BROKER_ACTION_KIND_OR_OPS_INVALID")
    if set(changes)!=GEN33_BROKER_ALLOWED_PATHS:
        reasons.append("GEN33_BROKER_EXACT_NINE_PATHS_REQUIRED")
    if set(req.get("target_scope_ids") or [])!=GEN33_BROKER_ALLOWED_PATHS:
        reasons.append("GEN33_BROKER_SCOPE_NOT_EXACT")
    if req.get("authorization_run_id")!=40743213897:
        reasons.append("GEN33_BROKER_AUTH_RUN_MISMATCH")
    if (base_lock.get("generation")!=33 or
        base_lock.get("current_action",{}).get("mode")!="READ_ONLY" or
        base_lock.get("execution_authorized_now") is not False or
        base_lock.get("private_execution_state_sha256")!=GEN33_BROKER_PRIVATE_SHA):
        reasons.append("GEN33_BROKER_UNEXPECTED_BASE_STATE")
    if base_root is None:
        reasons.append("GEN33_BROKER_BASE_REQUIRED")
    else:
        if sha(base_root/LOCK)!=GEN33_BROKER_SHA:
            reasons.append("GEN33_BROKER_BASE_LOCK_MISMATCH")
        for rel,expected in GEN33_BROKER_PREIMAGES.items():
            if git_blob_file(base_root/rel)!=expected:
                reasons.append("GEN33_BROKER_BASE_BLOB_MISMATCH:"+rel)
    return reasons


# GEN33 protected-claim proof phase 1: exactly eight code paths,
# independent from any real Git ref creation or Producer admission.
GEN33_PROOF_ACTION="GLOBAL_PUBLICATION_GEN33_PROTECTED_CLAIM_PROOF_V1_NONPRODUCER_IMPLEMENTATION"
GEN33_PROOF_PATHS={
    "broker/gen33_source_bound_broker.py",
    "broker/gen33_live_claim.py",
    "tests/test_gen33_live_claim.py",
    ".github/workflows/gen33-live-claim-proof.yml",
    ".github/workflows/gen33-broker-qa.yml",
    "scripts/ci_validate_pr.py",
    "scripts/selftest.py",
    "request/ACTION_REQUEST.json"
}
GEN33_PROOF_PREIMAGES={
    "broker/gen33_source_bound_broker.py":"404c6f650ee178ee3593967c7996c2636537ff91",
    ".github/workflows/gen33-broker-qa.yml":"ebe92ed236e3380a699ddae4662e769901001208",
    "scripts/ci_validate_pr.py":"ed11e2bbb1bd96b94c28e3a02b7eabf5548773fe",
    "scripts/selftest.py":"3c65dceb08af13896edcdb61830e299eb293cf3e",
    "request/ACTION_REQUEST.json":"544f89b76eb492e6078f152ce44568924f74f1d5"
}
GEN33_PROOF_PUBLIC_SHA="08c2c4c23f1223c7a05554ac81f5f1bac948ac805d28503ca1b0be890b5474fa"
GEN33_PROOF_PRIVATE_SHA="dfe3488ff09feba990938953c0caab822a01b90c32cc687d11c08f80d0818ed1"

def validate_gen33_proof_scope(changes, req, base_lock, base_root):
    if req.get("requested_action_id")!=GEN33_PROOF_ACTION:
        return []
    reasons=[]
    if (req.get("action_kind")!="GOVERNANCE_UPGRADE" or
        set(req.get("operations") or [])!={"GOVERNANCE_UPGRADE","PATCH"}):
        reasons.append("GEN33_PROOF_UNEXPECTED_ACTION_OR_OPERATIONS")
    if set(changes)!=GEN33_PROOF_PATHS:
        reasons.append("GEN33_PROOF_EXACT_EIGHT_PATHS_REQUIRED")
    if set(req.get("target_scope_ids") or [])!=GEN33_PROOF_PATHS:
        reasons.append("GEN33_PROOF_REQUEST_SCOPE_MISMATCH")
    if req.get("authorization_run_id")!=40748290755:
        reasons.append("GEN33_PROOF_AUTH_RUN_MISMATCH")
    if (base_lock.get("generation")!=33 or
        base_lock.get("current_action",{}).get("mode")!="READ_ONLY" or
        base_lock.get("execution_authorized_now") is not False or
        base_lock.get("private_execution_state_sha256")!=GEN33_PROOF_PRIVATE_SHA):
        reasons.append("GEN33_PROOF_BASE_STATE_MISMATCH")
    if base_root is None:
        reasons.append("GEN33_PROOF_BASE_REQUIRED")
    else:
        if sha(base_root/LOCK)!=GEN33_PROOF_PUBLIC_SHA:
            reasons.append("GEN33_PROOF_PUBLIC_SHA_MISMATCH")
        for rel, digest in GEN33_PROOF_PREIMAGES.items():
            if git_blob_file(base_root/rel)!=digest:
                reasons.append("GEN33_PROOF_BASE_FILE_MISMATCH:"+rel)
    return reasons


# GEN33 synthetic physical-race installation: EXACT five files / no ref write
# until a separately authorized later workflow_dispatch succeeds.
GEN33_RACE_CODE_ACTION="GLOBAL_PUBLICATION_GEN33_SYNTHETIC_PROTECTED_REF_RACE_V1_CODE_ONLY_IMPLEMENTATION"
GEN33_RACE_CODE_FILES={
    "scripts/gen33_synthetic_claim_race.py",
    "tests/test_gen33_synthetic_claim_race.py",
    ".github/workflows/gen33-synthetic-claim-race.yml",
    "scripts/ci_validate_pr.py",
    "request/ACTION_REQUEST.json"
}
GEN33_RACE_CODE_BASE_SHA="08c2c4c23f1223c7a05554ac81f5f1bac948ac805d28503ca1b0be890b5474fa"
GEN33_RACE_CODE_PRIVATE_SHA="dfe3488ff09feba990938953c0caab822a01b90c32cc687d11c08f80d0818ed1"
GEN33_RACE_CODE_PREIMAGES={
    "scripts/ci_validate_pr.py":"9cf15729ffbf218346e2228ed3df6a2c4495e9f8",
    "request/ACTION_REQUEST.json":"8ff2ad8fb475cdb4e06235f47feb724aab588485"
}

def validate_gen33_race_install_scope(changes,req,base_lock,base_root):
    if req.get("requested_action_id")!=GEN33_RACE_CODE_ACTION:
        return []
    reasons=[]
    if (req.get("action_kind")!="GOVERNANCE_UPGRADE" or
        set(req.get("operations") or [])!={"GOVERNANCE_UPGRADE","PATCH"}):
        reasons.append("GEN33_RACE_CODE_ACTION_OR_OPS_MISMATCH")
    if set(changes)!=GEN33_RACE_CODE_FILES or len(changes)!=5:
        reasons.append("GEN33_RACE_CODE_EXACT_FIVE_FILES_REQUIRED")
    if set(req.get("target_scope_ids") or [])!=GEN33_RACE_CODE_FILES or len(req.get("target_scope_ids") or [])!=5:
        reasons.append("GEN33_RACE_CODE_REQUEST_SCOPE_MISMATCH")
    if req.get("authorization_run_id")!=40756323455:
        reasons.append("GEN33_RACE_CODE_AUTH_RUN_MISMATCH")
    if (base_lock.get("generation")!=33 or
        base_lock.get("current_action",{}).get("mode")!="READ_ONLY" or
        base_lock.get("execution_authorized_now") is not False or
        base_lock.get("private_execution_state_sha256")!=GEN33_RACE_CODE_PRIVATE_SHA):
        reasons.append("GEN33_RACE_CODE_BASE_STATE_CHANGED")
    if base_root is None:
        reasons.append("GEN33_RACE_CODE_BASE_REQUIRED")
    else:
        if sha(base_root/LOCK)!=GEN33_RACE_CODE_BASE_SHA:
            reasons.append("GEN33_RACE_CODE_BASE_AUTHORITY_CHANGED")
        for rel,digest in GEN33_RACE_CODE_PREIMAGES.items():
            if git_blob_file(base_root/rel)!=digest:
                reasons.append("GEN33_RACE_CODE_BASE_BLOB_MISMATCH:"+rel)
    return reasons

# GEN34 exact nine-path code-only installation; no authority/state mutation.
GEN34_CODE_ACTION="GLOBAL_PUBLICATION_GEN34_R25R7_SECURE_BRIDGE_V1_CODE_ONLY_IMPLEMENTATION"
GEN34_CODE_RUN=40818118503
GEN34_CODE_PUBLIC="f70e7d9f9ae4178800bb62313fd9e61f027b49ebc03c5c8e45808c89c241eee2"
GEN34_CODE_PRIVATE="0881394eda6ffa3441cb9dbda592db5a77c68441169749b4d49513ce4d720d78"
GEN34_CODE_PREIMAGES={'broker/gen34_r25r7_bridge.py': None, 'tests/test_gen34_r25r7_bridge.py': None, '.github/workflows/gen34-r25r7-producer.yml': None, '.github/workflows/gen34-r25r7-qa.yml': None, 'gate/publication_gate.py': '963cb7dbf1f6b7ed6a8c493213b9e555e929a3af', 'gate/transition_guard.py': 'a77863cedd67aeb1264ab7877a07866325b32327', 'scripts/ci_validate_pr.py': 'df6c5b7d6ed71c0dd608103f91c8e871ff3f18b6', 'scripts/selftest.py': 'd57db4dcb29a4ec78356e80474ab6ed2ab4f80a0', 'request/ACTION_REQUEST.json': '312d546ee2c348efaf7ced1023c683151b9d7392'}
GEN34_CODE_PATHS=set(GEN34_CODE_PREIMAGES)

def validate_gen34_code_scope(changes,req,base_lock,base_root):
    if req.get("requested_action_id")!=GEN34_CODE_ACTION: return []
    reasons=[]
    if req.get("action_kind")!="GOVERNANCE_UPGRADE" or req.get("operations")!=["GOVERNANCE_UPGRADE","PATCH"]:
        reasons.append("GEN34_CODE_KIND_OR_OPERATIONS_INVALID")
    if set(changes)!=GEN34_CODE_PATHS or len(changes)!=9:
        reasons.append("GEN34_EXACT_NINE_PATHS_REQUIRED")
    if set(req.get("target_scope_ids",[]))!=GEN34_CODE_PATHS or len(req.get("target_scope_ids",[]))!=9:
        reasons.append("GEN34_EXACT_AUTHORIZED_SCOPE_REQUIRED")
    if req.get("authorization_run_id")!=GEN34_CODE_RUN:
        reasons.append("GEN34_CODE_AUTHORIZATION_RUN_MISMATCH")
    if base_lock.get("generation")!=34 or base_lock.get("execution_authorized_now") is not False or base_lock.get("current_action",{}).get("mode")!="READ_ONLY" or base_lock.get("private_execution_state_sha256")!=GEN34_CODE_PRIVATE:
        reasons.append("GEN34_CODE_BASE_STATE_MISMATCH")
    if base_root is None:
        reasons.append("GEN34_CODE_TRUSTED_BASE_REQUIRED")
    else:
        if sha(base_root/LOCK)!=GEN34_CODE_PUBLIC: reasons.append("GEN34_CODE_PUBLIC_SHA_MISMATCH")
        for rel,expected in GEN34_CODE_PREIMAGES.items():
            p=base_root/rel
            if expected is None:
                if p.exists(): reasons.append("GEN34_NEW_PATH_ALREADY_EXISTS:"+rel)
            elif not p.is_file() or git_blob_file(p)!=expected:
                reasons.append("GEN34_CODE_PREIMAGE_MISMATCH:"+rel)
    return reasons

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


# GEN32 DISPATCH v2: one approved immutable 5-path control-plane patch.
DISPATCH_V2_ACTION="GLOBAL_PUBLICATION_GEN32_R25R7_EXISTING_PRODUCER_ATOMIC_DISPATCH_BINDING"
DISPATCH_V2_PATHS=set(["gate/transition_guard.py","gate/publication_gate.py","scripts/ci_validate_pr.py","scripts/selftest.py","request/ACTION_REQUEST.json"])
DISPATCH_V2_SCOPES=set(["GEN32_R25R7_EXISTING_ATOMIC_BINDING_ISSUE53_SCOPE_ONLY","GEN32_DISPATCH_V2_CONTROL_PLANE_ONLY_NO_PRODUCER","GEN32_PRESERVE_V1_GEN29_HISTORY_AND_GATE_49","GEN32_NO_R25R7_ASSEMBLY_GRAMMAR_PPGES_C1_CHANGE","gate/transition_guard.py","gate/publication_gate.py","scripts/ci_validate_pr.py","scripts/selftest.py","request/ACTION_REQUEST.json","CONTRACT_SHA256_0522a6fc87521143d8fd689a6f82b65c1748a4f1bb63d9d0f6ab924ca002f24a","PUBLIC_SHA256_6870614362a1d090f4694d5f9de035ef4922ec5161707e7b9f83b82431ad64d9","PRIVATE_SHA256_dfe3488ff09feba990938953c0caab822a01b90c32cc687d11c08f80d0818ed1"])
DISPATCH_V2_BASE_BLOBS={"gate/transition_guard.py":"b171f9b8c29e849b2c235eded47f0cb9ea4417a1","gate/publication_gate.py":"462567f7c9c68684b9b1d2f488086f979d2d3982","scripts/ci_validate_pr.py":"d9d860fc3705999360b35da91e73622bc924e886","scripts/selftest.py":"f495fa80fb0364aef4cba9eb4929dcd12933d16f","request/ACTION_REQUEST.json":"5b630f562abde995ca514d24320b6d025f42709a"}
def validate_dispatch_v2_changed_paths(changes,request,base_lock,base_root=None):
    if request.get("requested_action_id")!=DISPATCH_V2_ACTION: return []
    reasons=[]
    if request.get("action_kind")!="GOVERNANCE_UPGRADE":
        reasons.append("DISPATCH_V2_REQUIRES_GOVERNANCE_UPGRADE")
    if set(request.get("operations") or [])!={"GOVERNANCE_UPGRADE","PATCH"}:
        reasons.append("DISPATCH_V2_OPERATIONS_NOT_EXACT")
    if set(request.get("target_scope_ids") or [])!=DISPATCH_V2_SCOPES:
        reasons.append("DISPATCH_V2_SCOPE_NOT_EXACT")
    if set(changes)!=DISPATCH_V2_PATHS:
        reasons.append("DISPATCH_V2_EXACT_FIVE_PATHS_REQUIRED")
    if base_lock.get("generation")!=32 or base_lock.get("current_action",{}).get("mode")!="READ_ONLY":
        reasons.append("DISPATCH_V2_WRONG_BASE_LOCK")
    if base_root is None:
        reasons.append("DISPATCH_V2_TRUSTED_BASE_REQUIRED")
    else:
        for rel,expected in DISPATCH_V2_BASE_BLOBS.items():
            if git_blob_file(Path(base_root)/rel)!=expected:
                reasons.append("DISPATCH_V2_BASE_BLOB_MISMATCH:"+rel)
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
    reasons += validate_dispatch_v2_changed_paths(changes,req,load_json(base/LOCK),base)
    reasons += validate_gen33_broker_scope(changes,req,load_json(base/LOCK),base)
    reasons += validate_gen33_proof_scope(changes,req,load_json(base/LOCK),base)
    reasons += validate_gen33_race_install_scope(changes,req,load_json(base/LOCK),base)

    reasons += validate_gen34_code_scope(changes,req,load_json(base/LOCK),base)

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
