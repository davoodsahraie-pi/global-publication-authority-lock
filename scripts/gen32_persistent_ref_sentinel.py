#!/usr/bin/env python3
"""GEN32 synthetic GitHub ref-claim experiment. NOT an authorization broker.

Invariants: fixed synthetic tag namespace; verify Ruleset before POST;
only a confirmed 201 for a new Git ref may emit a local synthetic marker;
unknown/timeout/422/permission failures never cause retries or any production work.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

REPOSITORY = 'davoodsahraie-pi/global-publication-authority-lock'
OWNER = 'davoodsahraie-pi'
RULESET_ID = 26012498
TAG_PATTERN = 'refs/tags/gen32-sentinel-claim/*'
CLAIM_REF = 'refs/tags/gen32-sentinel-claim/20261028-synthetic-a01'
PUBLIC_SHA256 = '6870614362a1d090f4694d5f9de035ef4922ec5161707e7b9f83b82431ad64d9'
PRIVATE_SHA256 = 'dfe3488ff09feba990938953c0caab822a01b90c32cc687d11c08f80d0818ed1'
BASE_API = f'https://api.github.com/repos/{REPOSITORY}'

class RefDenied(Exception):
    pass


def verify_local_authority() -> None:
    root=Path(__file__).resolve().parents[1]
    lock_bytes=(root/'authority/CURRENT.json').read_bytes()
    lock_sha=hashlib.sha256(lock_bytes).hexdigest()
    side=(root/'authority/CURRENT.sha256').read_text(encoding='utf-8').split()[0]
    lock=json.loads(lock_bytes)
    if lock_sha!=PUBLIC_SHA256 or side!=PUBLIC_SHA256:
        raise RefDenied('PUBLIC_LOCK_SHA_CHANGED')
    if lock.get('private_execution_state_sha256')!=PRIVATE_SHA256:
        raise RefDenied('PRIVATE_STATE_SHA_CHANGED')
    if lock.get('generation')!=32 or (lock.get('current_action') or {}).get('mode')!='READ_ONLY':
        raise RefDenied('AUTHORITY_UNEXPECTED_MODE')
    if lock.get('execution_authorized_now') is not False:
        raise RefDenied('EXECUTE_FLAG_UNEXPECTED')
    receipt=lock.get('gen29_attempt01_forensic_closeout_receipt') or {}
    if receipt.get('status')!='CONSUMED_CLOSED':
        raise RefDenied('GEN29_RECEIPT_CHANGED')


def verify_runner_context() -> str:
    if os.environ.get('GITHUB_REPOSITORY')!=REPOSITORY:
        raise RefDenied('REPO_MISMATCH')
    if os.environ.get('GITHUB_ACTOR','').lower()!=OWNER:
        raise RefDenied('ACTOR_NOT_OWNER')
    if os.environ.get('GITHUB_EVENT_NAME')!='workflow_dispatch':
        raise RefDenied('EVENT_NOT_MANUAL_DISPATCH')
    if os.environ.get('GITHUB_REF')!='refs/heads/main':
        raise RefDenied('BRANCH_NOT_MAIN')
    if os.environ.get('GITHUB_WORKFLOW_REF')!=(
        REPOSITORY+'/.github/workflows/gen32-sentinel-persistent-ref.yml@refs/heads/main'):
        raise RefDenied('WORKFLOW_REF_MISMATCH')
    sha=os.environ.get('GITHUB_SHA','')
    if not re.fullmatch(r'[0-9a-f]{40}',sha):
        raise RefDenied('COMMIT_SHA_INVALID')
    return sha


def api(method: str, path: str, payload: object|None = None) -> tuple[int, object]:
    token=os.environ.get('GH_TOKEN','')
    if not token:
        raise RefDenied('MISSING_WORKFLOW_TOKEN')
    data=None if payload is None else json.dumps(payload,separators=(',',':')).encode('utf-8')
    req=urllib.request.Request(BASE_API+path,data=data,method=method,
        headers={'Authorization':f'Bearer {token}',
                 'Accept':'application/vnd.github+json',
                 'X-GitHub-Api-Version':'2022-11-28',
                 'User-Agent':'gen32-synthetic-ref-only',
                 'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=15) as res:
            code=res.status
            content=res.read(32000)
    except urllib.error.HTTPError as e:
        code=e.code
        content=e.read(32000)
    # No retry on network errors, not even on transient GitHub conditions.
    try:
        response=json.loads(content.decode('utf-8')) if content else {}
    except (ValueError,UnicodeError):
        response={}
    return code,response


def ruleset_ok(rule: object) -> bool:
    if not isinstance(rule,dict):
        return False
    conditions=rule.get('conditions') or {}
    refs=conditions.get('ref_name') or {}
    types={r.get('type') for r in rule.get('rules',[]) if isinstance(r,dict)}
    return (rule.get('id')==RULESET_ID
        and rule.get('target')=='tag'
        and rule.get('enforcement')=='active'
        and rule.get('source')==REPOSITORY
        and refs.get('include')==[TAG_PATTERN]
        and refs.get('exclude')==[]
        and rule.get('bypass_actors')==[]
        and rule.get('current_user_can_bypass')=='never'
        and {'deletion','update'}.issubset(types)
        and 'creation' not in types)


def verify_ruleset() -> None:
    status,rule=api('GET',f'/rulesets/{RULESET_ID}')
    if status!=200 or not ruleset_ok(rule):
        raise RefDenied(f'RULESET_NOT_VERIFIED_{status}')


def check_ref() -> None:
    # Verifies that the synthetic ref exists and was never redirected.
    verify_local_authority()
    sha=verify_runner_context()
    verify_ruleset()
    status,info=api('GET','/git/ref/tags/gen32-sentinel-claim/20261028-synthetic-a01')
    if not (status==200 and isinstance(info,dict)
            and info.get('ref')==CLAIM_REF
            and isinstance(info.get('object'),dict)
            and info['object'].get('sha')==sha):
        raise RefDenied(f'SYNTHETIC_REF_NOT_PINNED_{status}')
    print('SYNTHETIC_REF_EXISTS_AND_RULESET_STILL_ACTIVE')


def classify_create_result(status: int, obj: object, commit_sha: str) -> str:
    if (status==201 and isinstance(obj,dict) and obj.get('ref')==CLAIM_REF
        and isinstance(obj.get('object'),dict)
        and obj['object'].get('sha')==commit_sha):
        return 'WON'
    if status in (409,422):
        return 'DENIED'
    return 'UNKNOWN' # fail closed, never retry


def write_output(value: str) -> None:
    target=os.environ.get('GITHUB_OUTPUT')
    if target:
        with Path(target).open('a',encoding='utf-8') as f:
            f.write('outcome='+value+'\n')


def claim() -> int:
    try:
        verify_local_authority()
        commit_sha=verify_runner_context()
        verify_ruleset()
        status,body=api('POST','/git/refs',{'ref':CLAIM_REF,'sha':commit_sha})
        outcome=classify_create_result(status,body,commit_sha)
    except (RefDenied,OSError,ValueError,urllib.error.URLError,TimeoutError) as exc:
        # No attempts to mutate anything after any uncertain result.
        print('SYNTHETIC_CLAIM_FAIL_CLOSED: '+type(exc).__name__)
        write_output('UNKNOWN')
        return 1
    print(f'SYNTHETIC_CLAIM_RESULT={outcome} HTTP={status}')
    write_output(outcome)
    if outcome=='WON':
        # Local job marker only. Never real producer, grant, file promotion, DOCX/PDF.
        marker=Path(os.environ['RUNNER_TEMP'])/'gen32_SYNTHETIC_WINNER_ONLY.marker'
        marker.open('x',encoding='utf-8').write('SYNTHETIC-ONLY\n')
        print('SYNTHETIC_LOCAL_MARKER_CREATED')
    return 0 if outcome in ('WON','DENIED') else 1


def selftest() -> int:
    sha='a'*40
    valid={
        'id':RULESET_ID,'name':'GEN32-SYNTHETIC-CLAIM-IMMUTABLE',
        'target':'tag','source':REPOSITORY,'enforcement':'active',
        'conditions':{'ref_name':{'include':[TAG_PATTERN],'exclude':[]}},
        'rules':[{'type':'update'},{'type':'deletion'},{'type':'non_fast_forward'}],
        'bypass_actors':[],'current_user_can_bypass':'never'
    }
    checks={
      'ACTIVE_RULE_ACCEPTED':ruleset_ok(valid),
      'INACTIVE_RULE_DENIED':not ruleset_ok({**valid,'enforcement':'disabled'}),
      'WRONG_TARGET_DENIED':not ruleset_ok({**valid,'target':'branch'}),
      'BYPASS_DENIED':not ruleset_ok({**valid,'bypass_actors':[{'actor_id':1}]}),
      'MISSING_UPDATE_PROTECTION_DENIED':not ruleset_ok({**valid,'rules':[{'type':'deletion'}]}),
      'WRONG_TAG_PATTERN_DENIED':not ruleset_ok({**valid,'conditions':{'ref_name':{'include':['refs/tags/*'],'exclude':[]}}}),
      'UNEXPECTED_CREATION_RESTRICTION_DENIED':not ruleset_ok({**valid,'rules':[{'type':'creation'},{'type':'update'},{'type':'deletion'}]}),
      'CONFIRMED_CREATE_WIN':classify_create_result(201,{'ref':CLAIM_REF,'object':{'sha':sha}},sha)=='WON',
      'CONFLICT_DENIED':classify_create_result(422,{},sha)=='DENIED',
      'RESPONSE_LOSS_DENIED':classify_create_result(0,{},sha)=='UNKNOWN',
      'MALFORMED_SUCCESS_DENIED':classify_create_result(201,{'ref':'other','object':{'sha':sha}},sha)=='UNKNOWN',
      'WRONG_SHA_SUCCESS_DENIED':classify_create_result(201,{'ref':CLAIM_REF,'object':{'sha':'b'*40}},sha)=='UNKNOWN',
    }
    result={'schema':'GEN32_PERSISTENT_REF_SENTINEL_PURE_UNIT/1.0.0',
            'mode':'LOCAL_NO_GITHUB_MUTATION','total':len(checks),
            'passed':sum(checks.values()),'checks':checks}
    print(json.dumps(result,indent=2))
    return 0 if result['passed']==result['total'] else 1


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument('mode',choices=('selftest','claim','check-ruleset','check-ref'))
    args=p.parse_args()
    if args.mode=='selftest':
        return selftest()
    if args.mode=='check-ref':
        try:
            check_ref()
            return 0
        except (RefDenied,OSError,ValueError,urllib.error.URLError,TimeoutError) as exc:
            print('REF_FINAL_CHECK_DENY_'+type(exc).__name__)
            return 1
    if args.mode=='check-ruleset':
        try:
            verify_local_authority()
            verify_runner_context()
            verify_ruleset()
            print('RULESET_PREFLIGHT_PASS_SYNTHETIC_ONLY')
            return 0
        except (RefDenied,OSError,ValueError,urllib.error.URLError,TimeoutError) as exc:
            print('RULESET_PREFLIGHT_DENY_'+type(exc).__name__)
            return 1
    return claim()

if __name__=='__main__':
    raise SystemExit(main())
