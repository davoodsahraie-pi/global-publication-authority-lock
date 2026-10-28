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
from datetime import datetime, timezone
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
# Independently inspected Ruleset 26012498 (GitHub connected owner-authorized read).
# All fields except bypass permissions are checked live with a version pin.
# GitHub hides bypass_actors from callers without ruleset-write access.
OWNER_RULESET_ATTESTATION = {
    'id': RULESET_ID,
    'node_id': 'RRS_lACqUmVwb3NpdG9yec5UXi5YzgGM61I',
    'updated_at': '2026-10-28T08:37:36.633+03:30',
    'name': 'GEN32-SYNTHETIC-CLAIM-IMMUTABLE',
    'target': 'tag',
    'source_type': 'Repository',
    'source': REPOSITORY,
    'enforcement': 'active',
    'ref_include': [TAG_PATTERN],
    'ref_exclude': [],
    'rule_types': {'deletion', 'non_fast_forward', 'update'},
    'verified_bypass_actors': [],
    'verified_owner_bypass_status': 'never',
}

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


def same_instant(a: object, b: object) -> bool:
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    try:
        parse = lambda v: datetime.fromisoformat(v.replace('Z', '+00:00')).astimezone(timezone.utc)
        return parse(a) == parse(b)
    except (ValueError, TypeError):
        return False


def ruleset_verdict(status: int, rule: object) -> str:
    """Return safe, bounded diagnostic; never interpret redaction as no bypass.

    A pinned owner-reviewed Ruleset version is only a limited *synthetic*
    compatibility witness, not cryptographic proof of cross-run immutability.
    """
    if status != 200:
        return ('RULESET_HTTP_'+str(status)+'_NO_CLAIM') if status in (401,403,404,422,429,500,502,503,504) else 'RULESET_HTTP_OTHER_NO_CLAIM'
    if not isinstance(rule, dict):
        return 'RULESET_SCHEMA_NO_CLAIM'
    w = OWNER_RULESET_ATTESTATION
    if w['verified_bypass_actors'] != [] or w['verified_owner_bypass_status'] != 'never':
        return 'OWNER_WITNESS_INVALID_NO_CLAIM'
    for field in ('id','node_id','name','target','source_type','source','enforcement'):
        if rule.get(field) != w[field]:
            return 'RULESET_'+field.upper()+'_DRIFT_NO_CLAIM'
    if not same_instant(rule.get('updated_at'), w['updated_at']):
        return 'RULESET_VERSION_DRIFT_NO_CLAIM'
    refs = rule.get('conditions')
    if not isinstance(refs,dict) or not isinstance(refs.get('ref_name'),dict):
        return 'RULESET_CONDITIONS_NO_CLAIM'
    refs=refs['ref_name']
    if refs.get('include') != w['ref_include'] or refs.get('exclude') != w['ref_exclude']:
        return 'RULESET_PATTERN_DRIFT_NO_CLAIM'
    rules=rule.get('rules')
    if not isinstance(rules,list) or not all(isinstance(item,dict) and isinstance(item.get('type'),str) for item in rules):
        return 'RULESET_RULES_SCHEMA_NO_CLAIM'
    types=[item['type'] for item in rules]
    if set(types) != w['rule_types'] or len(types) != len(w['rule_types']):
        return 'RULESET_RULES_DRIFT_NO_CLAIM'
    # An omitted field is REDACTED (not an empty list). Accept only if exact
    # immutable *version identity and all visible protections* match the
    # independently checked owner witness embedded in protected source.
    if 'bypass_actors' in rule and rule['bypass_actors'] != []:
        return 'RULESET_BYPASS_CONFLICT_NO_CLAIM'
    if 'current_user_can_bypass' in rule and rule['current_user_can_bypass'] != 'never':
        return 'RULESET_BYPASS_STATUS_CONFLICT_NO_CLAIM'
    return 'PASS_RULESET_OWNER_VERSION_ATTESTED_SYNTHETIC_ONLY'


def ruleset_ok(rule: object) -> bool:
    # Compatibility alias so old tests stay meaningful; fail-closed on drift.
    return ruleset_verdict(200,rule).startswith('PASS_')


def verify_ruleset() -> None:
    status,rule=api('GET',f'/rulesets/{RULESET_ID}')
    verdict=ruleset_verdict(status,rule)
    if not verdict.startswith('PASS_'):
        raise RefDenied(verdict)


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
        print('SYNTHETIC_CLAIM_FAIL_CLOSED: '+(str(exc) if isinstance(exc,RefDenied) else type(exc).__name__))
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
        'id':RULESET_ID,'node_id':OWNER_RULESET_ATTESTATION['node_id'],
        'updated_at':OWNER_RULESET_ATTESTATION['updated_at'],
        'name':'GEN32-SYNTHETIC-CLAIM-IMMUTABLE',
        'source_type':'Repository',
        'target':'tag','source':REPOSITORY,'enforcement':'active',
        'conditions':{'ref_name':{'include':[TAG_PATTERN],'exclude':[]}},
        'rules':[{'type':'update'},{'type':'deletion'},{'type':'non_fast_forward'}],
        'bypass_actors':[],'current_user_can_bypass':'never'
    }
    checks={
      'ACTIVE_RULE_ACCEPTED':ruleset_ok(valid),
      'REDACTED_BYPASS_WITH_VERSION_ATTESTED':ruleset_ok({k:v for k,v in valid.items() if k not in ('bypass_actors','current_user_can_bypass')}),
      'REDACTED_WITH_VERSION_DRIFT_DENIED':not ruleset_ok({**{k:v for k,v in valid.items() if k not in ('bypass_actors','current_user_can_bypass')},'updated_at':'2026-10-28T08:39:01+03:30'}),
      'MISSING_VERSION_DENIED':not ruleset_ok({k:v for k,v in valid.items() if k!='updated_at'}),
      'NODE_ID_DRIFT_DENIED':not ruleset_ok({**valid,'node_id':'wrong'}),
      'SOURCE_TYPE_DRIFT_DENIED':not ruleset_ok({**valid,'source_type':'Organization'}),
      'SAME_INSTANT_UTC_ACCEPTED':ruleset_ok({**valid,'updated_at':'2026-10-28T05:07:36.633Z'}),
      'EXPLICIT_BYPASS_STATUS_DENIED':not ruleset_ok({**valid,'current_user_can_bypass':'always'}),
      'HTTP_403_FAILS_CLOSED':ruleset_verdict(403,{})=='RULESET_HTTP_403_NO_CLAIM',
      'HTTP_404_FAILS_CLOSED':ruleset_verdict(404,{})=='RULESET_HTTP_404_NO_CLAIM',
      'MALFORMED_RESPONSE_FAILS_CLOSED':ruleset_verdict(200,None)=='RULESET_SCHEMA_NO_CLAIM',

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
            print('REF_FINAL_CHECK_DENY_'+(str(exc) if isinstance(exc,RefDenied) else type(exc).__name__))
            return 1
    if args.mode=='check-ruleset':
        try:
            verify_local_authority()
            verify_runner_context()
            verify_ruleset()
            print('RULESET_PREFLIGHT_PASS_SYNTHETIC_ONLY')
            return 0
        except (RefDenied,OSError,ValueError,urllib.error.URLError,TimeoutError) as exc:
            print('RULESET_PREFLIGHT_DENY_'+(str(exc) if isinstance(exc,RefDenied) else type(exc).__name__))
            return 1
    return claim()

if __name__=='__main__':
    raise SystemExit(main())
