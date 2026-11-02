#!/usr/bin/env python3
"""GEN40 code-only scope auditor, fail-closed; NOT a publication engine.

The approval 41429004374 authorizes a protected PR for QA code only.
This module NEVER validates a book based on a self-asserted PASS string or
historical N2/G.7 success. It inventories 1397 source lines and 114 cases,
checks duplication, and enumerates unavailable independent evidence.
"""
from __future__ import annotations
import argparse, collections, hashlib, json
from pathlib import Path

PUBLIC_SHA = '04860dce8ef7cfcd63f4bdddcc4f92ffff6493fdded8829ff4c43070a8e35e42'
PRIVATE_SHA = '60f74349af42e0816d445fb198b372453060bb57663e413496169792b146c90d'
OFFICIAL_DOCX_SHA = 'f07f17593d984221af78941fb550d5903996dbcae7cf389aa9e518f6aa33b7db'
ACTION = 'GLOBAL_PUBLICATION_GEN40_INDEPENDENT_NORMATIVE_QA_CODE_ONLY_SCOPE_V1'
RUN = 41429004374
REFERENCE_COUNTS = {'GRAMMAR': (1153,848), 'BOOTSTRAP': (68,60), 'N2_GOLDEN': (113,106), 'N2_CROSSWALK': (63,50)}
CASE_COUNTS = {'PPGES':49,'N2':13,'G7':52}
SOURCE_ROSTER_SHA = '067a9c81f2848d8022a361d2a6a009d967a7fa82c45bd2d04be153e74a666c09'
CASE_ROSTER_SHA = 'c40a927ec2bbb9215e31bc228222adcdbb06a547218010266734dc6feed36f33'


def sha(data):return hashlib.sha256(data).hexdigest()


def inspect(inventory:dict, scope:dict)->dict:
    """Pure, deterministic scoped inventory check; cannot return book PASS."""
    blockers=[]
    if not isinstance(inventory,dict) or not isinstance(scope,dict):
        return {'status':'FAIL_CLOSED','blockers':['NON_OBJECT_INPUT'],'qualification':'NOT_PROVEN'}
    if inventory.get('schema')!='GEN40_INDEPENDENT_NORMATIVE_SCOPE_INVENTORY/1':blockers.append('INVENTORY_SCHEMA_INVALID')
    if scope.get('schema')!='GEN40_INDEPENDENT_QA_SCOPE_CODE_ONLY/1':blockers.append('SCOPE_SCHEMA_INVALID')
    if inventory.get('authorization_run_id')!=RUN or scope.get('authorization_run_id')!=RUN:blockers.append('WRONG_OWNER_RUN')
    if scope.get('requested_action_id')!=ACTION:blockers.append('ACTION_ID_MISMATCH')
    if scope.get('current_public_lock_sha256')!=PUBLIC_SHA or scope.get('private_state_declared_sha256')!=PRIVATE_SHA:
        blockers.append('AUTHORITY_IDENTITY_MISMATCH')
    refs=inventory.get('references',[])
    try:
        if not isinstance(refs,list):raise ValueError('REFERENCE_SET_NOT_LIST')
        refcounts={x['source']:(x['lines'],x['nonempty_lines']) for x in refs}
        if len(refcounts)!=len(refs) or refcounts!=REFERENCE_COUNTS:blockers.append('REFERENCE_POPULATION_MISMATCH')
    except (KeyError,TypeError,ValueError):blockers.append('REFERENCE_RECORD_INVALID')
    rows=inventory.get('source_rows',[])
    if not isinstance(rows,list) or len(rows)!=1397:
        blockers.append('MISSING_SOURCE_LINE_POPULATION');rows=[]
    identities=set();counts=collections.Counter();nonempty=collections.Counter()
    for row in rows:
        if not isinstance(row,dict):blockers.append('NONOBJECT_SOURCE_ROW');continue
        k=(row.get('source'),row.get('unit_id'),row.get('line_number'))
        if k in identities:blockers.append('DUPLICATE_SOURCE_LINE');continue
        identities.add(k)
        if row.get('source') not in REFERENCE_COUNTS or not isinstance(row.get('line_number'),int):
            blockers.append('SOURCE_LINE_IDENTITY_INVALID');continue
        if row.get('unit_id')!=f"{row['source']}:L{row['line_number']:05d}":blockers.append('SOURCE_UNIT_ID_NOT_CANONICAL')
        digest=row.get('text_sha256')
        if not isinstance(digest,str) or len(digest)!=64 or any(x not in '0123456789abcdef' for x in digest):
            blockers.append('SOURCE_LINE_DIGEST_INVALID')
        if row.get('qualification')!='NOT_RUN':blockers.append('SOURCE_LINE_PREMATURE_PASS')
        counts[row['source']]+=1
        if row.get('nonempty') is True:nonempty[row['source']]+=1
        elif row.get('nonempty') is not False:blockers.append('SOURCE_LINE_NONEMPTY_UNKNOWN')
    if counts!={k:v[0] for k,v in REFERENCE_COUNTS.items()} or nonempty!={k:v[1] for k,v in REFERENCE_COUNTS.items()}:
        blockers.append('SOURCE_LINE_COUNTS_OR_NONEMPTY_MISMATCH')
    if sum(nonempty.values())!=1064:blockers.append('EXPECTED_1064_LINE_POPULATION_MISSING')
    if sha(json.dumps(rows,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode('utf-8'))!=SOURCE_ROSTER_SHA:
        blockers.append('SOURCE_LINE_ROSTER_NOT_PINNED')
    cases=inventory.get('cases',[])
    if not isinstance(cases,list) or len(cases)!=114:
        blockers.append('MISSING_CASE_POPULATION');cases=[]
    caseids=set();groups=collections.Counter()
    for item in cases:
        if not isinstance(item,dict) or not isinstance(item.get('id'),str) or not item['id']:
            blockers.append('INVALID_CASE');continue
        key=(item.get('group'),item['id'])
        if key in caseids:blockers.append('DUPLICATE_CASE_ID')
        caseids.add(key);groups[item.get('group')]+=1
        if item.get('qualification')!='NOT_RUN':blockers.append('CASE_PREMATURE_PASS')
    if groups!=CASE_COUNTS:blockers.append('114_CASE_GROUP_COUNTS_MISMATCH')
    if sha(json.dumps(cases,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode('utf-8'))!=CASE_ROSTER_SHA:
        blockers.append('114_CASE_IDS_AND_ORDER_NOT_PINNED')
    if inventory.get('official_gen40_docx_sha256')!=OFFICIAL_DOCX_SHA:blockers.append('OFFICIAL_DOCX_IDENTITY_WRONG')
    if inventory.get('original_ppges_registry_verified') is not False:blockers.append('UNVERIFIED_PPGES_REGISTRY_CLAIM')
    if inventory.get('official_docx_bytes_available') is not False:blockers.append('UNVERIFIED_OFFICIAL_DOCX_BYTES_CLAIM')
    if inventory.get('all_normative_atoms_qualified') is not False:blockers.append('UNVERIFIED_ATOMICITY_CLAIM')
    if inventory.get('word_desktop_mobile_pdf_evidence') is not False:blockers.append('UNVERIFIED_WORD_PDF_CLAIM')
    # Even error-free inventory does not attest independent bytes or 114
    # complete positive/negative/manual tests. Never claim full qualification.
    return {'status':'PASS_SCOPED_INVENTORY_ONLY' if not blockers else 'FAIL_CLOSED',
            'blockers':sorted(set(blockers)), 'source_lines':len(rows),'nonempty_lines':sum(nonempty.values()),
            'case_records':len(cases),'qualification':'NOT_PROVEN',
            'next_evidence':['frozen primary PPGES registry SHA','all atomic clauses and exception branches',
                'signed independently replayed per-case positive and negative evidence',
                'official GEN40 DOCX bytes and Word Desktop/Mobile/PDF visual proof']}


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--inventory',required=True);ap.add_argument('--scope',required=True)
    ap.add_argument('--out');a=ap.parse_args()
    try:r=inspect(json.loads(Path(a.inventory).read_text()),json.loads(Path(a.scope).read_text()))
    except Exception as ex:r={'status':'FAIL_CLOSED','blockers':['READ_OR_PARSE_ERROR:'+type(ex).__name__], 'qualification':'NOT_PROVEN'}
    if a.out:Path(a.out).write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps(r))
    return 0 if r['status']=='PASS_SCOPED_INVENTORY_ONLY' else 2


if __name__=='__main__':raise SystemExit(main())
