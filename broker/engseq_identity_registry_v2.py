#!/usr/bin/env python3
"""GEN37 R25R7 ENGSEQ R09: additive, LAB-ONLY identity-v2 admission adapter.

Consumes *frozen and already-qualified* R08 crosswalk rows. Does not scan source,
call Producer, alter original Generator/Driver, or grant official publication.
A protected Broker must supply a scoped verifier when the active evidence policy requires it; it
must authenticate its own identity/trust anchors out of band.
"""
from __future__ import annotations
import hashlib
import json
import re
from typing import Callable

REGISTRY_SCHEMA = 'GEN37_ENGSEQ_ADJUDICATION/2.0'
SOURCE_SHA = '360ee8a7db0cfead8576b68b768bfa9e0f4038fd9f2892102e801541abc272d5'
QUEUE_SHA = '2e970a4f50cfef286d8d041ca3c4c02f48c5bd4cdc96c9718913240ed9ae85fe'
R08_ARCHIVE_SHA = '27bfe2030719e38faa100fefc0e8759e46362874c40de0342073dcd93707bd63'
ALLOWED_AB = {'A_CONTINUOUS_TECHNICAL_PHRASE','B_PROPER_NAME_OR_TITLE'}
HEX64 = re.compile(r'^[0-9a-f]{64}$')
BINDING_FIELDS = (
    'canonical_source_sha256','source_line','canonical_block_id','publication_block_id',
    'source_record_sha256','effective_text_sha256','publication_role',
    'offset_start','offset_end','sequence','occurrence_sha256_legacy_unchanged',
    'stable_occurrence_key_sha256','stable_record_key_sha256',
)
STABLE_OCCURRENCE_FIELDS = (
    'canonical_source_sha256','source_line','canonical_block_id','publication_block_id',
    'source_record_sha256','effective_text_sha256','offset_start','offset_end',
    'sequence','occurrence_sha256_legacy_unchanged',
)
STABLE_RECORD_FIELDS = (
    'canonical_source_sha256','source_line','canonical_block_id','publication_block_id',
    'source_record_sha256','effective_text_sha256',
)

class IdentityHold(ValueError):
    """Fixed-code identity rejection. No source content belongs in public logs."""

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def cj(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')

def check(test, reason):
    if not test:
        raise IdentityHold(reason)

def integer(value):
    return type(value) is int and value > 0

def offset(value):
    return type(value) is int and value >= 0

def verify_identity_pair(record: dict, occurrence: dict, *, source_sha=SOURCE_SHA, queue_sha=QUEUE_SHA) -> dict:
    """Validate an R08 record-crosswalk/occurrence-crosswalk pair; no semantic scan.

    Stable keys are independently recomputed from frozen row metadata. This is
    NOT a replacement for a protected input archive SHA/byte-readback gate.
    """
    check(isinstance(record,dict) and isinstance(occurrence,dict),'ROW_TYPE_INVALID')
    check(source_sha==SOURCE_SHA and queue_sha==QUEUE_SHA,'INPUT_PINS_CHANGED')
    check(record.get('canonical_source_sha256')==source_sha and
          occurrence.get('canonical_source_sha256')==source_sha,'SOURCE_SHA_MISMATCH')
    check(occurrence.get('queue_sha256')==queue_sha,'QUEUE_SHA_MISMATCH')
    for k in ('source_line','canonical_block_id','publication_block_id'):
        check(integer(record.get(k)) and integer(occurrence.get(k)) and
              record[k]==occurrence[k], 'RECORD_OCCURRENCE_'+k.upper()+'_MISMATCH')
    check(record['source_line']==record['publication_block_id'], 'SOURCE_LINE_PUBLICATION_ID_MISMATCH')
    check(record.get('source_record_sha256')==occurrence.get('source_record_sha256') and
          isinstance(record.get('source_record_sha256'),str) and
          bool(HEX64.fullmatch(record['source_record_sha256'])), 'SOURCE_RECORD_SHA_MISMATCH')
    check(record.get('effective_text_sha256')==occurrence.get('effective_text_sha256') and
          isinstance(record.get('effective_text_sha256'),str) and
          bool(HEX64.fullmatch(record['effective_text_sha256'])), 'EFFECTIVE_SHA_MISMATCH')
    check(record.get('role')==occurrence.get('publication_role'), 'ROLE_MISMATCH')
    check(record.get('record_class')==occurrence.get('record_class'), 'RECORD_CLASS_MISMATCH')
    check(occurrence.get('legacy_queue_block_id')==record['publication_block_id'], 'LEGACY_QUEUE_ALIAS_MISMATCH')
    check(occurrence.get('identity_attested') is True, 'R08_ATTESTATION_MISSING')
    a,b=occurrence.get('offset_start'),occurrence.get('offset_end')
    check(offset(a) and offset(b) and a < b, 'OFFSETS_INVALID')
    check(isinstance(occurrence.get('sequence'),str) and len(occurrence['sequence'])>0, 'SEQUENCE_MISSING')
    check(all(isinstance(occurrence.get(k),str) and bool(HEX64.fullmatch(occurrence[k])) for k in
              ('occurrence_sha256_legacy_unchanged','stable_occurrence_key_sha256')),
          'OCCURRENCE_HASH_MISSING')
    check(record.get('stable_record_key_sha256') == sha(cj({k:record[k] for k in STABLE_RECORD_FIELDS})),
          'STABLE_RECORD_KEY_INVALID')
    check(occurrence['stable_occurrence_key_sha256'] == sha(cj({k:occurrence[k] for k in STABLE_OCCURRENCE_FIELDS})),
          'STABLE_OCCURRENCE_KEY_INVALID')
    check(record.get('source_start_line')==occurrence.get('source_start_line') and
          record.get('source_end_line')==occurrence.get('source_end_line'),
          'SOURCE_ORIGIN_LINES_MISMATCH')
    return {
        **{k:(record['stable_record_key_sha256'] if k=='stable_record_key_sha256' else occurrence[k]) for k in BINDING_FIELDS},
        'canonical_queue_sha256':queue_sha,
    }

def validate_registry_document(document: dict, *, source_sha=SOURCE_SHA, queue_sha=QUEUE_SHA,
                               crosswalk_archive_sha=R08_ARCHIVE_SHA) -> dict:
    check(isinstance(document,dict) and document.get('schema')==REGISTRY_SCHEMA, 'V1_OR_UNKNOWN_REGISTRY_DENIED')
    check(document.get('canonical_source_sha256')==source_sha==SOURCE_SHA, 'REGISTRY_SOURCE_PIN_INVALID')
    check(document.get('canonical_queue_sha256')==queue_sha==QUEUE_SHA, 'REGISTRY_QUEUE_PIN_INVALID')
    check(document.get('r08_crosswalk_archive_sha256')==crosswalk_archive_sha==R08_ARCHIVE_SHA,
          'REGISTRY_CROSSWALK_PIN_INVALID')
    entries=document.get('entries')
    check(isinstance(entries,list),'REGISTRY_ENTRIES_INVALID')
    index={}
    for entry in entries:
        check(isinstance(entry,dict), 'REGISTRY_ENTRY_INVALID')
        key=entry.get('stable_occurrence_key_sha256')
        check(isinstance(key,str) and bool(HEX64.fullmatch(key)), 'REGISTRY_KEY_MISSING')
        check(key not in index, 'REGISTRY_DUPLICATE_STABLE_KEY')
        check('block_id' not in entry, 'AMBIGUOUS_LEGACY_ID_FORBIDDEN')
        index[key]=entry
    return index

def bind_entry(entry:dict, binding:dict) -> None:
    check(isinstance(entry,dict), 'REGISTRY_ENTRY_NOT_OBJECT')
    check('block_id' not in entry, 'AMBIGUOUS_LEGACY_ID_FORBIDDEN')
    for field in BINDING_FIELDS:
        check(field in binding and field in entry and type(entry[field]) is type(binding[field]) and
              entry[field]==binding[field], 'REGISTRY_BINDING_MISMATCH_'+field.upper())
    check(entry.get('canonical_queue_sha256')==binding['canonical_queue_sha256'], 'REGISTRY_QUEUE_BINDING_MISMATCH')
    check(entry['publication_block_id']==entry['source_line'], 'REGISTRY_LINE_PUBLICATION_MISMATCH')
    check(offset(entry['offset_start']) and offset(entry['offset_end']) and
          entry['offset_start']<entry['offset_end'], 'REGISTRY_OFFSETS_INVALID')

def evaluate_occurrence(record:dict, occurrence:dict, registry_index:dict, ppges, *,
                        receipt_verifier:Callable | None=None, policy_sha256:str | None=None) -> dict:
    """Returns LAB semantic disposition; never a publication authorization.

    `ppges` must be loaded from SHA-pinned v1.3.5 by the protected caller.
    `receipt_verifier` must be a qualified pinned Broker callback. Test mocks
    cannot confer authority; caller cannot install arbitrary callback in PROD.
    """
    binding=verify_identity_pair(record,occurrence)
    key=binding['stable_occurrence_key_sha256']
    entry=registry_index.get(key)
    if entry is not None:
        bind_entry(entry,binding)  # reject stale and cross-record entries *before* any auto-known shortcut
    innate=ppges.classify_english_sequence(binding['sequence'])
    if innate.get('status')=='AUTO_KNOWN' and innate.get('class') in ALLOWED_AB:
        return {'decision':'AB_VERIFIED_PPGES_KNOWN_LAB','class':innate['class'],
                'stable_occurrence_key_sha256':key,'producer_authorized':False}
    if entry is None:
        return {'decision':'HOLD_NO_SCOPED_DECISION','stable_occurrence_key_sha256':key,'producer_authorized':False}
    if entry.get('editorial_vote')!='APPROVE' or entry.get('class') not in ALLOWED_AB:
        return {'decision':'HOLD_NOT_AN_APPROVED_AB','stable_occurrence_key_sha256':key,'producer_authorized':False}
    # GEN38: the base Grammar/PPGES does not impose two human receipts on every A/B.
    # Unknown A/B remains held without an authenticated policy-scoped verifier.
    if not all(isinstance(entry.get(k),str) and entry[k].strip() for k in
               ('domain','sense_id','reason','evidence_uri','review_version')):
        return {'decision':'HOLD_EVIDENCE_OR_RECEIPT_METADATA_MISSING','producer_authorized':False}
    if not isinstance(entry.get('evidence_sha256'),str) or not HEX64.fullmatch(entry['evidence_sha256']):
        return {'decision':'HOLD_EVIDENCE_DIGEST_MISSING','producer_authorized':False}
    structured={'class':entry['class'],'reason':entry['reason'],'evidence':entry['evidence_uri'],
                'segments':[binding['sequence']]}
    proof=ppges.classify_english_sequence(binding['sequence'],structured)
    if proof.get('status')!='REVIEWED_WITH_EVIDENCE' or proof.get('class') not in ALLOWED_AB:
        return {'decision':'HOLD_PPGES_STRUCTURED_DECISION_INVALID','producer_authorized':False}
    if not policy_sha256 or not HEX64.fullmatch(policy_sha256) or receipt_verifier is None:
        return {'decision':'HOLD_QUALIFIED_VERIFIER_UNAVAILABLE','producer_authorized':False}
    try:
        result=receipt_verifier(entry,binding)
    except Exception:
        result=None
    if not isinstance(result,dict) or result.get('authenticated') is not True or result.get('trust_policy_sha256')!=policy_sha256 or result.get('scope_occurrence_sha256')!=key:
        return {'decision':'HOLD_REVIEW_AUTHENTICATION_FAILED','producer_authorized':False}
    return {'decision':'AB_WITH_SCOPED_EXTERNAL_ATTESTATION_LAB_ONLY',
            'class':proof['class'],'stable_occurrence_key_sha256':key,
            'producer_authorized':False}

def bind_source_delta(delta:dict, record:dict) -> dict:
    """Immutable v2 Source Delta envelope. No file edit; reject legacy id-only lookup."""
    check(delta.get('canonical_source_sha256')==SOURCE_SHA, 'DELTA_SOURCE_PIN_MISMATCH')
    for k in ('canonical_block_id','publication_block_id','source_line','source_record_sha256'):
        check(k in delta and delta[k]==record.get(k), 'DELTA_'+k.upper()+'_MISMATCH')
    check(delta.get('before_sha256')==record.get('effective_text_sha256'), 'DELTA_EFFECTIVE_BEFORE_HASH_MISMATCH')
    check(isinstance(delta.get('before'),str) and isinstance(delta.get('after'),str), 'DELTA_TEXT_MISSING')
    check(sha(delta['before'].encode('utf-8'))==delta['before_sha256'], 'DELTA_BEFORE_BYTES_CHANGED')
    check(sha(delta['after'].encode('utf-8'))==delta.get('after_sha256'), 'DELTA_AFTER_BYTES_CHANGED')
    check(delta.get('approved_for_source_mutation') is False, 'DELTA_FALSE_APPROVAL_CLAIM')
    return {'schema':'GEN37_R25R7_DELTA_IDENTITY/2.0_LAB',
            'canonical_source_sha256':SOURCE_SHA, 'delta_id':delta['delta_id'],
            'canonical_block_id':record['canonical_block_id'],
            'publication_block_id':record['publication_block_id'],
            'source_line':record['source_line'],
            'source_record_sha256':record['source_record_sha256'],
            'effective_text_sha256':record['effective_text_sha256'],
            'stable_record_key_sha256':record['stable_record_key_sha256'],
            'before_sha256':delta['before_sha256'], 'after_sha256':delta['after_sha256'],
            'before':delta['before'], 'after':delta['after'],
            'independent_review_status':delta.get('r07_review_status'),
            'eligible_for_official_application':False}

def reject_unbound_registry_entries(registry_index:dict, verified_crosswalk_keys:set[str]) -> None:
    """Protects against unsolicited approvals; caller authenticates complete R08 index."""
    check(isinstance(registry_index,dict) and isinstance(verified_crosswalk_keys,set),
          'REGISTRY_COVERAGE_INPUT_INVALID')
    check(not (set(registry_index)-verified_crosswalk_keys),'REGISTRY_ORPHAN_APPROVAL_KEY')

def lab_preclaim_identity_seam(*, record_row:dict, occurrence_row:dict,
                               registry_document:dict, ppges, receipt_verifier=None,
                               trust_policy_sha256=None) -> dict:
    """Executable LAB seam: veto-first. No claim, no Producer, no official grant.

    Protected Broker must pin R08 archive byte digest, source+queue bytes,
    PPGE engine code digest, registry digest and external verifier code+policy;
    this function only guards a selected occurrence's semantic/identity match.
    """
    registry=validate_registry_document(registry_document)
    decision=evaluate_occurrence(record_row,occurrence_row,registry,ppges,
        receipt_verifier=receipt_verifier,policy_sha256=trust_policy_sha256)
    return {**decision,'release_authorized':False,'gate_type':'LAB_PRECLAIM_IDENTITY_ONLY'}

# Archive pins are a prerequisite for trusting R08's prior identity findings.
# Never substitute a recomputed crosswalk for the already-attested frozen files.
R08_RECORD_CROSSWALK_GZIP_SHA = 'b3a050a4c4b55185a2646470f3a4cb584590123da22ca289e2744148ca95141c'
R08_OCCURRENCE_CROSSWALK_GZIP_SHA = '715099b791e0a6c6b756bf8280bd5148f6b784d21793b5c21fd184bd51c101b8'

def require_frozen_crosswalk_bytes(*, r08_archive: bytes, record_crosswalk_gzip: bytes,
                                   occurrence_crosswalk_gzip: bytes) -> None:
    """Byte checks only; no repeat of R08 record or semantic scanning."""
    check(sha(r08_archive)==R08_ARCHIVE_SHA, 'R08_ORIGINAL_ARCHIVE_PIN_MISMATCH')
    check(sha(record_crosswalk_gzip)==R08_RECORD_CROSSWALK_GZIP_SHA, 'R08_RECORD_CROSSWALK_PIN_MISMATCH')
    check(sha(occurrence_crosswalk_gzip)==R08_OCCURRENCE_CROSSWALK_GZIP_SHA, 'R08_OCCURRENCE_CROSSWALK_PIN_MISMATCH')

def preclaim_v2_from_frozen_crosswalk(*, protected_profile:dict, source_bytes:bytes,
                                      queue_bytes:bytes, r08_archive:bytes,
                                      record_crosswalk_gzip:bytes, occurrence_crosswalk_gzip:bytes,
                                      registry_bytes:bytes, pinned_ppges, qualified_verifier=None) -> dict:
    """Proposed, isolated Broker seam; never launches anything or grants a claim.

    This reads the existing R08 crosswalks, NOT the original manuscript Regex.
    No test or full-book call is made by R09; this is the future integration API.
    
    The protected Broker must independently assert that protected_profile itself
    was authenticated from protected public+private authority. A caller-supplied
    dictionary is NOT authoritative. It must also ensure only this preclaim seam
    can reach redeem()/Driver and pin the unchanged Generator/Driver/PPGES bytes.
    """
    import gzip
    from collections import Counter
    check(isinstance(protected_profile,dict) and
          protected_profile.get('schema')=='GEN37_ENGSEQ_IDENTITY_V2_PROTECTED_PROFILE/1.0',
          'PROTECTED_V2_PROFILE_REQUIRED')
    expected={'canonical_source_sha256':SOURCE_SHA,'queue_sha256':QUEUE_SHA,
              'r08_archive_sha256':R08_ARCHIVE_SHA,
              'record_crosswalk_gzip_sha256':R08_RECORD_CROSSWALK_GZIP_SHA,
              'occurrence_crosswalk_gzip_sha256':R08_OCCURRENCE_CROSSWALK_GZIP_SHA}
    check(all(protected_profile.get(k)==v for k,v in expected.items()),
          'PROTECTED_V2_PROFILE_PINS_INVALID')
    check(sha(source_bytes)==SOURCE_SHA and sha(queue_bytes)==QUEUE_SHA,
          'ORIGINAL_SOURCE_OR_QUEUE_BYTES_CHANGED')
    require_frozen_crosswalk_bytes(r08_archive=r08_archive,
        record_crosswalk_gzip=record_crosswalk_gzip,
        occurrence_crosswalk_gzip=occurrence_crosswalk_gzip)
    check(isinstance(registry_bytes,bytes) and
          protected_profile.get('registry_v2_sha256')==sha(registry_bytes),
          'REGISTRY_UNPINNED_OR_STALE')
    check(protected_profile.get('ppges_bundle_sha256')==
          '8175f477e0d45c25db894fd00fb51cd3bd0ad78ea18b61aaa034a02f725a1371',
          'PPGES_ENGINE_PIN_MISSING')
    check(protected_profile.get('generator_sha256')==
          '646cf341c774953baa99da400ee3aa6e992fbbd8d0af95f36144f72c0fa5980c' and
          protected_profile.get('driver_sha256')==
          'b6ff959711cb3f3b9d103cb627bcc54e11de336b4ea2a4d862aa916ed2cb9191',
          'ORIGINAL_GENERATOR_DRIVER_PINS_INVALID')
    # The independent Broker must authenticate its code+trust policy; absence
    # does not silently turn off the semantic or Source Delta admission gate.
    check(isinstance(protected_profile.get('trust_policy_sha256'),str) and
          bool(HEX64.fullmatch(protected_profile['trust_policy_sha256'])),
          'TRUST_POLICY_UNPINNED')
    try:
        registry_document=json.loads(registry_bytes)
        registry=validate_registry_document(registry_document)
        records={}
        for raw in gzip.decompress(record_crosswalk_gzip).splitlines():
            rec=json.loads(raw);pub=rec['publication_block_id']
            check(pub not in records,'DUPLICATE_PUB_ID_IN_FROZEN_CROSSWALK')
            records[pub]=rec
        counts=Counter();seen=set();first_holds=[]
        for raw in gzip.decompress(occurrence_crosswalk_gzip).splitlines():
            occ=json.loads(raw)
            rec=records.get(occ.get('publication_block_id'))
            check(rec is not None,'R08_MISSING_SOURCE_RECORD')
            result=evaluate_occurrence(rec,occ,registry,pinned_ppges,
                receipt_verifier=qualified_verifier,
                policy_sha256=protected_profile['trust_policy_sha256'])
            stable=occ['stable_occurrence_key_sha256']
            check(stable not in seen,'DUPLICATE_OCCURRENCE_IN_FROZEN_CROSSWALK')
            seen.add(stable);counts[result['decision']]+=1
            if result['decision'] not in ('AB_VERIFIED_PPGES_KNOWN_LAB',
                                          'AB_WITH_SCOPED_EXTERNAL_ATTESTATION_LAB_ONLY') and len(first_holds)<8:
                first_holds.append(result['decision'])
    except (ValueError,TypeError,KeyError,UnicodeDecodeError) as exc:
        raise IdentityHold('REGISTRY_OR_CROSSWALK_DATA_INVALID') from None
    reject_unbound_registry_entries(registry,seen)
    # Role coverage (tables, captions, display titles) requires an independently
    # verified separate manifest; this R17R9 ENGSEQ queue alone does not prove it.
    coverage=protected_profile.get('independently_attested_role_coverage') is True
    holds=sum(n for k,n in counts.items() if k not in ('AB_VERIFIED_PPGES_KNOWN_LAB',
                                                       'AB_WITH_SCOPED_EXTERNAL_ATTESTATION_LAB_ONLY'))
    return {'status':'LAB_READY_FOR_SEPARATE_GOVERNANCE_CHECK' if holds==0 and coverage else 'DENIED',
            'held_occurrence_count':holds,'processed_frozen_crosswalk_occurrences':len(seen),
            'role_coverage_attested':coverage,'first_hold_reasons':first_holds,
            'producer_authorized':False,'one_time_claim_consumed':False}