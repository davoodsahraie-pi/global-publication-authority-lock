"""Fail-closed role coverage evidence reader for frozen R17R9; no source scans."""
from __future__ import annotations
import hashlib
import json

SOURCE_SHA = "360ee8a7db0cfead8576b68b768bfa9e0f4038fd9f2892102e801541abc272d5"
ROLE_SCHEMA = "GLOBAL_PUBLICATION_R17R9_STAGE3_ROLE_EVIDENCE/1.0"


def check_role_coverage(raw: bytes, *, expected_sha256: str) -> dict:
    """Returns ready_for_admission=False until every source/render role is proven.

    This function is an evidence gate only, not a semantic classifier, reviewer
    verifier, or official final-qualification authority.
    """
    result={"ready_for_admission":False, "producer_authorized":False,
            "release_authorized":False,"reason_codes":[]}
    if not isinstance(expected_sha256,str) or len(expected_sha256)!=64 or hashlib.sha256(raw).hexdigest()!=expected_sha256:
        result["reason_codes"].append("ROLE_MANIFEST_BYTE_PIN_INVALID")
        return result
    try:
        obj=json.loads(raw)
        if obj.get("schema")!=ROLE_SCHEMA or obj.get("source_sha256")!=SOURCE_SHA:
            raise ValueError("ROLE_MANIFEST_SOURCE_INVALID")
        census=obj.get("census") or {}
        expected={"part_title_blocks":25,"table_structure_blocks":27,
                  "fixed_width_semantic_table_blocks":4,"total_blocks":56,
                  "raw_multiword_spans":363,"mixed_persian_table_spans":163,
                  "non_persian_context_spans":200}
        if any(census.get(k)!=v for k,v in expected.items()):
            raise ValueError("STRUCTURAL_CENSUS_MISMATCH")
        if (census["mixed_persian_table_spans"]+census["non_persian_context_spans"]
            !=census["raw_multiword_spans"]):
            raise ValueError("UNBALANCED_ROLE_SPANS")
        attest=obj.get("attestations") or {}
        needed=("part_titles", "tables", "captions", "rendered_output",
                "mixed_table_semantic_review")
        for key in needed:
            item=attest.get(key)
            if not isinstance(item,dict) or item.get("verified") is not True:
                result["reason_codes"].append("UNATTESTED_"+key.upper())
                continue
            if item.get("source_sha256")!=SOURCE_SHA or not isinstance(item.get("evidence_sha256"),str) or len(item["evidence_sha256"])!=64:
                result["reason_codes"].append("UNPINNED_"+key.upper())
        if attest.get("captions",{}).get("verified") is True and not attest["captions"].get("rendered_output_exhaustive"):
            result["reason_codes"].append("CAPTION_OUTPUT_NOT_EXHAUSTIVE")
    except (TypeError,ValueError,AttributeError,KeyError):
        result["reason_codes"].append("INVALID_ROLE_MANIFEST")
    # The status never authorizes a Producer; a protected independent source /
    # renderer trust verifier is required to promote any verified fields.
    result["ready_for_admission"] = not result["reason_codes"]
    return result
