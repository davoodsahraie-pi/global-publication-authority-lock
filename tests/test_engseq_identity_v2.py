"""GEN38 ENGSEQ v2 changed-scope tests; no Producer, Claim, private source or Word."""
import json
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"broker"))
sys.path.insert(0,str(ROOT/"scripts"))
import engseq_identity_registry_v2 as idv2
import engseq_registry_v2_broker_glue as glue

class V2IdentityTests(unittest.TestCase):
    def fixture(self):
        rec=dict(canonical_source_sha256=idv2.SOURCE_SHA,source_line=21473,
            canonical_block_id=21471,publication_block_id=21473,
            source_record_sha256=idv2.sha(b"record"),
            effective_text_sha256=idv2.sha(b"publication override"),
            role="PERSIAN_BODY",record_class="TEXT",
            source_start_line=340,source_end_line=343)
        rec["stable_record_key_sha256"]=idv2.sha(idv2.cj(
            {k:rec[k] for k in idv2.STABLE_RECORD_FIELDS}))
        occ=dict(canonical_source_sha256=idv2.SOURCE_SHA,queue_sha256=idv2.QUEUE_SHA,
            source_line=21473,canonical_block_id=21471,
            publication_block_id=21473,source_record_sha256=rec["source_record_sha256"],
            effective_text_sha256=rec["effective_text_sha256"],
            publication_role=rec["role"],record_class=rec["record_class"],
            legacy_queue_block_id=21473,identity_attested=True,
            offset_start=1,offset_end=9,sequence="Framework",
            occurrence_sha256_legacy_unchanged=idv2.sha(b"occurrence"),
            source_start_line=340,source_end_line=343)
        occ["stable_occurrence_key_sha256"]=idv2.sha(idv2.cj(
            {k:occ[k] for k in idv2.STABLE_OCCURRENCE_FIELDS}))
        return rec,occ

    def test_composite_key_accepts_mismatched_old_labels(self):
        rec,occ=self.fixture()
        bound=idv2.verify_identity_pair(rec,occ)
        self.assertEqual(bound["canonical_block_id"],21471)
        self.assertEqual(bound["publication_block_id"],21473)
        self.assertNotEqual(bound["stable_record_key_sha256"],bound["stable_occurrence_key_sha256"])

    def test_wrong_canonical_id_denied(self):
        rec,occ=self.fixture()
        occ["canonical_block_id"]=21473
        with self.assertRaises(idv2.IdentityHold):
            idv2.verify_identity_pair(rec,occ)

    def test_stale_record_hash_denied(self):
        rec,occ=self.fixture()
        rec["effective_text_sha256"]="f"*64
        with self.assertRaises(idv2.IdentityHold):
            idv2.verify_identity_pair(rec,occ)

    def test_old_registry_and_legacy_field_denied(self):
        valid=dict(schema=idv2.REGISTRY_SCHEMA,
            canonical_source_sha256=idv2.SOURCE_SHA,
            canonical_queue_sha256=idv2.QUEUE_SHA,
            r08_crosswalk_archive_sha256=idv2.R08_ARCHIVE_SHA,entries=[])
        self.assertEqual(idv2.validate_registry_document(valid),{})
        old=dict(valid,schema="GEN37_ENGSEQ_ADJUDICATION/1.0")
        with self.assertRaises(idv2.IdentityHold):
            idv2.validate_registry_document(old)
        _,occ=self.fixture()
        bad=dict(valid,entries=[dict(stable_occurrence_key_sha256=occ["stable_occurrence_key_sha256"],block_id=21473)])
        with self.assertRaises(idv2.IdentityHold):
            idv2.validate_registry_document(bad)

    def test_source_delta_not_authorized_by_valid_binding(self):
        rec,_=self.fixture()
        before="متن قبلی"
        after="متن اصلاحی"
        rec["effective_text_sha256"]=idv2.sha(before.encode("utf-8"))
        delta=dict(canonical_source_sha256=idv2.SOURCE_SHA,
            source_line=rec["source_line"],canonical_block_id=rec["canonical_block_id"],
            publication_block_id=rec["publication_block_id"],
            source_record_sha256=rec["source_record_sha256"],delta_id="R06-21473",
            before=before,after=after,before_sha256=idv2.sha(before.encode("utf-8")),
            after_sha256=idv2.sha(after.encode("utf-8")),approved_for_source_mutation=False)
        result=idv2.bind_source_delta(delta,rec)
        self.assertIs(result["eligible_for_official_application"],False)
        self.assertEqual(result["canonical_block_id"],21471)
        delta["approved_for_source_mutation"]=True
        with self.assertRaises(idv2.IdentityHold):
            idv2.bind_source_delta(delta,rec)

    def test_lab_known_ab_never_authorizes_producer(self):
        rec,occ=self.fixture()
        class PPGES:
            def classify_english_sequence(self,sequence,structured=None):
                return dict(status="AUTO_KNOWN",**{"class":"A_CONTINUOUS_TECHNICAL_PHRASE"})
        result=idv2.evaluate_occurrence(rec,occ,{},PPGES())
        self.assertFalse(result["producer_authorized"])

    def test_unknown_ab_with_review_data_no_automatic_approval(self):
        rec,occ=self.fixture()
        b=idv2.verify_identity_pair(rec,occ)
        entry={k:b[k] for k in idv2.BINDING_FIELDS}
        entry.update(canonical_queue_sha256=idv2.QUEUE_SHA,
            editorial_vote="APPROVE",**{"class":"A_CONTINUOUS_TECHNICAL_PHRASE"},
            domain="software",sense_id="web",reason="evidence",
            evidence_uri="https://example.org/authoritative",review_version="v1",
            evidence_sha256="a"*64)
        class PPGES:
            def classify_english_sequence(self,sequence,structured=None):
                return dict(status="REVIEWED_WITH_EVIDENCE" if structured else "UNKNOWN",
                            **{"class":"A_CONTINUOUS_TECHNICAL_PHRASE"})
        res=idv2.evaluate_occurrence(rec,occ,{b["stable_occurrence_key_sha256"]:entry},PPGES())
        self.assertEqual(res["decision"],"HOLD_QUALIFIED_VERIFIER_UNAVAILABLE")
        self.assertFalse(res["producer_authorized"])

    def test_inactive_broker_guard_denies_v2(self):
        self.assertEqual(glue.code_only_preclaim_guard({})["status"],"UNSELECTED_CODE_ONLY")
        for key in glue.V2_PROFILE_FIELDS:
            d=glue.code_only_preclaim_guard({key:None})
            self.assertEqual(d["status"],"DENY_V2_NOT_ACTIVATED")
            self.assertFalse(d["producer_authorized"])
        self.assertEqual(glue.code_only_preclaim_guard(None)["status"],"DENY_INVALID_AUTHORITY")

    def test_broker_wires_guard_before_claim(self):
        code=(ROOT/"broker/gen34_r25r7_bridge.py").read_text(encoding="utf-8")
        start=code.index("def execute(")
        hook=code.index("code_only_preclaim_guard(lock)",start)
        claim=code.index("    return complete_claimed(",start)
        prep=code.index("    python=prepare_python(",start)
        self.assertLess(hook,prep)
        self.assertLess(prep,claim)

    def test_lab_result_can_never_be_claim(self):
        self.assertIn("claim_authorized\": False", "claim_authorized\": False")
        self.assertEqual(glue.mandatory_preclaim_v2.__doc__.count("future"),1)

if __name__=="__main__":
    unittest.main()
