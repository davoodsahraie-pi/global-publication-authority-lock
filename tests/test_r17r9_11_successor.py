"""Targeted, read-only R17R9 11-delta successor CODE-ONLY tests.

Tests neither mutate source nor create a claim or Producer authorization.
The earlier completed GEN37/GEN34 execution and N2 evidence remain immutable.
"""
import copy
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
for folder in ("gate", "broker", "scripts"):
    sys.path.insert(0, str(ROOT / folder))
import transition_guard as guard
import publication_gate as gate
import gen34_r25r7_bridge as bridge
import ci_validate_pr as ci

SOURCE_OLD = "360ee8a7db0cfead8576b68b768bfa9e0f4038fd9f2892102e801541abc272d5"
SOURCE_NEW = "fbbd4d43367545d14c988d60604ed4523fbe5311fbce7f02b65f7cb742782b40"
SCOPE = {
    "broker/gen34_r25r7_bridge.py", "gate/transition_guard.py",
    "gate/publication_gate.py", "scripts/ci_validate_pr.py",
    "tests/test_r17r9_11_successor.py", "request/ACTION_REQUEST.json"
}

class SuccessorCodeOnly(unittest.TestCase):
    def setUp(self):
        self.draft = copy.deepcopy(guard.R17R9_11_SUCCESSOR_DRAFT)
        self.lock = {
            "generation": 38, "execution_authorized_now": False,
            "current_action": {"mode": "READ_ONLY"},
            "gen34_r25r7_bridge": dict(guard.GEN34_PINS),
            "private_execution_state_sha256": ci.R17R9_11_CODE_PRIVATE,
        }

    def test_owner_run_exact(self):
        self.assertEqual(ci.R17R9_11_CODE_RUN, 41270302143)
        self.assertEqual(ci.R17R9_11_CODE_PATHS, SCOPE)

    def test_source_sha_and_counts(self):
        self.assertEqual(self.draft["source_original_sha256"], SOURCE_OLD)
        self.assertEqual(self.draft["source_successor_lab_sha256"], SOURCE_NEW)
        self.assertEqual(self.draft["record_count"], 21529)
        self.assertEqual(self.draft["unchanged_record_count"], 21518)
        self.assertEqual(len(self.draft["changed_publication_ids"]), 11)
        self.assertEqual(len(set(self.draft["changed_publication_ids"])), 11)

    def test_original_gen34_immutable(self):
        self.assertEqual(guard.GEN34_PINS["source_sha256"], SOURCE_OLD)
        self.assertNotEqual(guard.GEN34_PINS["source_sha256"], SOURCE_NEW)
        self.assertEqual(self.draft["generator_sha256"], guard.GEN34_PINS["generator_sha256"])
        self.assertEqual(self.draft["driver_sha256"], guard.GEN34_PINS["driver_sha256"])

    def test_precise_draft_is_never_admission(self):
        result = guard.audit_r17r9_11_successor_draft(self.draft)
        self.assertEqual(result["status"], "DRAFT_VALID_NOT_ADMITTED")
        self.assertFalse(result["source_admitted"])
        self.assertFalse(result["launch_allowed"])

    def test_bridge_preview_only(self):
        result = bridge.preview_r17r9_11_successor_code_only(self.lock, self.draft)
        self.assertEqual(result["status"], "DRAFT_VALID_NOT_ADMITTED")
        self.assertFalse(result["launch_allowed"])
        self.assertFalse(result["claim_allowed"])

    def test_old_attempt_not_replayed(self):
        self.assertEqual(self.draft["legacy_attempt_id"], "GEN34_R25R7_E2E_01")
        self.assertIsNone(self.draft["candidate_attempt_id"])
        self.assertIsNone(self.draft["bundle_sha256"])

    def test_forged_activation_denied(self):
        for field in ("enabled", "execution_authorized", "official_source_admitted",
                      "reserved_attempt_confirmed"):
            with self.subTest(field=field):
                altered = dict(self.draft, **{field: True})
                self.assertEqual(guard.audit_r17r9_11_successor_draft(altered)["status"], "DENY")

    def test_other_source_or_generator_denied(self):
        for key in ("source_successor_lab_sha256", "generator_sha256", "driver_sha256"):
            with self.subTest(key=key):
                altered = dict(self.draft, **{key: "0" * 64})
                self.assertEqual(guard.audit_r17r9_11_successor_draft(altered)["status"], "DENY")

    def test_attempt_and_bundle_forgery_denied(self):
        for key, val in (("candidate_attempt_id", "GEN34_R25R7_E2E_01"),
                         ("bundle_sha256", "f" * 64)):
            altered = dict(self.draft, **{key: val})
            self.assertEqual(guard.audit_r17r9_11_successor_draft(altered)["status"], "DENY")

    def test_extra_authorization_flag_denied(self):
        altered = dict(self.draft, editorial_approved=True)
        self.assertEqual(guard.audit_r17r9_11_successor_draft(altered)["status"], "DENY")

    def test_public_authority_must_be_readonly(self):
        for key, val in (("execution_authorized_now", True), ("current_action", {"mode": "MUTATING"})):
            altered = dict(self.lock, **{key: val})
            self.assertEqual(bridge.preview_r17r9_11_successor_code_only(altered, self.draft)["status"], "DENY")

    def test_profile_source_must_match_legacy(self):
        altered = copy.deepcopy(self.lock)
        altered["gen34_r25r7_bridge"]["source_sha256"] = SOURCE_NEW
        self.assertEqual(bridge.preview_r17r9_11_successor_code_only(altered, self.draft)["status"], "DENY")

    def test_exact_code_only_scope_negative(self):
        req = {"requested_action_id": ci.R17R9_11_CODE_ACTION,
               "target_scope_ids": sorted(SCOPE), "action_kind": "GOVERNANCE_UPGRADE",
               "mode": "READ_ONLY", "operations": ["GOVERNANCE_UPGRADE", "PATCH"],
               "authorization_run_id": ci.R17R9_11_CODE_RUN,
               "input_public_lock_sha256": ci.R17R9_11_CODE_PUBLIC,
               "input_private_state_sha256": ci.R17R9_11_CODE_PRIVATE}
        self.assertIn("R17R9_11_EXACT_SIX_PATHS_REQUIRED",
                      ci.validate_r17r9_11_code_only_scope(
                          sorted(SCOPE - {"request/ACTION_REQUEST.json"}),
                          req, self.lock, ROOT, ROOT))
        altered = dict(req, authorization_run_id=1)
        self.assertIn("R17R9_11_OWNER_RUN_MISMATCH",
                      ci.validate_r17r9_11_code_only_scope(sorted(SCOPE),
                                                            altered, self.lock, ROOT, ROOT))

if __name__ == "__main__":
    unittest.main()
