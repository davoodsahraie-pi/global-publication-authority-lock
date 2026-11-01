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


class RuntimeSuccessorNoExecution(unittest.TestCase):
    def test_exact_owner_run_and_scope(self):
        self.assertEqual(ci.R17R9_11_RUNTIME_RUN, 41279306481)
        self.assertEqual(len(ci.R17R9_11_RUNTIME_PATHS), 7)

    def test_new_source_manifest_and_driver_are_pinned(self):
        self.assertEqual(guard.R17R9_11_SOURCE_SHA256, SOURCE_NEW)
        self.assertEqual(guard.R17R9_11_MANIFEST_SHA256,
                         "4bf88aa6ab1632b9bde6757cdd6aac195542d33bfc1940d8ca52604d904ea980")
        self.assertEqual(guard.R17R9_11_OWNER_VOTE_ID, 6553602646)
        self.assertEqual(guard.GEN34_PINS["source_sha256"], SOURCE_OLD)

    def test_new_attempt_never_reuses_old_attempt(self):
        self.assertEqual(guard.R17R9_11_NEW_ATTEMPT,"R17R9_11_SOURCE_BOUND_E2E_01")
        self.assertNotEqual(guard.R17R9_11_NEW_ATTEMPT, "GEN34_R25R7_E2E_01")

    def test_no_public_activation_denies_without_private_access(self):
        with self.assertRaises(bridge.Denied):
            from unittest.mock import Mock,patch
            with patch.object(bridge,"ROOT",ROOT):
                bridge.execute_r17r9_11_successor(
                    Mock(),Mock(),{},"999999999",None,ROOT)

    def test_new_profile_none_denied(self):
        self.assertTrue(guard.r17r9_11_successor_activation_errors(None))

    def test_forged_enabled_profile_denied(self):
        p=dict(guard.R17R9_11_SUCCESSOR_DRAFT)
        p["enabled"]=True
        self.assertTrue(guard.r17r9_11_successor_activation_errors(p))

    def test_inactive_lab_private_bundle_does_not_equal_run_bundle(self):
        self.assertEqual(len(guard.R17R9_11_LAB_INPUT_SHA256),64)
        self.assertNotEqual(guard.R17R9_11_LAB_INPUT_SHA256,
                            guard.R17R9_11_SOURCE_SHA256)

    def test_seven_stage_plan_exact_25_parts(self):
        self.assertEqual(len(bridge.R17R9_11_BATCHES),7)
        self.assertEqual(bridge.R17R9_11_BATCHES[0][:2],(1,1))
        self.assertEqual(bridge.R17R9_11_BATCHES[-1][:2],(21,25))
        self.assertEqual(sum(s[2] for s in bridge.R17R9_11_BATCHES),21529)
        self.assertEqual(bridge.R17R9_11_BATCHES[-1][3],21529)
        self.assertTrue(all(a[1]+1==b[0] for a,b in zip(
            bridge.R17R9_11_BATCHES,bridge.R17R9_11_BATCHES[1:])))

    def test_missing_private_state_always_denied(self):
        result=gate.validate_r17r9_11_successor_admission({}, {}, {}, {}, "a"*64)
        self.assertEqual(result["status"],"DENY")
        self.assertFalse(result["launch_allowed"])

    def test_old_canonical_profile_rejected_as_successor(self):
        result=gate.validate_r17r9_11_successor_admission(
            {"r17r9_11_successor":dict(guard.GEN34_PINS)},
            {"next_action_contract":{}} ,{},{}, "a"*64)
        self.assertEqual(result["status"],"DENY")

    def test_no_legacy_success_path_change(self):
        import inspect
        s=inspect.getsource(bridge.execute)
        self.assertNotIn("r17r9_11",s)
        self.assertIn("GEN34_PROTECTED_ACTIVATION_REQUIRED",s)

    def test_single_claimed_seven_batch_runner_fail_closed(self):
        # No actual file or subprocess: expired deadline must deny before spawn.
        from unittest.mock import Mock
        with self.assertRaises(bridge.Denied):
            bridge.run_r17r9_11_seven_batches(
                "python",Mock(),ROOT,0,dict(guard.GEN34_PINS))

    def test_successor_not_selected_in_current(self):
        state=gate.load_json(ROOT/"authority/CURRENT.json")
        self.assertEqual(state.get("generation"),38)
        self.assertIsNone(state.get("r17r9_11_successor"))
        self.assertFalse(state["execution_authorized_now"])
