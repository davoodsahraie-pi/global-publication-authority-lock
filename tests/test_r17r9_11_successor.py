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



class ManifestCycleContractFix(unittest.TestCase):
    """Approval 41280688586: cycle-free digest binding, no execution."""
    def make_profile(self, digest="1"*64):
        legacy=guard.GEN34_PINS
        p={
            "schema":guard.R17R9_11_RUNTIME_SCHEMA,"enabled":True,
            "runtime_profile":"R17R9_11_UNMODIFIED_R25R7_DRIVER",
            "action_id":"R17R9_11_SOURCE_BOUND_FULLBOOK_BUILD_ONCE",
            "project":"GLOBAL","method_id":"R17R9_11_ORIGINAL_DRIVER_SUCCESSOR",
            "attempt_id":guard.R17R9_11_NEW_ATTEMPT,
            "executor_id":"GITHUB_ACTIONS_PROTECTED_MAIN",
            "operations":["BUILD","GENERATE_DOCX"],
            "target_scope_ids":["R17R9_11_APPROVED_FULLBOOK_SUCCESSOR_ONCE"],
            "max_seconds":3000,
            "private_repository":"davoodsahraie-pi/global-publication-authority",
            "environment":"gen34-r25r7-production",
            "source_sha256":guard.R17R9_11_SOURCE_SHA256,
            "manifest_sha256":digest,
            "generator_sha256":guard.R17R9_11_CLI_GENERATOR_SHA256,
            "driver_sha256":legacy["driver_sha256"],
            "c1_sha256":legacy["c1_sha256"],
            "grammar_sha256":legacy["grammar_sha256"],
            "ppges_sha256":legacy["ppges_sha256"],
            "dependency_lock_sha256":legacy["source_sha256"],
            "bundle_sha256":"2"*64,"bundle_blob_sha":"3"*40,
            "receipt_key_sha256":"4"*64,
            "runtime_code_sha256":"5"*64,
            "runtime_workflow_sha256":"6"*64,
            "source_admission_status":"FORMALLY_ADMITTED",
            "source_admission_receipt_sha256":"7"*64,
            "private_authority_mode":guard.R17R9_PRIVATE_AUTHORITY_MODE,
            "library_current_role":guard.R17R9_LIBRARY_ARCHIVE_ROLE,
            "owner_source_adoption_comment_id":6553602646,
        }
        self.assertEqual(set(p),guard.R17R9_11_RUNTIME_KEYS)
        return p

    def make_private(self,profile):
        return {"next_action_contract":{
            "id":profile["action_id"],"mode":"MUTATING",
            "source_sha256":profile["source_sha256"],
            "attempt_id":profile["attempt_id"],
            "method_id":profile["method_id"],
            "owner_source_adoption_comment_id":6553602646,
            "source_admission_status":"FORMALLY_ADMITTED",
            "build_authorized":True,
            "private_payload_delivery_allowed":True,
            "real_claim_authorized":True
        }}

    def test_real_executable_digest_structurally_valid_no_claim(self):
        p=self.make_profile()
        self.assertEqual(guard.r17r9_11_successor_activation_errors(p),[])
        self.assertNotEqual(p["manifest_sha256"],guard.R17R9_11_MANIFEST_SHA256)

    def test_multiple_future_digest_preimages_have_no_fixpoint_constraint(self):
        for digest in ("1"*64,"8"*64):
            with self.subTest(digest=digest):
                p=self.make_profile(digest)
                self.assertEqual(guard.r17r9_11_successor_activation_errors(p),[])

    def test_lab_old_private_manifest_fails_closed(self):
        p=self.make_profile(guard.R17R9_11_MANIFEST_SHA256)
        self.assertIn("R17R9_LAB_MANIFEST_IS_NOT_EXECUTABLE",
                      guard.r17r9_11_successor_activation_errors(p))

    def test_invalid_manifest_pin_fails_closed(self):
        for value in ("",None,"invalid-manifest", "a"*63, "g"*64):
            with self.subTest(value=value):
                p=self.make_profile(value)
                self.assertIn("R17R9_EXECUTABLE_MANIFEST_DIGEST_INVALID",
                              guard.r17r9_11_successor_activation_errors(p))

    def test_private_contract_never_embeds_manifest_digest(self):
        p=self.make_profile()
        private=self.make_private(p)
        self.assertNotIn("manifest_sha256",private["next_action_contract"])
        lock={"r17r9_11_successor":p,
              "execution_authorized_now":True,
              "current_action":{"id":p["action_id"],"mode":"MUTATING"},
              "private_execution_state_sha256":"9"*64,
              "attempt_ledger":[],"ledger_hashes":{}}
        request={"schema":gate.REQ_SCHEMA,"action_kind":"EXECUTE",
                 "mode":"MUTATING","user_explicit_authorization":True,
                 "requested_action_id":p["action_id"],
                 "input_public_lock_sha256":"0"*64,
                 "input_private_state_sha256":"9"*64,
                 "authorization_run_id":41280688586,
                 **{k:p[k] for k in ("project","method_id","attempt_id",
                                    "executor_id","operations","target_scope_ids")}}
        result=gate.validate_r17r9_11_successor_admission(
            lock,private,request,None,"0"*64)
        self.assertNotIn("R17R9_PRIVATE_SOURCE_BINDING_OR_ADMISSION_MISSING",
                         result["reasons"])
        # Authorization and protected reservation are still required.
        self.assertEqual(result["status"],"DENY")
        self.assertFalse(result["launch_allowed"])
        self.assertIn("R17R9_NEW_UNSPENT_RESERVATION_REQUIRED",
                      result["reasons"])

    def test_old_manifest_not_authorized_by_forged_private_contract(self):
        p=self.make_profile(guard.R17R9_11_MANIFEST_SHA256)
        private=self.make_private(p)
        result=gate.validate_r17r9_11_successor_admission(
            {"r17r9_11_successor":p},private,{},None,"0"*64)
        self.assertEqual(result["status"],"DENY")
        self.assertIn("R17R9_LAB_MANIFEST_IS_NOT_EXECUTABLE",result["reasons"])

    def test_legacy_gen34_still_pins_original_source(self):
        self.assertEqual(guard.GEN34_PINS["source_sha256"],SOURCE_OLD)
        self.assertEqual(guard.R17R9_11_SOURCE_SHA256,SOURCE_NEW)
        self.assertNotEqual(guard.GEN34_PINS["source_sha256"],SOURCE_NEW)

    def test_manifest_digest_remains_checked_in_existing_broker(self):
        import inspect
        body=inspect.getsource(bridge.prepare_payload)
        self.assertIn('profile["manifest_sha256"]',body)
        self.assertIn('MANIFEST_SHA_MISMATCH',body)
        self.assertIn('"private-state.json":private_sha',body)

    def test_no_executable_state_mutation_from_tests(self):
        lock=gate.load_json(ROOT/"authority/CURRENT.json")
        self.assertEqual(lock["generation"],38)
        self.assertFalse(lock["execution_authorized_now"])
        self.assertNotIn("r17r9_11_successor",lock)



class PrivateGitBlobSingleAuthorityCodeOnly(unittest.TestCase):
    def test_exact_owner_workflow_run(self):
        self.assertEqual(ci.R17R9_BLOB_AUTHORITY_OWNER_RUN, 41288491850)

    """Owner approved design review: no official activation or private payload release."""

    def active_shape(self):
        return ManifestCycleContractFix().make_profile()

    def test_only_immutable_private_git_blob_is_valid(self):
        p=self.active_shape()
        self.assertEqual(guard.r17r9_11_successor_activation_errors(p),[])
        self.assertEqual(p["private_authority_mode"],
                         "R17R9_PRIVATE_GITHUB_IMMUTABLE_BLOB/1.0")
        self.assertEqual(p["library_current_role"],
                         "ARCHIVE_ONLY_NOT_EXECUTION_AUTHORITY")

    def test_private_authority_mode_must_be_exact(self):
        for mode in ("LIBRARY_CURRENT","GITHUB_MAIN","LIVE_PRIVATE_BRANCH","",None):
            with self.subTest(mode=mode):
                p=self.active_shape();p["private_authority_mode"]=mode
                self.assertIn("R17R9_PRIVATE_GITHUB_BLOB_AUTHORITY_REQUIRED",
                    guard.r17r9_11_successor_activation_errors(p))

    def test_library_cannot_become_runtime_fallback(self):
        for role in ("EXECUTION_INPUT","PRIMARY","FALLBACK","",None):
            with self.subTest(role=role):
                p=self.active_shape();p["library_current_role"]=role
                self.assertIn("R17R9_LIBRARY_MUST_BE_ARCHIVE_ONLY",
                    guard.r17r9_11_successor_activation_errors(p))

    def test_missing_profile_field_fails_closed(self):
        for key in ("private_authority_mode","library_current_role"):
            with self.subTest(key=key):
                p=self.active_shape();del p[key]
                self.assertIn("R17R9_SUCCESSOR_EXACT_PROFILE_KEYS_REQUIRED",
                    guard.r17r9_11_successor_activation_errors(p))

    def test_no_live_library_read_in_successor_execution(self):
        import inspect
        source=inspect.getsource(bridge.execute_r17r9_11_successor)
        self.assertIn("blob_bytes(private_api",source)
        self.assertIn("R17R9_PRIVATE_AUTHORITY_NOT_BOUND",source)
        self.assertNotIn("files__",source)
        self.assertNotIn("library_current.json",source.lower())
        self.assertLess(source.find("R17R9_PRIVATE_AUTHORITY_NOT_BOUND"),
                        source.find("blob_bytes(private_api"))

    def test_git_blob_has_three_independent_pins(self):
        import inspect
        code=inspect.getsource(bridge.execute_r17r9_11_successor)
        self.assertIn('profile["bundle_blob_sha"]',code)
        self.assertIn('lock["private_execution_state_sha256"]',code)
        self.assertIn("prepare_payload(",code)
        payload_source=inspect.getsource(bridge.prepare_payload)
        self.assertIn('profile["bundle_sha256"]',payload_source)
        self.assertIn('profile["manifest_sha256"]',payload_source)
        self.assertIn('"private-state.json":private_sha',payload_source)

    def test_unactivated_gen38_denies_before_private_api(self):
        from unittest.mock import Mock
        private_api=Mock()
        with self.assertRaises(bridge.Denied):
            bridge.execute_r17r9_11_successor(Mock(),private_api,{},
                                               "41280688586",None,ROOT)
        private_api.assert_not_called()

    def test_legacy_path_has_no_new_authority_mode(self):
        import inspect
        code=inspect.getsource(bridge.execute)
        self.assertNotIn("R17R9_PRIVATE_AUTHORITY_NOT_BOUND",code)
        self.assertNotIn("library_current_role",code)

    def test_code_only_cannot_authorize_execution(self):
        state=gate.load_json(ROOT/"authority/CURRENT.json")
        self.assertEqual(state["generation"],38)
        self.assertFalse(state["execution_authorized_now"])
        self.assertNotIn("r17r9_11_successor",state)



class RuntimeManifestSourcePinRegression(unittest.TestCase):
    """Fail-closed proof for the surviving post-PR82 historical Manifest pin."""

    def test_new_executable_manifest_reaches_broker_source_pins(self):
        p = ManifestCycleContractFix().make_profile()
        self.assertEqual(guard.r17r9_11_successor_activation_errors(p), [])
        pins = bridge.r17r9_11_pins(p)
        self.assertEqual(pins["source_sha256"], SOURCE_NEW)
        self.assertEqual(pins["generator_sha256"], guard.R17R9_11_CLI_GENERATOR_SHA256)
        self.assertEqual(pins["driver_sha256"], guard.GEN34_PINS["driver_sha256"])

    def test_historical_lab_manifest_denied(self):
        p = ManifestCycleContractFix().make_profile()
        p["manifest_sha256"] = guard.R17R9_11_MANIFEST_SHA256
        with self.assertRaises(bridge.Denied):
            bridge.r17r9_11_pins(p)

    def test_malformed_manifest_digest_denied(self):
        for digest in (None, "", "a"*63, "G"*64, 34):
            with self.subTest(digest=digest):
                p = ManifestCycleContractFix().make_profile()
                p["manifest_sha256"] = digest
                with self.assertRaises(bridge.Denied):
                    bridge.r17r9_11_pins(p)

    def test_wrong_source_denied_even_with_fresh_manifest(self):
        for digest in (SOURCE_OLD, "0"*64):
            p = ManifestCycleContractFix().make_profile()
            p["source_sha256"] = digest
            with self.assertRaises(bridge.Denied):
                bridge.r17r9_11_pins(p)

    def test_existing_manifest_member_and_state_byte_checks_remain(self):
        import inspect
        body = inspect.getsource(bridge.prepare_payload)
        self.assertIn('profile["manifest_sha256"]', body)
        self.assertIn('"private-state.json":private_sha', body)
        self.assertIn("PAYLOAD_FILE_SHA_MISMATCH", body)


class CLIOptionGeneratorSuccessorCodeOnly(unittest.TestCase):
    """Run 41307551624: successor-only CLI atom fix, NEVER an execution grant."""
    def test_exact_sha_and_frozen_legacy(self):
        self.assertEqual(guard.R17R9_11_CLI_GENERATOR_SHA256, "2ee4fabe98066c78dc5be0017c0c84ab4885ab582ca0cf66fdd32005e91dd8e9")
        self.assertEqual(guard.GEN34_PINS["generator_sha256"], "646cf341c774953baa99da400ee3aa6e992fbbd8d0af95f36144f72c0fa5980c")
        self.assertNotEqual(guard.R17R9_11_CLI_GENERATOR_SHA256, guard.GEN34_PINS["generator_sha256"])

    def test_successor_pins_new_sha_but_not_legacy(self):
        p=ManifestCycleContractFix().make_profile()
        self.assertEqual(guard.r17r9_11_successor_activation_errors(p), [])
        pins=bridge.r17r9_11_pins(p)
        self.assertEqual(pins["generator_sha256"], guard.R17R9_11_CLI_GENERATOR_SHA256)
        self.assertEqual(pins["source_sha256"], guard.R17R9_11_SOURCE_SHA256)
        self.assertEqual(pins["driver_sha256"], guard.GEN34_PINS["driver_sha256"])
        self.assertEqual(guard.GEN34_PINS["generator_sha256"], "646cf341c774953baa99da400ee3aa6e992fbbd8d0af95f36144f72c0fa5980c")

    def test_old_or_forged_generator_fails_closed(self):
        for digest in (guard.GEN34_PINS["generator_sha256"], "0"*64, "", None):
            with self.subTest(generator_sha256=digest):
                p=ManifestCycleContractFix().make_profile()
                p["generator_sha256"]=digest
                self.assertIn("R17R9_PIN_INVALID:generator_sha256",
                              guard.r17r9_11_successor_activation_errors(p))
                with self.assertRaises(bridge.Denied):
                    bridge.r17r9_11_pins(p)

    def test_unverified_private_payload_still_denied(self):
        p=ManifestCycleContractFix().make_profile()
        self.assertEqual(guard.r17r9_11_successor_activation_errors(p), [])
        lock=gate.load_json(ROOT/"authority/CURRENT.json")
        self.assertEqual(lock["generation"], 38)
        self.assertFalse(lock["execution_authorized_now"])
        self.assertIsNone(lock.get("r17r9_11_successor"))
        self.assertEqual(gate.validate_r17r9_11_successor_admission(
            lock,{}, {},None, "e972e0293128c7d223079603ceaf62db9d0fe96afcc2844fa947af6dc2a562ab")["status"], "DENY")

    def test_private_manifest_still_bound_to_exact_generator(self):
        import inspect
        source=inspect.getsource(bridge.prepare_payload)
        self.assertIn('GENERATOR:pins["generator_sha256"]',source)
        stages=inspect.getsource(bridge.run_r17r9_11_seven_batches)
        self.assertIn('file_sha(payload/GENERATOR)==pins["generator_sha256"]',stages)
        self.assertIn("PAYLOAD_FILE_SHA_MISMATCH", source)
