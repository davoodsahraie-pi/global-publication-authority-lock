#!/usr/bin/env python3
"""GEN33 protected-ref claim evidence, NON-PRODUCER / READ-ONLY PHASE 1.

This module performs no Git ref writes, no retries, no Producer imports/spawns,
and does not accept credentials for mutating GitHub. A verified Ruleset plus
a synthetic 201 response is NOT authorization to launch or create a real claim.
Physical claim creation requires a separately approved owner action/run.
"""
import json
import re

from gen33_source_bound_broker import (
    REAL_NAMESPACE, expected_claim_ref, classify_synthetic_claim
)

REPO = "davoodsahraie-pi/global-publication-authority-lock"
RULESET_PATTERN = REAL_NAMESPACE + "*"
RULE_TYPES = frozenset(("deletion", "update", "non_fast_forward"))
HEX40 = re.compile(r"^[0-9a-f]{40}$")
RULESET_UNKNOWN = "PROTECTION_NOT_ESTABLISHED"


def verify_ruleset(ruleset):
    """Evaluate *full Ruleset GET JSON*, not a claimed success flag."""
    if not isinstance(ruleset, dict):
        return (False, "RULESET_UNAVAILABLE")
    if ruleset.get("target") != "tag":
        return (False, "RULESET_TARGET_MISMATCH")
    if ruleset.get("enforcement") != "active":
        return (False, "RULESET_NOT_ACTIVE")
    if ruleset.get("bypass_actors") != []:
        return (False, "RULESET_BYPASS_PRESENT_OR_UNKNOWN")
    conditions = ruleset.get("conditions")
    if not isinstance(conditions, dict) or set(conditions) != {"ref_name"}:
        return (False, "RULESET_CONDITIONS_INVALID")
    refs = conditions.get("ref_name")
    if not isinstance(refs, dict) or refs.get("include") != [RULESET_PATTERN] or refs.get("exclude") != []:
        return (False, "RULESET_NAMESPACE_NOT_EXACT")
    rules = ruleset.get("rules")
    if not isinstance(rules, list):
        return (False, "RULESET_RULES_INVALID")
    kinds = [rule.get("type") for rule in rules if isinstance(rule, dict)]
    if len(kinds) != len(rules) or set(kinds) != RULE_TYPES or len(kinds) != 3:
        return (False, "RULESET_RULES_NOT_EXACT")
    return (True, "PROTECTION_SHAPE_PASS_READ_ONLY")


def classify_claim_http_result(status, response, ref, commit_sha, verified_ruleset):
    """Pure response classification. No HTTP POST and no retry."""
    if not isinstance(verified_ruleset, dict):
        return {"status": RULESET_UNKNOWN, "physical_claim_authorized": False,
                "producer_launch_authorized": False}
    ok, why = verify_ruleset(verified_ruleset)
    if not ok:
        return {"status": why, "physical_claim_authorized": False,
                "producer_launch_authorized": False}
    classification = classify_synthetic_claim(status, response, ref, commit_sha, True)
    return {"status": classification, "physical_claim_authorized": False,
            "producer_launch_authorized": False}


def simulated_competition(project, method, attempt, results, verified_ruleset):
    """Demonstrate at most one 201 in a supplied *synthetic* response sequence."""
    ref=expected_claim_ref(project,method,attempt)
    if not isinstance(results,list):
        raise ValueError("INVALID_SIMULATED_RESULTS")
    results_out=[]
    for item in results:
        if not isinstance(item,dict) or not HEX40.fullmatch(str(item.get("commit_sha",""))):
            raise ValueError("INVALID_SIMULATED_RESULT")
        result=classify_claim_http_result(item.get("http_status"),item.get("body"),
                                           ref,item["commit_sha"],verified_ruleset)
        results_out.append(result["status"])
    return {"ref":ref,"synthetic_results":results_out,
            "launch_allowed":False,"physical_claim_authorized":False,
            "observed_synthetic_wins":sum(v=="SYNTHETIC_WIN_ONLY" for v in results_out)}


def observe_claim_protection(ruleset_json):
    """Return only a non-operational inspection report."""
    okay,reason=verify_ruleset(ruleset_json)
    return {"schema":"GEN33_PROTECTED_CLAIM_OBSERVATION/1.0.0",
            "ruleset_shape_verified":okay,"reason":reason,
            "physical_claim_authorized":False,"producer_launch_authorized":False,
            "ruleset_exists_in_github":None}


def main():
    import argparse
    parser=argparse.ArgumentParser(description="GEN33 code-only, offline proof tool")
    parser.add_argument("--mode",choices=("offline","inspect-stdin"),default="offline")
    args=parser.parse_args()
    if args.mode=="offline":
        print(json.dumps(observe_claim_protection(None),sort_keys=True))
        return 0
    import sys
    try:
        data=json.load(sys.stdin)
    except (ValueError,TypeError):
        print(json.dumps(observe_claim_protection(None),sort_keys=True))
        return 2
    print(json.dumps(observe_claim_protection(data),sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
