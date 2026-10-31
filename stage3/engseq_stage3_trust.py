"""Review-only, fail-closed ENGSEQ external reviewer evidence verifier.

No protected caller currently installs this module.  The only live identities
remain the protected GEN38 authority and separately pinned private state.
Cryptographic trust depends on a separately approved, byte-pinned public-key
registry and policy, not self-declared reviewer fields or a mock callback.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import datetime, timezone

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
POLICY_SCHEMA = "GLOBAL_PUBLICATION_ENGSEQ_REVIEW_TRUST_POLICY/1.0"
ANCHOR_SCHEMA = "GLOBAL_PUBLICATION_ENGSEQ_REVIEW_TRUST_ANCHORS/1.0"
RECEIPT_SCHEMA = "GLOBAL_PUBLICATION_ENGSEQ_SCOPED_REVIEW_RECEIPT/1.0"
_ALLOWED_AB = frozenset({"A_CONTINUOUS_TECHNICAL_PHRASE", "B_PROPER_NAME_OR_TITLE"})


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(document: dict) -> bytes:
    return json.dumps(document, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def strict_json(raw: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    def reject_constant(_value):
        raise ValueError("NONCANONICAL_JSON_CONSTANT")
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=reject_constant)
    if not isinstance(value, dict) or canonical(value) + b"\n" != raw:
        raise ValueError("DOCUMENT_NOT_CANONICAL_JSON")
    return value


def utc(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("INVALID_UTC_TIMESTAMP")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError) as exc:
        raise ValueError("INVALID_UTC_TIMESTAMP") from exc
    if parsed.utcoffset().total_seconds() != 0:
        raise ValueError("INVALID_UTC_TIMESTAMP")
    return parsed


def decode_b64(value: str, size: int) -> bytes:
    if not isinstance(value, str):
        raise ValueError("SIGNATURE_OR_KEY_NOT_BASE64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("SIGNATURE_OR_KEY_NOT_BASE64") from exc
    if len(decoded) != size or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("SIGNATURE_OR_KEY_LENGTH_INVALID")
    return decoded


class ReviewOnlyTrustVerifier:
    """Validate Ed25519 signatures against independently pinned trust anchors.

    Construction *requires* expected hashes supplied by a protected loader;
    unpinned caller-supplied policy/anchors are not trustworthy. No helper here
    ever grants Claim, Producer, Source edits, renderer or publication rights.
    """
    __slots__ = ("_policy", "_anchors", "_policy_sha", "_anchor_sha")

    @classmethod
    def from_pinned_bytes(cls, *, policy_bytes: bytes, anchor_bytes: bytes,
                          expected_policy_sha256: str, expected_anchor_sha256: str):
        if (not isinstance(expected_policy_sha256, str)
            or not isinstance(expected_anchor_sha256, str)
            or not HEX64.fullmatch(expected_policy_sha256)
            or not HEX64.fullmatch(expected_anchor_sha256)):
            raise ValueError("PROTECTED_SHA_PINS_REQUIRED")
        if digest(policy_bytes) != expected_policy_sha256 or digest(anchor_bytes) != expected_anchor_sha256:
            raise ValueError("TRUST_SOURCE_BYTE_PIN_MISMATCH")
        policy, anchors = strict_json(policy_bytes), strict_json(anchor_bytes)
        if (policy.get("schema") != POLICY_SCHEMA or anchors.get("schema") != ANCHOR_SCHEMA
            or policy.get("algorithm") != "Ed25519"
            or policy.get("allow_self_signed_reviewers") is not False
            or policy.get("review_permission") != "SEMANTIC_ATTESTATION_ONLY"
            or anchors.get("registry_status") != "EXTERNAL_OWNER_PROVISIONED"):
            raise ValueError("TRUST_SCHEMA_OR_APPROVAL_STATUS_INVALID")
        if not isinstance(policy.get("revocation_max_age_seconds"), int) or not 0 < policy["revocation_max_age_seconds"] <= 86400:
            raise ValueError("REVOCATION_FRESHNESS_POLICY_INVALID")
        if not isinstance(anchors.get("reviewers"), list):
            raise ValueError("REVIEWER_REGISTRY_INVALID")
        if not isinstance(anchors.get("revocation_checked_at"), str):
            raise ValueError("REVOCATION_TIMESTAMP_ABSENT")
        utc(anchors["revocation_checked_at"])
        byid = {}
        for r in anchors["reviewers"]:
            if not isinstance(r, dict) or not isinstance(r.get("reviewer_id"), str):
                raise ValueError("REVIEWER_RECORD_INVALID")
            rid = r["reviewer_id"]
            if not rid or rid in byid:
                raise ValueError("REVIEWER_DUPLICATED")
            decode_b64(r.get("ed25519_public_key_b64"), 32)
            if r.get("credential_verified") is not True or r.get("independent") is not True:
                raise ValueError("REVIEWER_CREDENTIALS_NOT_VERIFIED")
            if r.get("revoked") is not False:
                raise ValueError("REVOKED_REVIEWER")
            if not isinstance(r.get("domains"), list) or not r["domains"]:
                raise ValueError("REVIEWER_DOMAIN_MISSING")
            if not isinstance(r.get("qualifications"), list) or not r["qualifications"]:
                raise ValueError("REVIEWER_QUALIFICATION_MISSING")
            if not isinstance(r.get("source_sha256_scopes"), list) or not all(
                    isinstance(x, str) and HEX64.fullmatch(x) for x in r["source_sha256_scopes"]):
                raise ValueError("REVIEWER_SOURCE_SCOPE_MISSING")
            if not isinstance(r.get("sense_id_scopes"), list) or not all(
                    isinstance(x, str) and x for x in r["sense_id_scopes"]):
                raise ValueError("REVIEWER_SENSE_SCOPE_MISSING")
            if not r["source_sha256_scopes"] or not r["sense_id_scopes"]:
                raise ValueError("REVIEWER_SCOPE_EMPTY")
            byid[rid] = r
        obj = object.__new__(cls)
        obj._policy, obj._anchors = policy, (anchors, byid)
        obj._policy_sha, obj._anchor_sha = expected_policy_sha256, expected_anchor_sha256
        return obj

    def verify(self, entry: dict, binding: dict) -> dict:
        """Return a scoped verified decision or HOLD. All inputs fail closed."""
        denied = {"authenticated": False, "producer_authorized": False,
                  "claim_authorized": False, "release_authorized": False}
        try:
            if not isinstance(entry, dict) or not isinstance(binding, dict):
                raise ValueError("MISSING_ENTRY_OR_BINDING")
            receipt = entry.get("signed_review_receipt")
            if not isinstance(receipt, dict):
                raise ValueError("NO_SIGNED_RECEIPT")
            claims, signature_b64 = receipt.get("claims"), receipt.get("signature_ed25519_b64")
            if not isinstance(claims, dict) or claims.get("schema") != RECEIPT_SCHEMA:
                raise ValueError("RECEIPT_SCHEMA_INVALID")
            reviewer_id = claims.get("reviewer_id")
            reviewer = self._anchors[1].get(reviewer_id)
            if not reviewer:
                raise ValueError("UNTRUSTED_REVIEWER")
            if self._policy_sha != claims.get("trust_policy_sha256"):
                raise ValueError("POLICY_SHA_MISMATCH")
            for key in ("stable_occurrence_key_sha256", "canonical_source_sha256",
                        "source_record_sha256", "effective_text_sha256",
                        "publication_block_id", "source_line", "canonical_block_id",
                        "publication_role", "sequence"):
                if claims.get(key) != binding.get(key) or key not in claims:
                    raise ValueError("SCOPED_BINDING_MISMATCH")
            for key in ("domain", "sense_id", "reason", "evidence_uri",
                        "evidence_sha256", "review_version", "class"):
                if not claims.get(key) or claims.get(key) != entry.get(key):
                    raise ValueError("REVIEW_EVIDENCE_MISMATCH")
            if (claims.get("class") not in _ALLOWED_AB
                or claims.get("domain") not in reviewer["domains"]
                or claims.get("qualification") not in reviewer["qualifications"]
                or claims.get("canonical_source_sha256") not in reviewer["source_sha256_scopes"]
                or claims.get("sense_id") not in reviewer["sense_id_scopes"]):
                raise ValueError("OUT_OF_SCOPE_OR_UNQUALIFIED")
            for k in ("stable_occurrence_key_sha256", "canonical_source_sha256", "evidence_sha256"):
                if not isinstance(claims.get(k), str) or not HEX64.fullmatch(claims[k]):
                    raise ValueError("HASH_MALFORMED")
            now = datetime.now(timezone.utc)
            revocation_time = utc(self._anchors[0]["revocation_checked_at"])
            age = (now - revocation_time).total_seconds()
            if not 0 <= age <= self._policy["revocation_max_age_seconds"]:
                raise ValueError("REVOCATION_SNAPSHOT_STALE")
            issued, expires = utc(claims.get("issued_at")), utc(claims.get("expires_at"))
            if (not issued <= now < expires or not issued <= revocation_time
                or (expires - issued).total_seconds() > self._policy["maximum_receipt_lifetime_seconds"]):
                raise ValueError("RECEIPT_TIME_INVALID")
            # The optional cryptography backend is an independently qualified,
            # pinned PROD dependency. Unavailable backend means HOLD, not pass.
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.exceptions import InvalidSignature
            public_key = Ed25519PublicKey.from_public_bytes(decode_b64(reviewer["ed25519_public_key_b64"], 32))
            try:
                public_key.verify(decode_b64(signature_b64, 64), canonical(claims))
            except InvalidSignature as exc:
                raise ValueError("INVALID_SIGNATURE") from exc
            return {"authenticated": True, "trust_policy_sha256": self._policy_sha,
                    "scope_occurrence_sha256": claims["stable_occurrence_key_sha256"],
                    "producer_authorized": False, "claim_authorized": False,
                    "release_authorized": False}
        except (ValueError, TypeError, KeyError, ImportError, AttributeError):
            return {**denied, "status": "HOLD_UNVERIFIED_REVIEW"}
