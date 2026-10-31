"""Only Stage-3 affected-path negative/contract tests, not producer tests."""
import base64
import json
import hashlib
import sys
import unittest
from datetime import datetime,timezone,timedelta
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'stage3'))
import engseq_stage3_trust as trust
import engseq_stage3_roles as roles

def raw(name):return (ROOT/'stage3'/name).read_bytes()
def valid_doc(obj):return trust.canonical(obj)+b'\n'
def sha(data):return hashlib.sha256(data).hexdigest()

class Stage3Tests(unittest.TestCase):
    def profile(self):return json.loads(raw('staged_profile.json'))
    def test_policy_canonical_and_pin(self):
        p=self.profile()
        self.assertEqual(sha(raw('trust_policy.json')),p['trust_policy_sha256'])
        self.assertEqual(trust.strict_json(raw('trust_policy.json'))['schema'],trust.POLICY_SCHEMA)
    def test_anchor_is_empty_unapproved(self):
        d=trust.strict_json(raw('trust_anchors.json'))
        self.assertEqual(d['reviewers'],[])
        self.assertEqual(d['registry_status'],'NOT_PROVISIONED')
    def test_default_anchor_does_not_load(self):
        p=self.profile()
        with self.assertRaisesRegex(ValueError,'TRUST_SCHEMA_OR_APPROVAL_STATUS_INVALID'):
            trust.ReviewOnlyTrustVerifier.from_pinned_bytes(policy_bytes=raw('trust_policy.json'),anchor_bytes=raw('trust_anchors.json'),expected_policy_sha256=p['trust_policy_sha256'],expected_anchor_sha256=p['trust_anchors_sha256'])
    def test_unpinned_policy_fails(self):
        p=self.profile()
        with self.assertRaisesRegex(ValueError,'TRUST_SOURCE_BYTE_PIN_MISMATCH'):
            trust.ReviewOnlyTrustVerifier.from_pinned_bytes(policy_bytes=raw('trust_policy.json')+b' ',anchor_bytes=raw('trust_anchors.json'),expected_policy_sha256=p['trust_policy_sha256'],expected_anchor_sha256=p['trust_anchors_sha256'])
    def test_explicit_hashes_required(self):
        with self.assertRaisesRegex(ValueError,'PROTECTED_SHA_PINS_REQUIRED'):
            trust.ReviewOnlyTrustVerifier.from_pinned_bytes(policy_bytes=b'{}',anchor_bytes=b'{}',expected_policy_sha256='',expected_anchor_sha256='f'*64)
    def test_double_json_key_rejected(self):
        with self.assertRaisesRegex(ValueError,'DUPLICATE_JSON_KEY'):
            trust.strict_json(b'{"a":1,"a":2}')
    def test_noncanonical_json_rejected(self):
        with self.assertRaisesRegex(ValueError,'DOCUMENT_NOT_CANONICAL_JSON'):
            trust.strict_json(b'{ "a":1 }')
    def test_bad_utc_denied(self):
        for s in ('2026-10-31T00:00:00+03:30','2026-10-31', 'not-time'):
            with self.subTest(s=s),self.assertRaises(ValueError): trust.utc(s)
    def test_b64_length_and_noncannon(self):
        for s in ('_',base64.b64encode(b'A').decode(),123):
            with self.subTest(s=s),self.assertRaises(ValueError):trust.decode_b64(s,32)
    def test_role_manifest_pin(self):
        p=self.profile(); self.assertEqual(sha(raw('role_evidence.json')),p['role_evidence_sha256'])
    def test_role_census_present_and_not_release(self):
        p=self.profile()
        r=roles.check_role_coverage(raw('role_evidence.json'),expected_sha256=p['role_evidence_sha256'])
        self.assertFalse(r['ready_for_admission'])
        self.assertFalse(r['producer_authorized'])
        self.assertIn('UNATTESTED_CAPTIONS',r['reason_codes'])
        self.assertIn('UNATTESTED_MIXED_TABLE_SEMANTIC_REVIEW',r['reason_codes'])
    def test_bad_role_pin_denied(self):
        r=roles.check_role_coverage(raw('role_evidence.json'),expected_sha256='0'*64)
        self.assertEqual(r['reason_codes'],['ROLE_MANIFEST_BYTE_PIN_INVALID'])
    def test_role_count_tampering_denied(self):
        d=json.loads(raw('role_evidence.json'));d['census']['part_title_blocks']+=1
        r=roles.check_role_coverage(valid_doc(d),expected_sha256=sha(valid_doc(d)))
        self.assertEqual(r['reason_codes'],['INVALID_ROLE_MANIFEST'])
    def test_profile_never_authorizes(self):
        p=self.profile()
        for k in ('claim_allowed','producer_allowed','release_allowed','trust_anchors_qualified','role_coverage_attested','new_broker_runtime_pin_activated'):
            self.assertIs(p[k],False,k)
    def test_broker_code_runtime_mismatch_preserved(self):
        p=self.profile()
        self.assertNotEqual(p['installed_legacy_broker_sha256'],p['historic_legacy_broker_runtime_pin_sha256'])
    def test_staged_code_sha_refs(self):
        p=self.profile()
        for name in ('engseq_stage3_trust.py','engseq_stage3_roles.py'):
            self.assertEqual(sha(raw(name)),p[name+'_sha256'])
    def test_reference_pins(self):
        p=self.profile()
        self.assertEqual(p['canonical_record_count'],21529)
        self.assertEqual(p['engseq_occurrences'],13589)
        self.assertEqual(p['source_sha256'],roles.SOURCE_SHA)
        self.assertEqual(p['ppges_bundle_sha256'],'8175f477e0d45c25db894fd00fb51cd3bd0ad78ea18b61aaa034a02f725a1371')

    def setUp(self):
        self.crypto_available=True
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError:
            self.crypto_available=False

    def synthetic_positive_fixture(self, *,anchor_age=timedelta(minutes=2), revoke=False, allowed_domain='software'):
        if not self.crypto_available:
            self.skipTest('No qualified crypto library installed: signature-positive fixture unverified')
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        key=Ed25519PrivateKey.generate()
        pub=key.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)
        policy=raw('trust_policy.json');now=datetime.now(timezone.utc)
        rev=(now-anchor_age).isoformat(timespec='seconds').replace('+00:00','Z')
        anchors={'schema':trust.ANCHOR_SCHEMA,'registry_status':'EXTERNAL_OWNER_PROVISIONED','revocation_checked_at':rev,
                 'reviewers':[{'reviewer_id':'synthetic-test-key','ed25519_public_key_b64':base64.b64encode(pub).decode(),
                               'credential_verified':True,'independent':True,'revoked':revoke,'domains':[allowed_domain],'qualifications':['scientific']}]}
        b={'stable_occurrence_key_sha256':'a'*64,'canonical_source_sha256':roles.SOURCE_SHA,
           'source_record_sha256':'b'*64,'effective_text_sha256':'c'*64,
           'publication_block_id':21473,'canonical_block_id':21471,'source_line':21473,
           'publication_role':'PERSIAN_BODY','sequence':'runserver development server'}
        fields={'domain':'software','sense_id':'django-server','reason':'source-linked scientific evidence',
                'evidence_uri':'https://docs.djangoproject.com/en/6.0/ref/django-admin/',
                'evidence_sha256':'d'*64,'review_version':'R10','class':'A_CONTINUOUS_TECHNICAL_PHRASE'}
        issued=(now-timedelta(minutes=4)).isoformat(timespec='seconds').replace('+00:00','Z')
        expires=(now+timedelta(hours=1)).isoformat(timespec='seconds').replace('+00:00','Z')
        claims={'schema':trust.RECEIPT_SCHEMA,'reviewer_id':'synthetic-test-key',
                'trust_policy_sha256':sha(policy),'qualification':'scientific','issued_at':issued,'expires_at':expires,**b,**fields}
        signature=base64.b64encode(key.sign(trust.canonical(claims))).decode()
        entry={**fields,'signed_review_receipt':{'claims':claims,'signature_ed25519_b64':signature}}
        encoded=valid_doc(anchors)
        verifier=trust.ReviewOnlyTrustVerifier.from_pinned_bytes(policy_bytes=policy,anchor_bytes=encoded,
                              expected_policy_sha256=sha(policy),expected_anchor_sha256=sha(encoded))
        return verifier,entry,b

    def test_synthetic_ed25519_positive_only_review(self):
        verifier,entry,b=self.synthetic_positive_fixture()
        result=verifier.verify(entry,b)
        self.assertIs(result['authenticated'],True)
        self.assertIs(result['producer_authorized'],False)
        self.assertIs(result['release_authorized'],False)
        self.assertEqual(result['scope_occurrence_sha256'],b['stable_occurrence_key_sha256'])
    def test_tampered_signature_denied(self):
        verifier,entry,b=self.synthetic_positive_fixture()
        entry['signed_review_receipt']['signature_ed25519_b64']=base64.b64encode(bytes(64)).decode()
        self.assertFalse(verifier.verify(entry,b)['authenticated'])
    def test_cross_record_binding_denied(self):
        verifier,entry,b=self.synthetic_positive_fixture()
        b['canonical_block_id']+=1
        self.assertFalse(verifier.verify(entry,b)['authenticated'])
    def test_cross_domain_denied(self):
        verifier,entry,b=self.synthetic_positive_fixture(allowed_domain='electronics')
        self.assertFalse(verifier.verify(entry,b)['authenticated'])
    def test_expired_revocation_snapshot_denied(self):
        verifier,entry,b=self.synthetic_positive_fixture(anchor_age=timedelta(days=3))
        self.assertFalse(verifier.verify(entry,b)['authenticated'])
    def test_revoked_key_denied_at_load(self):
        with self.assertRaisesRegex(ValueError,'REVOKED_REVIEWER'):
            self.synthetic_positive_fixture(revoke=True)
    def test_signature_metadata_changed_denied(self):
        verifier,entry,b=self.synthetic_positive_fixture()
        entry['evidence_sha256']='e'*64
        self.assertFalse(verifier.verify(entry,b)['authenticated'])
    def test_verifier_does_not_trust_plain_approve(self):
        verifier,entry,b=self.synthetic_positive_fixture()
        del entry['signed_review_receipt']
        entry['editorial_vote']='APPROVE'
        self.assertFalse(verifier.verify(entry,b)['authenticated'])

if __name__=='__main__': unittest.main()
