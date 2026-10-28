"""Only synthetic, offline, no-write tests; no GitHub token or Producer."""
import copy
import hashlib
import hmac
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'gate'))
from broker import gen33_source_bound_broker as broker
from broker import gen33_receipt_verifier as receipt
from transition_guard import gen33_source_bound_fingerprint

DATA={key:(key+' synthetic payload').encode() for key in ('generator','driver','source','c1','ppges','dependencies')}
SHAS={key:hashlib.sha256(data).hexdigest() for key,data in DATA.items()}
AUTH={'public_sha256':'1'*64,'private_sha256':'2'*64,'authorization_run_id':'40743213897'}
PROFILE={'schema':broker.PROFILE_SCHEMA,'runtime_profile':broker.PROFILE,
         'generator_sha256':SHAS['generator'],'driver_sha256':SHAS['driver'],
         'canonical_source_sha256':SHAS['source'],'c1_sha256':SHAS['c1'],
         'ppges_sha256':SHAS['ppges'],'dependency_lock_sha256':SHAS['dependencies'],**AUTH}
RUN_SHA='a'*40
REF=broker.expected_claim_ref('GLOBAL','SAFE-METHOD','A01')
KEY=b'Z'*32
EXPECTED={'issuer':'trusted-broker-test','attempt_key_sha256':'3'*64,
          'dispatch_descriptor_sha256':'4'*64,'claim_ref':REF,'claim_commit_sha':RUN_SHA,
          'authorization_run_id':'40743213897'}

def synthetic_receipt(output=None):
    d={'schema':receipt.RECEIPT_SCHEMA,**EXPECTED,
       'terminal_result':'COMPLETED' if output else 'NOT_LAUNCHED',
       'output_sha256':output,'nonce':'synthetic-nonce-0001'}
    d['mac_sha256']=hmac.new(KEY,receipt.canonical(d),hashlib.sha256).hexdigest()
    return d

class Gen33BrokerCodeOnly(unittest.TestCase):
    def synthetic_preflight(self,p=None,b=None,a=None):
        # The authentic R25R7 hashes are immutable in production; synthetic
        # content substitutes only inside this isolated unit test process.
        with patch.object(broker,'GENERATOR_SHA',SHAS['generator']),patch.object(broker,'DRIVER_SHA',SHAS['driver']):
            return broker.preflight(p if p is not None else PROFILE,
                                    b if b is not None else DATA,
                                    a if a is not None else AUTH)
    def claim(self,status=201,response=None,ref=REF,sha=RUN_SHA,protected=True):
        if response is None: response={'ref':ref,'object':{'sha':sha,'type':'commit'}}
        return broker.classify_synthetic_claim(status,response,ref,sha,protected)
    def test_P01_valid_source_bound_preflight_not_launch(self):
        v=self.synthetic_preflight();self.assertEqual(v['status'],'CODE_ONLY_PREFLIGHT_PASS');self.assertFalse(v['launch_allowed'])
    def test_P02_synthetic_exact_claim_classified_but_no_launch_api(self):
        self.assertEqual(self.claim(),'SYNTHETIC_WIN_ONLY')
        with self.assertRaises(broker.NotActivated):broker.launch_producer()
    def test_P03_mock_authenticated_not_launched_receipt(self):
        v=receipt.verify_terminal_receipt(synthetic_receipt(),KEY,EXPECTED)
        self.assertTrue(v['authenticated']);self.assertFalse(v['launch_allowed'])
    def test_P04_fingerprint_deterministic(self):
        data={k:SHAS[t] for k,t in [('generator_sha256','generator'),('driver_sha256','driver'),('canonical_source_sha256','source'),('c1_sha256','c1'),('ppges_sha256','ppges'),('dependency_lock_sha256','dependencies')]}
        self.assertEqual(gen33_source_bound_fingerprint(data),gen33_source_bound_fingerprint(dict(reversed(list(data.items())))))
    def test_N01_wrong_generator_identity(self):
        x={**PROFILE,'generator_sha256':'a'*64};self.assertIn('ORIGINAL_GENERATOR_IDENTITY_MISMATCH',self.synthetic_preflight(p=x)['reasons'])
    def test_N02_wrong_driver_identity(self):
        x={**PROFILE,'driver_sha256':'a'*64};self.assertIn('ORIGINAL_DRIVER_IDENTITY_MISMATCH',self.synthetic_preflight(p=x)['reasons'])
    def test_N03_source_byte_tampering(self):
        x={**DATA,'source':b'evil'};self.assertIn('INPUT_BYTES_MISMATCH_SOURCE',self.synthetic_preflight(b=x)['reasons'])
    def test_N04_missing_c1_bytes(self):
        x={**DATA};del x['c1'];self.assertIn('INPUT_MISSING_OR_UNBOUND_C1',self.synthetic_preflight(b=x)['reasons'])
    def test_N05_stale_public_authority(self):
        x={**AUTH,'public_sha256':'b'*64};self.assertIn('AUTHORITY_MISMATCH_PUBLIC_SHA256',self.synthetic_preflight(a=x)['reasons'])
    def test_N06_stale_private_authority(self):
        x={**AUTH,'private_sha256':'b'*64};self.assertIn('AUTHORITY_MISMATCH_PRIVATE_SHA256',self.synthetic_preflight(a=x)['reasons'])
    def test_N07_wrong_authorization_run(self):
        x={**AUTH,'authorization_run_id':'99999'};self.assertIn('AUTHORITY_MISMATCH_AUTHORIZATION_RUN_ID',self.synthetic_preflight(a=x)['reasons'])
    def test_N08_engineering_wheel_proxy_forbidden(self):
        x={**PROFILE,'engineering_wheel_sha256':'c'*64};self.assertIn('ENGINEERING_WHEEL_PROXY_FORBIDDEN',self.synthetic_preflight(p=x)['reasons'])
    def test_N09_response_lost_after_claim(self):
        self.assertEqual(self.claim(status=0,response={}), 'UNKNOWN')
    def test_N10_replayed_claim_conflict(self):
        self.assertEqual(self.claim(status=422,response={}), 'DENY')
    def test_N11_wrong_git_ref(self):
        self.assertEqual(self.claim(response={'ref':REF+'extra','object':{'sha':RUN_SHA,'type':'commit'}}),'UNKNOWN')
    def test_N12_ruleset_not_verified(self):
        self.assertEqual(self.claim(protected=False),'DENY')
    def test_N13_wrong_git_commit_sha(self):
        self.assertEqual(self.claim(response={'ref':REF,'object':{'sha':'b'*40,'type':'commit'}}),'UNKNOWN')
    def test_N14_wrong_git_ref_namespace(self):
        self.assertEqual(self.claim(ref='refs/tags/gen32-sentinel-claim/abc'),'DENY')
    def test_N15_receipt_forged_mac(self):
        x=synthetic_receipt();x['mac_sha256']='a'*64
        self.assertIn('MAC_AUTHENTICATION_FAILED',receipt.verify_terminal_receipt(x,KEY,EXPECTED)['reasons'])
    def test_N16_receipt_binding_wrong_attempt(self):
        x=synthetic_receipt();x['attempt_key_sha256']='0'*64
        self.assertFalse(receipt.verify_terminal_receipt(x,KEY,EXPECTED)['authenticated'])
    def test_N17_receipt_replay(self):
        x=synthetic_receipt();self.assertIn('RECEIPT_REPLAY',receipt.verify_terminal_receipt(x,KEY,EXPECTED,seen_nonces={x['nonce']})['reasons'])
    def test_N18_missing_trusted_issuer_key(self):
        x=synthetic_receipt();self.assertIn('TRUSTED_ISSUER_KEY_UNAVAILABLE',receipt.verify_terminal_receipt(x,None,EXPECTED)['reasons'])

if __name__=='__main__':unittest.main()
