"""Functional and adversarial regression tests; not a security proof."""

import json
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from Crypto.Util.number import inverse

from gost_nizkp import core as c
from gost_nizkp.service import AuthenticationService, Request
from gost_nizkp.vault import seal, unseal


class CoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = 0x123456789ABCDEF0123456789
        cls.q = c.public_key(cls.d)
        cls.ctx = c.Context(b'alice', b'service.example', 1, 1700000000, b'A'*32)
        cls.m = cls.ctx.to_bytes()

    def test_rfc5832_independent_arithmetic_vector(self):
        # RFC 5832 sections 7.1.6, 7.1.7 and 7.2; this checks curve arithmetic,
        # not compatibility of the NIZKP challenge with standard GOST signing.
        d = int('7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28', 16)
        q = (int('7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B', 16),
             int('26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA', 16))
        k = int('77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3', 16)
        e = int('2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5', 16)
        r = int('41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493', 16)
        s = int('1456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40', 16)
        self.assertEqual(c.public_key(d), q)
        self.assertEqual(c.multiply(k)[0], r)
        self.assertEqual((r*d+k*e) % c.N, s)

    def test_domain_and_group_boundaries(self):
        c.validate_domain()
        self.assertLess(c.P, c.N)
        self.assertIsNone(c.multiply(c.N))
        self.assertIsNone(c.multiply(0))
        self.assertEqual(c.multiply(c.N+1), c.G)
        self.assertIsNone(c.add(c.G, (c.G[0], -c.G[1] % c.P)))
        self.assertEqual(c.multiply(12), c.add(c.multiply(5), c.multiply(7)))

    def test_random_roundtrips(self):
        for _ in range(10):
            d, q = c.generate_keypair()
            proof = c.prove(d, self.m)
            self.assertTrue(c.verify(q, self.m, proof))
            self.assertEqual(c.import_public_key(c.export_public_key(q)), q)
            self.assertEqual(c.Proof.from_bytes(proof.to_bytes()), proof)

    def test_fresh_nonce(self):
        proofs = [c.prove(self.d, self.m).to_bytes() for _ in range(12)]
        self.assertEqual(len(set(proofs)), len(proofs))

    def test_each_context_field_is_bound(self):
        proof = c.prove(self.d, self.m)
        alternatives = [replace(self.ctx, account_id=b'bob'),
                        replace(self.ctx, verifier_id=b'evil.example'),
                        replace(self.ctx, credential_version=2),
                        replace(self.ctx, timestamp=self.ctx.timestamp+1),
                        replace(self.ctx, channel_binding=b'B'*32)]
        for ctx in alternatives:
            with self.subTest(ctx=ctx):
                self.assertFalse(c.verify(self.q, ctx.to_bytes(), proof))

    def test_key_and_response_tampering(self):
        proof = c.prove(self.d, self.m)
        self.assertFalse(c.verify(c.public_key(self.d+1), self.m, proof))
        self.assertFalse(c.verify(self.q, self.m, replace(proof, z=(proof.z+1) % c.N)))
        self.assertFalse(c.verify(self.q, self.m, replace(proof, r=(proof.r+1) % c.N)))

    def test_noncanonical_scalars(self):
        for r, z in [(0, 1), (c.N, 1), (-1, 1), (1, -1), (1, c.N), (True, 1), (1, False)]:
            with self.subTest(r=r, z=z):
                self.assertFalse(c.verify(self.q, self.m, c.Proof(r, z)))
                with self.assertRaises(ValueError):
                    c.Proof(r, z).to_bytes()
        for data in [b'', b'\0'*64, b'\1'*63, b'\1'*65, bytearray(64)]:
            with self.assertRaises(ValueError):
                c.Proof.from_bytes(data)

    def test_invalid_public_keys(self):
        proof = c.prove(self.d, self.m)
        for q in [None, (0, 0), (c.P, 1), (-1, 1), (True, 1), [1, 2]]:
            self.assertFalse(c.verify(q, self.m, proof))
        for data in [b'', b'\0'*33, b'\4'+b'\0'*32, b'\2'+c.P.to_bytes(32, 'big')]:
            with self.assertRaises(ValueError):
                c.import_public_key(data)

    def test_point_sign_encodings(self):
        positive = c.export_public_key(self.q)
        negative = bytes([positive[0] ^ 1]) + positive[1:]
        self.assertEqual(c.import_public_key(negative), (self.q[0], -self.q[1] % c.P))

    def test_identity_rejected_and_zero_response_permitted(self):
        # z=r*d produces W=zG-rP=O, so the verifier must reject it.
        self.assertFalse(c.verify(self.q, self.m, c.Proof(1, self.d)))
        # Force a nonzero oracle answer that makes z=0, only inside this test.
        # A fixed concrete hash cannot be programmed this way in deployment.
        k = 17
        r = c.multiply(k)[0]
        h = -r*self.d*int(inverse(k, c.N)) % c.N
        with patch.object(c, 'challenge', return_value=h):
            self.assertTrue(c.verify(self.q, self.m, c.Proof(r, 0)))
        self.assertEqual(c.Proof.from_bytes(c.Proof(r, 0).to_bytes()).z, 0)

    def test_rejection_sampling(self):
        chunks = [b'\0'*32, c.N.to_bytes(32, 'big'), (1).to_bytes(32, 'big')]
        with patch.object(c, 'get_random_bytes', side_effect=chunks):
            self.assertEqual(c._scalar(), 1)
        class HashResult:
            def __init__(self, value): self.value = value
            def digest(self): return self.value.to_bytes(32, 'big')
        with patch.object(c.SHA256, 'new', side_effect=[HashResult(0), HashResult(c.N), HashResult(7)]):
            self.assertEqual(c.challenge(self.m, 2, self.q), 7)

    def test_signed_extractor_both_branches(self):
        # Check the paper's extraction equation independently of prover API.
        k, h1, h2 = 23, 19, 31
        r = c.multiply(k)[0]
        for sign in (1, -1):
            z1 = (r*self.d+k*h1) % c.N
            z2 = (r*self.d+sign*k*h2) % c.N
            recovered = ((h1*z2-sign*h2*z1)
                         * int(inverse(r*(h1-sign*h2) % c.N, c.N))) % c.N
            self.assertEqual(recovered, self.d)

    def test_simulator_algebra(self):
        # This validates an algebraic identity, not zero-knowledge for SHA-256.
        u, v = 71, 29
        t = c.add(c.multiply(u), c.multiply(v, self.q))
        r = t[0]
        h = -r*int(inverse(v, c.N)) % c.N
        z = u*h % c.N
        with patch.object(c, 'challenge', return_value=h):
            self.assertTrue(c.verify(self.q, self.m, c.Proof(r, z)))

    def test_size_limits_and_unambiguous_encoding(self):
        self.assertNotEqual(c.encode((1, b'ab'), (2, b'c')), c.encode((1, b'a'), (2, b'bc')))
        msg = b'x'*c.MAX_MESSAGE
        self.assertTrue(c.verify(self.q, msg, c.prove(self.d, msg)))
        with self.assertRaises(ValueError): c.prove(self.d, msg+b'x')
        with self.assertRaises(ValueError): replace(self.ctx, timestamp=-1).to_bytes()
        with self.assertRaises(ValueError): replace(self.ctx, account_id=b'x'*257).to_bytes()
        with self.assertRaises(ValueError): replace(self.ctx, channel_binding=b'').to_bytes()

    def test_frozen_protocol_vector(self):
        v = json.loads((Path(__file__).parent / 'vector.json').read_text())
        d, k = int(v['secret_hex'], 16), int(v['nonce_hex'], 16)
        q = c.public_key(d)
        m = bytes.fromhex(v['message_hex'])
        with patch.object(c, 'get_random_bytes', return_value=k.to_bytes(32, 'big')):
            proof = c.prove(d, m)
        self.assertEqual(c.export_public_key(q).hex(), v['public_key_hex'])
        self.assertEqual(proof.to_bytes().hex(), v['proof_hex'])
        self.assertEqual(c.challenge(m, proof.r, q), int(v['challenge_hex'], 16))
        self.assertTrue(c.verify(q, m, proof))


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.now = 1700000000
        self.d, self.q = c.generate_keypair()
        self.server = AuthenticationService(b'service', clock=lambda: self.now)
        self.server.enroll_authorized(b'alice', c.export_public_key(self.q))
        self.binding = b'A'*32

    def request(self, **kwargs):
        ctx = c.Context(b'alice', b'service', 1, self.now, self.binding)
        ctx = replace(ctx, **kwargs)
        return Request(ctx.account_id, ctx.credential_version, ctx.timestamp,
                       c.prove(self.d, ctx.to_bytes()).to_bytes())

    def accept(self, request):
        return self.server.authenticate(request, trusted_channel_binding=self.binding)

    def test_replay_and_connection_binding(self):
        req = self.request()
        self.assertFalse(self.server.authenticate(req, trusted_channel_binding=b'B'*32))
        self.assertTrue(self.accept(req))
        self.assertFalse(self.accept(req))

    def test_concurrent_duplicates_accept_exactly_once(self):
        req = self.request()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.accept(req), range(16)))
        self.assertEqual(sum(results), 1)

    def test_timestamp_boundaries(self):
        for delta, expected in [(-61, False), (-60, True), (5, True), (6, False)]:
            self.assertEqual(self.accept(self.request(timestamp=self.now+delta)), expected)

    def test_revocation_and_rotation(self):
        old = self.request()
        self.server.revoke_authorized(b'alice')
        self.assertFalse(self.accept(old))
        new_d, new_q = c.generate_keypair()
        version = self.server.rotate_authorized(b'alice', c.export_public_key(new_q))
        self.assertEqual(version, 2)
        self.assertFalse(self.accept(old))
        ctx = c.Context(b'alice', b'service', version, self.now, self.binding)
        req = Request(b'alice', version, self.now, c.prove(new_d, ctx.to_bytes()).to_bytes())
        self.assertTrue(self.accept(req))

    def test_invalid_requests_do_not_poison_replay_store(self):
        req = self.request()
        self.assertFalse(self.accept(replace(req, proof_bytes=b'\0'*64)))
        self.assertTrue(self.accept(req))

    def test_wrong_account_and_version(self):
        self.assertFalse(self.accept(self.request(account_id=b'unknown')))
        self.assertFalse(self.accept(self.request(credential_version=2)))
        with self.assertRaises(ValueError):
            self.server.enroll_authorized(b'alice', c.export_public_key(self.q))

    def test_capacity_fails_closed_and_expiry_releases_space(self):
        self.server.capacity = 1
        req1, req2 = self.request(), self.request()
        self.assertTrue(self.accept(req1))
        self.assertFalse(self.accept(req2))
        self.assertFalse(self.accept(req1))
        self.now += 63
        self.assertTrue(self.accept(self.request()))
        self.assertFalse(self.accept(req1))

    def test_clock_rollback_fails_closed(self):
        req = self.request()
        self.assertTrue(self.accept(req))
        self.now += 100
        self.assertTrue(self.accept(self.request()))
        self.now -= 100
        self.assertFalse(self.accept(req))


class VaultTests(unittest.TestCase):
    def test_roundtrip_and_randomization(self):
        d, _ = c.generate_keypair()
        a = seal(d, b'test password', owner=b'alice')
        b = seal(d, b'test password', owner=b'alice')
        self.assertNotEqual(a, b)
        self.assertEqual(unseal(a, b'test password', owner=b'alice'), d)

    def test_wrong_password_owner_and_tampering(self):
        d, _ = c.generate_keypair()
        blob = seal(d, b'password', owner=b'alice')
        for password, owner in [(b'wrong', b'alice'), (b'password', b'bob')]:
            with self.assertRaises(ValueError): unseal(blob, password, owner=owner)
        for offset in [0, 5, 21, 33, len(blob)-17, len(blob)-1]:
            tampered = bytearray(blob)
            tampered[offset] ^= 1
            with self.assertRaises(ValueError):
                unseal(bytes(tampered), b'password', owner=b'alice')
        with self.assertRaises(ValueError): unseal(blob+b'\0', b'password', owner=b'alice')


if __name__ == '__main__':
    unittest.main()
