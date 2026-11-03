"""Run a local enrollment/authentication demonstration (not a TLS server)."""

from time import time
from Crypto.Random import get_random_bytes
from gost_nizkp import Context, generate_keypair, prove, export_public_key
from gost_nizkp.service import AuthenticationService, Request
from gost_nizkp.vault import seal, unseal


def main():
    account, verifier = b'citizen-demo-001', b'demo.gov.example'
    secret, q = generate_keypair()
    # This demonstration password is public and must not protect real keys.
    blob = seal(secret, b'demo password -- never use for real credentials', owner=account)
    unlocked = unseal(blob, b'demo password -- never use for real credentials', owner=account)
    server = AuthenticationService(verifier)
    # In a real service this call follows trusted identity verification.
    version = server.enroll_authorized(account, export_public_key(q))
    # Stand-in for the same trusted TLS exporter on both endpoints.
    # Random bytes alone DO NOT implement authenticated channel binding.
    binding = get_random_bytes(32)
    context = Context(account, verifier, version, int(time()), binding)
    proof = prove(unlocked, context.to_bytes())
    request = Request(account, version, context.timestamp, proof.to_bytes())
    print('Public key:', export_public_key(q).hex())
    print('Proof size:', len(proof.to_bytes()), 'bytes')
    print('First authentication:', server.authenticate(request, trusted_channel_binding=binding))
    print('Replay rejected:', not server.authenticate(request, trusted_channel_binding=binding))
    print('Other connection rejected:', not server.authenticate(
        request, trusted_channel_binding=get_random_bytes(32)))
    server.revoke_authorized(account)
    fresh = prove(unlocked, context.to_bytes())
    print('Revoked credential rejected:', not server.authenticate(
        Request(account, version, context.timestamp, fresh.to_bytes()),
        trusted_channel_binding=binding))


if __name__ == '__main__':
    main()
