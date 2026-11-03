"""Optional local credential vault: scrypt + AES-256-GCM via PyCryptodome.

The paper permits a separate password-protection layer. This example chooses
scrypt because PyCryptodome supplies it; it is NOT an Argon2id implementation.
Vault theft still permits offline password guessing. No file I/O is implicit.
"""

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

from .core import N, SUITE, _bytes, encode, export_public_key, public_key

MAGIC = b'GNZV\x01'
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
LENGTH = len(MAGIC) + 16 + 12 + 33 + 32 + 16


def _password(password: bytes) -> bytes:
    return _bytes(password, 1024, 'password', nonempty=True)


def _aad(header: bytes, owner: bytes) -> bytes:
    _bytes(owner, 256, 'vault owner', nonempty=True)
    return encode((1, b'GOST-NIZKP/vault/scrypt-AES256GCM/v1'),
                  (2, SUITE), (3, header), (4, owner))


def seal(secret: int, password: bytes, *, owner: bytes) -> bytes:
    """Encrypt an independently generated credential; do not derive d from PW."""
    q = export_public_key(public_key(secret))
    password = _password(password)
    salt, nonce = get_random_bytes(16), get_random_bytes(12)
    header = MAGIC + salt + nonce + q
    aad = _aad(header, owner)
    key = scrypt(password, salt, 32, N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(secret.to_bytes(32, 'big'))
    return header + ciphertext + tag


def unseal(blob: bytes, password: bytes, *, owner: bytes) -> int:
    """Authenticate the whole envelope before returning a secret scalar."""
    _bytes(blob, LENGTH, 'vault')
    if len(blob) != LENGTH or not blob.startswith(MAGIC):
        raise ValueError('Invalid vault format')
    password = _password(password)
    offset = len(MAGIC)
    salt, nonce = blob[offset:offset+16], blob[offset+16:offset+28]
    q = blob[offset+28:offset+61]
    header = blob[:offset+61]
    aad = _aad(header, owner)
    # The fixed version selects bounded KDF costs; untrusted blobs cannot
    # request arbitrary work or allocate attacker-chosen amounts of memory.
    key = scrypt(password, salt, 32, N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(aad)
    try:
        plaintext = cipher.decrypt_and_verify(blob[-48:-16], blob[-16:])
        secret = int.from_bytes(plaintext, 'big')
        if not 1 <= secret < N or export_public_key(public_key(secret)) != q:
            raise ValueError('Invalid key')
    except ValueError:
        raise ValueError('Vault authentication failed') from None
    return secret

