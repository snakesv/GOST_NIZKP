"""Reference GOST-style NIZKP core from the revised manuscript.

Research implementation only: affine Python arithmetic is variable-time.
The RFC 5832 Section 7 parameters are test parameters, not a production suite.
This is not a GOST-standard signature implementation or a PAKE.
"""

from dataclasses import dataclass
from functools import lru_cache

from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.number import inverse, isPrime

P = int('8000000000000000000000000000000000000000000000000000000000000431', 16)
A = 7
B = int('5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E', 16)
N = int('8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3', 16)
G = (2, int('8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8', 16))
Point = tuple[int, int] | None
SIZE = 32
SUITE = b'GOST-NIZKP-RFC5832-TEST-SHA256-v1'
PROTOCOL = b'GOST-NIZKP-v1'
MAX_MESSAGE = 4096
MAX_ID = 256


def _bytes(value: bytes, limit: int, name: str, *, nonempty: bool = False) -> bytes:
    if type(value) is not bytes or len(value) > limit or (nonempty and not value):
        raise ValueError(f'Invalid {name}')
    return value


def u64(value: int) -> bytes:
    """Encode an unsigned 64-bit integer in network byte order."""
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError('Expected an unsigned 64-bit integer')
    return value.to_bytes(8, 'big')


def encode(*fields: tuple[int, bytes]) -> bytes:
    """Encode ordered fields as type:u8 || length:u32be || value.

    Callers define the field types and order. No Unicode normalization or
    implicit conversion is performed; identifiers are exact byte strings.
    """
    result = bytearray()
    for tag, value in fields:
        if type(tag) is not int or not 0 <= tag <= 255:
            raise ValueError('Invalid field type')
        _bytes(value, MAX_MESSAGE + 1024, 'field')
        result.extend(bytes([tag]) + len(value).to_bytes(4, 'big') + value)
    return bytes(result)


def on_curve(q: Point) -> bool:
    if q is None:
        return True
    if type(q) is not tuple or len(q) != 2:
        return False
    x, y = q
    return (type(x) is int and type(y) is int and 0 <= x < P and 0 <= y < P
            and (y*y - x*x*x - A*x - B) % P == 0)


def add(q: Point, r: Point) -> Point:
    """Add validated affine points; None denotes the identity.

    This low-level helper assumes its inputs have already been validated.
    """
    if q is None:
        return r
    if r is None:
        return q
    x1, y1 = q
    x2, y2 = r
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        slope = (3*x1*x1 + A) * int(inverse(2*y1, P)) % P
    else:
        slope = (y2-y1) * int(inverse((x2-x1) % P, P)) % P
    x3 = (slope*slope - x1 - x2) % P
    return x3, (slope*(x1-x3)-y1) % P


def multiply(k: int, q: Point = G) -> Point:
    """Multiply a validated point without reducing k modulo N.

    In particular, validation must compute the actual N*Q. Reducing k first
    would make the subgroup check vacuous. This routine is not constant-time.
    """
    if type(k) is not int or k < 0:
        raise ValueError('Invalid scalar')
    result = None
    while k:
        if k & 1:
            result = add(result, q)
        q = add(q, q)
        k >>= 1
    return result


@lru_cache(maxsize=1)
def validate_domain() -> None:
    """Sanity-check the fixed test domain, including the paper's p < n rule."""
    if not (P > 3 and P < N and N & 1 and isPrime(P) and isPrime(N)):
        raise ValueError('Invalid prime parameters')
    if (4*A**3 + 27*B**2) % P == 0 or not on_curve(G) or multiply(N, G) is not None:
        raise ValueError('Invalid curve or generator')


def validate_public_key(q: Point) -> None:
    validate_domain()
    if q is None or not on_curve(q) or multiply(N, q) is not None:
        raise ValueError('Invalid public key')


def _compressed(q: tuple[int, int]) -> bytes:
    return bytes([2 | (q[1] & 1)]) + q[0].to_bytes(SIZE, 'big')


def export_public_key(q: Point) -> bytes:
    validate_public_key(q)
    return _compressed(q)


def _sqrt(value: int) -> int:
    """Tonelli-Shanks for this odd prime; reject non-residues."""
    if value == 0:
        return 0
    if pow(value, (P-1)//2, P) != 1:
        raise ValueError('Compressed point has no square root')
    odd, power = P-1, 0
    while odd % 2 == 0:
        odd //= 2
        power += 1
    nonresidue = 2
    while pow(nonresidue, (P-1)//2, P) != P-1:
        nonresidue += 1
    c, root, t, m = pow(nonresidue, odd, P), pow(value, (odd+1)//2, P), pow(value, odd, P), power
    while t != 1:
        i, t2 = 0, t
        while t2 != 1 and i < m:
            t2 = t2*t2 % P
            i += 1
        if i == m:
            raise ValueError('Invalid square root input')
        b = pow(c, 1 << (m-i-1), P)
        root, t, c, m = root*b % P, t*b*b % P, b*b % P, i
    return root


def import_public_key(data: bytes) -> tuple[int, int]:
    """Accept exactly one canonical SEC1-style compressed test-suite point."""
    _bytes(data, 33, 'public key')
    if len(data) != 33 or data[0] not in (2, 3):
        raise ValueError('Expected a 33-byte compressed public key')
    x = int.from_bytes(data[1:], 'big')
    if x >= P:
        raise ValueError('Noncanonical x coordinate')
    y = _sqrt((x*x*x+A*x+B) % P)
    if (y & 1) != (data[0] & 1):
        y = (-y) % P
    q = (x, y)
    if _compressed(q) != data:
        raise ValueError('Noncanonical point encoding')
    validate_public_key(q)
    return q


def _scalar() -> int:
    """Use rejection sampling instead of biased reduction modulo N."""
    while True:
        k = int.from_bytes(get_random_bytes(SIZE), 'big')
        if 1 <= k < N:
            return k


def public_key(secret: int) -> tuple[int, int]:
    validate_domain()
    if type(secret) is not int or not 1 <= secret < N:
        raise ValueError('Invalid secret key')
    return multiply(secret)


def generate_keypair() -> tuple[int, tuple[int, int]]:
    """Generate a random secret independent of all passwords and identifiers."""
    validate_domain()
    secret = _scalar()
    return secret, public_key(secret)


@dataclass(frozen=True)
class Context:
    account_id: bytes
    verifier_id: bytes
    credential_version: int
    timestamp: int
    channel_binding: bytes

    def to_bytes(self) -> bytes:
        """Construct m from exact identifiers, Unix seconds and a 32-byte binding.

        The caller must obtain the binding from its authenticated connection.
        This class does not establish TLS or authenticate a remote server.
        """
        _bytes(self.account_id, MAX_ID, 'account identifier', nonempty=True)
        _bytes(self.verifier_id, MAX_ID, 'verifier identifier', nonempty=True)
        _bytes(self.channel_binding, 32, 'channel binding')
        if len(self.channel_binding) != 32:
            raise ValueError('The application profile requires a 32-byte binding')
        if type(self.credential_version) is not int or self.credential_version < 1:
            raise ValueError('Invalid credential version')
        return encode((1, PROTOCOL), (2, SUITE), (3, self.account_id),
                      (4, self.verifier_id), (5, u64(self.credential_version)),
                      (6, u64(self.timestamp)), (7, self.channel_binding))


@dataclass(frozen=True)
class Proof:
    r: int
    z: int

    def to_bytes(self) -> bytes:
        if type(self.r) is not int or not 1 <= self.r < N:
            raise ValueError('Invalid r')
        # Unlike standard GOST signatures, the manuscript permits z == 0.
        if type(self.z) is not int or not 0 <= self.z < N:
            raise ValueError('Invalid z')
        return self.r.to_bytes(SIZE, 'big') + self.z.to_bytes(SIZE, 'big')

    @classmethod
    def from_bytes(cls, data: bytes) -> 'Proof':
        _bytes(data, 64, 'proof')
        if len(data) != 64:
            raise ValueError('Expected a 64-byte proof')
        result = cls(int.from_bytes(data[:32], 'big'), int.from_bytes(data[32:], 'big'))
        result.to_bytes()
        return result


def challenge(message: bytes, r: int, q: tuple[int, int]) -> int:
    """Instantiate H with domain-separated SHA-256 and scalar rejection.

    SHA-256 is a concrete implementation choice, not a programmable oracle
    and not a GOST hash. The proof in the paper remains a ROM statement.
    Internal callers supply validated q and a canonical nonzero r.
    """
    _bytes(message, MAX_MESSAGE, 'message')
    payload = encode((1, b'GOST-NIZKP/challenge'), (2, message),
                     (3, r.to_bytes(SIZE, 'big')), (4, _compressed(q)))
    for counter in range(2**32):
        digest = SHA256.new(encode((1, b'GOST-NIZKP/hash-to-scalar/SHA256/v1'),
                                  (2, payload), (3, counter.to_bytes(4, 'big')))).digest()
        h = int.from_bytes(digest, 'big')
        if 1 <= h < N:
            return h
    raise RuntimeError('Hash-to-scalar counter exhausted')


def prove(secret: int, message: bytes) -> Proof:
    """Generate pi=(r,z) with a fresh random k on every call."""
    _bytes(message, MAX_MESSAGE, 'message')
    q = public_key(secret)
    while True:
        k = _scalar()
        commitment = multiply(k)
        r = commitment[0]  # p < n, so x mod n equals canonical x.
        if r:
            h = challenge(message, r, q)
            return Proof(r, (r*secret + k*h) % N)


def verify(q: Point, message: bytes, proof: Proof) -> bool:
    """Verify only the proof equation, without timestamp or replay policy."""
    try:
        _bytes(message, MAX_MESSAGE, 'message')
        if type(proof) is not Proof:
            return False
        proof.to_bytes()
        # Under p < n, values r >= p have no corresponding abscissa.
        if proof.r >= P:
            return False
        validate_public_key(q)
        h = challenge(message, proof.r, q)
        v = int(inverse(h, N))
        t = add(multiply(proof.z*v % N), multiply(-proof.r*v % N, q))
        return t is not None and t[0] == proof.r
    except (ValueError, TypeError, OverflowError):
        return False
