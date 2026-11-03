"""Single-process authentication example with atomic replay rejection.

Transport authentication and enrollment authorization are external trust
boundaries. Use a durable, shared transactional store for a real service.
"""

from dataclasses import dataclass
from threading import RLock
from time import time
from typing import Callable

from Crypto.Hash import SHA256

from .core import Context, Proof, MAX_ID, _bytes, encode, import_public_key, verify


@dataclass(frozen=True)
class Request:
    """Untrusted request fields; the channel binding is intentionally absent."""
    account_id: bytes
    credential_version: int
    timestamp: int
    proof_bytes: bytes


@dataclass(frozen=True)
class Credential:
    public_key: tuple[int, int]
    version: int
    active: bool = True


class AuthenticationService:
    def __init__(self, verifier_id: bytes, *, past_skew: int = 60,
                 future_skew: int = 5, replay_capacity: int = 10000,
                 clock: Callable[[], float] = time):
        _bytes(verifier_id, MAX_ID, 'verifier identifier', nonempty=True)
        if any(type(x) is not int or x < 0 for x in (past_skew, future_skew)):
            raise ValueError('Invalid freshness window')
        if type(replay_capacity) is not int or replay_capacity < 1:
            raise ValueError('Invalid replay capacity')
        self.verifier_id = verifier_id
        self.past_skew = past_skew
        self.future_skew = future_skew
        self.capacity = replay_capacity
        self._clock = clock
        self._last_time = -1
        self._credentials: dict[bytes, Credential] = {}
        self._replays: dict[bytes, int] = {}
        self._lock = RLock()

    def enroll_authorized(self, account_id: bytes, encoded_key: bytes) -> int:
        """Call only AFTER an external trusted identity/enrollment procedure.

        This is an administrator-side method, not an unauthenticated endpoint.
        Re-enrollment cannot silently replace an existing account's key.
        """
        _bytes(account_id, MAX_ID, 'account identifier', nonempty=True)
        q = import_public_key(encoded_key)
        with self._lock:
            if account_id in self._credentials:
                raise ValueError('Account already enrolled; use authorized rotation')
            self._credentials[account_id] = Credential(q, 1)
        return 1

    def rotate_authorized(self, account_id: bytes, encoded_key: bytes) -> int:
        """Replace a credential only after external authorization/recovery."""
        _bytes(account_id, MAX_ID, 'account identifier', nonempty=True)
        q = import_public_key(encoded_key)
        with self._lock:
            old = self._credentials[account_id]
            version = old.version + 1
            if version >= 2**64:
                raise ValueError('Credential version exhausted')
            self._credentials[account_id] = Credential(q, version)
            return version

    def revoke_authorized(self, account_id: bytes) -> None:
        """Revoke a credential only after external authorization."""
        with self._lock:
            old = self._credentials[account_id]
            self._credentials[account_id] = Credential(old.public_key, old.version, False)

    def authenticate(self, request: Request, *, trusted_channel_binding: bytes) -> bool:
        """Check a request against the receiving authenticated connection.

        The transport adapter must derive trusted_channel_binding LOCALLY,
        e.g. RFC 9266 tls-exporter for this TLS 1.3 connection. Never pass a
        value supplied in a client request. Do not accept TLS early data.
        A True result authorizes only this connection, not other sessions.
        """
        if type(request) is not Request:
            return False
        try:
            # Bounds and canonical parsing precede expensive curve operations.
            context = Context(request.account_id, self.verifier_id,
                              request.credential_version, request.timestamp,
                              trusted_channel_binding)
            message = context.to_bytes()
            proof = Proof.from_bytes(request.proof_bytes)
        except (ValueError, TypeError, OverflowError):
            return False

        # One lock serializes status checks, proof verification and acceptance.
        # This is intentionally simple, not a high-throughput architecture.
        with self._lock:
            now = int(self._clock())
            if now < self._last_time:
                # Fail closed on a clock rollback; otherwise expired replay
                # entries could become acceptable again after eviction.
                return False
            self._last_time = now
            credential = self._credentials.get(request.account_id)
            if (credential is None or not credential.active
                    or credential.version != request.credential_version):
                return False
            if not now-self.past_skew <= request.timestamp <= now+self.future_skew:
                return False
            replay_id = SHA256.new(encode((1, b'GOST-NIZKP/replay/v1'),
                                         (2, message), (3, request.proof_bytes))).digest()
            # Expiry is inclusive; retain entries beyond their last valid second.
            self._replays = {key: expiry for key, expiry in self._replays.items()
                             if expiry >= now}
            if replay_id in self._replays:
                return False
            if not verify(credential.public_key, message, proof):
                return False
            if len(self._replays) >= self.capacity:
                # Never evict a still-valid entry just to accept new traffic.
                return False
            self._replays[replay_id] = request.timestamp + self.past_skew + 2
            return True
