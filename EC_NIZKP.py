import hashlib
import time
import secrets
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point

# Domain parameters based on the paper's requirement (using SECP256k1 as a standard 256-bit curve)
G = SECP256k1.generator
n = SECP256k1.order

def H_hash(*args) -> int:
    """Cryptographic hash function H returning an integer modulo n"""
    data = "".join(str(arg) for arg in args).encode('utf-8')
    h_hex = hashlib.sha256(data).hexdigest()
    return int(h_hex, 16) % n

def mod_inverse(a: int, m: int) -> int:
    """Calculate the modular inverse of a modulo m"""
    return pow(a, -1, m)

class ProverA:
    def __init__(self, id_a: str, pw_a: str):
        self.id_a = id_a
        self.pw_a = pw_a
        # 1st Round: Compute secret dA and public PA
        self.d_a = H_hash(self.id_a, self.pw_a)
        self.P_a = self.d_a * G

    def get_registration_data(self):
        return self.id_a, self.P_a

    def generate_proof(self):
        # 2nd Round: Verification phase - Prover side
        ts_1 = int(time.time())
        nonce = secrets.randbelow(n - 2) + 1 # 1 < Nonce < n - 1
        
        # Calculate k, Q, and r
        k = H_hash(ts_1, self.pw_a, nonce)
        Q = k * G
        r = Q.x() % n
        
        # Calculate h and z
        h = H_hash(ts_1, r, self.P_a.x(), self.P_a.y())
        z = (r * self.d_a + k * h) % n
        
        return self.id_a, ts_1, r, z

class VerifierB:
    def __init__(self, allowed_time_diff=60):
        self.database = {}
        self.allowed_time_diff = allowed_time_diff

    def register(self, id_a: str, P_a: Point):
        # Store IDA and PA in database
        self.database[id_a] = P_a

    def verify(self, id_a: str, ts_1: int, r: int, z: int) -> bool:
        # Check IDA and timestamp
        if id_a not in self.database:
            return False
        
        current_time = int(time.time())
        if abs(current_time - ts_1) > self.allowed_time_diff:
            return False # Timestamp out of allowed range
            
        P_a = self.database[id_a]
        
        # Calculate h, v, s1, s2
        h = H_hash(ts_1, r, P_a.x(), P_a.y())
        if h == 0:
            h = 1
        v = mod_inverse(h, n)
        
        s1 = (z * v) % n
        s2 = (-r * v) % n
        
        # Calculate T and r'
        T = (s1 * G) + (s2 * P_a)
        r_prime = T.x() % n
        
        # Verification check
        return r_prime == r

# --- Example Usage ---
# Registration
prover = ProverA(id_a="citizen_123", pw_a="SecurePass2026")
verifier = VerifierB()
verifier.register(*prover.get_registration_data())

# Authentication
id_a, ts_1, r, z = prover.generate_proof()
is_valid = verifier.verify(id_a, ts_1, r, z)
print(f"[English] Authentication Result: {is_valid}")