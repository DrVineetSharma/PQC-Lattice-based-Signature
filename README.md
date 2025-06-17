# PQC-Lattice-based-Signature
# Python code to generate a digital signature
import hashlib
import random

# Parameter setup for the toy scheme
n = 20              # dimension of lattice (size of vector s and z)
q = 2042           # prime modulus (small for toy example)
bound_s = 10        # secret key coefficients are sampled uniformly from [-bound_s, bound_s]
bound_y = 20       # random y coefficients from [-bound_y, bound_y]
bound_z = 30       # rejection bound for z's coefficients
c_range = 8        # challenge c will be an integer 0 <= c < c_range

def keygen():
    """Generate a public/secret key pair."""
    # Sample secret vector s with small entries
    s = [random.randint(-bound_s, bound_s) for _ in range(n)]
    # Sample random matrix A (n x n) with entries mod q
    A = [[random.randrange(q) for _ in range(n)] for _ in range(n)]
    # Compute t = A * s mod q  (matrix-vector multiplication)
    t = [(sum(A[i][j] * s[j] for j in range(n)) % q) for i in range(n)]
    # Public key is (A, t), secret key is s
    return {"A": A, "t": t}, {"s": s}

def hash_u_message(u, message):
    """Hash function H(u, message) -> small challenge c."""
    # Convert u (list of ints) and message (bytes) to a hash input deterministically
    u_bytes = b''.join(int(val % q).to_bytes(2, byteorder='little', signed=True) for val in u)
    # Combine u and message bytes
    data = u_bytes + message
    digest = hashlib.sha256(data).digest()
    # Use few bits of the digest to form a small integer challenge
    c_value = digest[0] % c_range  # take first byte modulo c_range
    return c_value

def sign(sk, message):
    """Sign the message using the secret key sk."""
    s = sk["s"]
    while True:
        # Sample random vector y with small entries
        y = [random.randint(-bound_y, bound_y) for _ in range(n)]
        # Compute u = A * y mod q
        A = pk["A"]
        u = [(sum(A[i][j] * y[j] for j in range(n)) % q) for i in range(n)]
        # Derive challenge c from hash of (u, message)
        c = hash_u_message(u, message)
        # Compute z = y + c * s (component-wise)
        z = [(y[i] + c * s[i]) for i in range(n)]
        # Check if z is within the acceptable bound
        if all(abs(z[i]) <= bound_z for i in range(n)):
            # If acceptable, output signature (z, c)
            return {"z": z, "c": c}

def verify(pk, message, signature):
    """Verify a signature (z, c) against the public key pk and message."""
    A = pk["A"]; t = pk["t"]
    z = signature["z"]; c = signature["c"]
    # Check z's size bound
    if not all(abs(z[i]) <= bound_z for i in range(n)):
        return False
    # Recompute u' = A * z - c * t mod q
    u_prime = []
    for i in range(n):
        # Compute A[i] dot z
        Az = sum(A[i][j] * z[j] for j in range(n)) % q
        # Subtract c * t[i]
        u_prime.append((Az - c * t[i]) % q)
    # Hash (u_prime, message) to get c'
    c_prime = hash_u_message(u_prime, message)
    # Signature is valid if c' equals c (and bounds were ok)
    return c_prime == c

# Example usage
pk, sk = keygen()
message = b"Quantum resistant document"
signature = sign(sk, message)

print("Public key (A matrix) size:", len(pk["A"]), "x", len(pk["A"][0]), "elements")
print("Secret key vector s:", sk["s"])
print("Generated signature:", signature)
print("Signature valid?", verify(pk, message, signature))
