"""
Table 4 Benchmark — Recreating Cryptographic Primitive Benchmarks from the Paper
Runs 1,000 iterations using Python's timeit to measure:
- h(SHA256)
- mac(HMAC-SHA-256)
- e(AES-CBC-256 Encryption)
- e(AES-CBC-256 Decryption)
- Point Multiplication (SECP256R1 / ECDH)

Paper Table 4 Reference for Raspberry Pi 3 B/B+:
- SHA256:             0.013 ms
- HMAC-SHA256:        1.572 ms
- AES-256 Enc:        0.0752 ms
- AES-256 Dec:        0.132 ms
- Point Multiplic.:   1.62 ms
"""

import timeit
import hashlib
import hmac
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac

ITERATIONS = 1000

print("=" * 65)
print("  EAP-IMP CRYPTOGRAPHIC BENCHMARK (Table 4 Replication)")
print(f"  Running {ITERATIONS} iterations per primitive...")
print("=" * 65)

# 1. SHA-256 Hash
test_data = os.urandom(32)
t_sha = timeit.timeit(
    stmt=lambda: hashlib.sha256(test_data).digest(),
    number=ITERATIONS
) / ITERATIONS * 1000

# 2. HMAC-SHA-256
key_hmac = os.urandom(32)
t_hmac = timeit.timeit(
    stmt=lambda: hmac.new(key_hmac, test_data, hashlib.sha256).digest(),
    number=ITERATIONS
) / ITERATIONS * 1000

# 3. AES-256-CBC Encryption
aes_key = os.urandom(32)
aes_iv = os.urandom(16)
aes_plain = b"A" * 64  # standard block size payload

def do_aes_enc():
    c = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv))
    enc = c.encryptor()
    return enc.update(aes_plain) + enc.finalize()

t_aes_enc = timeit.timeit(stmt=do_aes_enc, number=ITERATIONS) / ITERATIONS * 1000

# 4. AES-256-CBC Decryption
ciphertext = do_aes_enc()

def do_aes_dec():
    c = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv))
    dec = c.decryptor()
    return dec.update(ciphertext) + dec.finalize()

t_aes_dec = timeit.timeit(stmt=do_aes_dec, number=ITERATIONS) / ITERATIONS * 1000

# 5. Point Multiplication (ECDH / SECP256R1)
priv_key = ec.generate_private_key(ec.SECP256R1())
peer_key = ec.generate_private_key(ec.SECP256R1()).public_key()

t_ecdh = timeit.timeit(
    stmt=lambda: priv_key.exchange(ec.ECDH(), peer_key),
    number=ITERATIONS
) / ITERATIONS * 1000

print(f"\n{'Operation':<28} | {'Measured (ms)':<15} | {'Paper Table 4 (Pi 3B+)':<22}")
print("-" * 72)
print(f"{'h(SHA256)':<28} | {t_sha:>10.4f} ms    | {'0.013 ms':>18}")
print(f"{'mac(HMAC-SHA-256)':<28} | {t_hmac:>10.4f} ms    | {'1.572 ms':>18}")
print(f"{'e(AES-CBC-256 Enc)':<28} | {t_aes_enc:>10.4f} ms    | {'0.0752 ms':>18}")
print(f"{'e(AES-CBC-256 Dec)':<28} | {t_aes_dec:>10.4f} ms    | {'0.132 ms':>18}")
print(f"{'Point Multiplication':<28} | {t_ecdh:>10.4f} ms    | {'1.62 ms':>18}")
print("=" * 72)

# Theoretical protocol cost on device: 2E + 2D + 8H + PUF
# PUF response is simulated as 1 hash
t_puf = t_sha
t_device_total = (2 * t_aes_enc) + (2 * t_aes_dec) + (8 * t_sha) + (0.7 * t_puf)
print(f"\nCalculated IoT Device Authentication Time (2E + 2D + 8H + 0.7PF):")
print(f"  Your Pi 3B+:    {t_device_total:.4f} ms")
print(f"  Paper (Pi 3B+): 0.5275 ms")
print("=" * 72)
