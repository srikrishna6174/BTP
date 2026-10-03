"""
Authentication Server (AS) — Listens for connections from AP.
Full authentication protocol with timing, energy, and communication metrics.
"""

import socket                                                       # TCP server socket programming
import json                                                         # Serialize/deserialize protocol messages to JSON
import base64                                                       # Encode binary data (ciphertext, hashes) for JSON
import hashlib                                                      # SHA-256 hashing for integrity & key derivation
import os                                                           # os.urandom() for cryptographic random bytes, env vars
import sys                                                          # sys.exit() for error termination
import time                                                         # perf_counter() for wall time, process_time() for CPU
import resource                                                     # getrusage() for OS-level memory & CPU stats
from cryptography.hazmat.primitives.asymmetric import ec            # Elliptic Curve key generation & ECDH key exchange
from cryptography.hazmat.primitives import serialization, hashes    # PEM key encoding & hash algorithm objects
from cryptography.hazmat.primitives.kdf.hkdf import HKDF            # HMAC-based Key Derivation Function
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # AES-256-CBC encryption/decryption

HOST = ''                                                           # Listen on all network interfaces (0.0.0.0)
PORT = int(os.environ.get('AS_PORT', '55556'))                      # Port to listen on (default 55556)

# Typical server power draw in watts
AS_POWER_WATTS = float(os.environ.get('AS_POWER_WATTS', '65.0'))    # Power model for energy estimation (server ~65W)

# --- METRICS COLLECTOR ---
class Metrics:                                                      # Tracks timing, energy, and communication per phase
    def __init__(self):
        self.phases = []                                            # List of completed phase measurements
        self.total_bytes_sent = 0                                   # Running total of bytes sent
        self.total_bytes_recv = 0                                   # Running total of bytes received
        self._phase_start_wall = None                               # Wall-clock start for current phase
        self._phase_start_cpu = None                                # CPU time start for current phase
        self._phase_bytes_sent = 0                                  # Bytes sent in current phase
        self._phase_bytes_recv = 0                                  # Bytes received in current phase
        self._total_start_wall = None                               # Wall-clock start for entire protocol
        self._total_start_cpu = None                                # CPU time start for entire protocol

    def start_total(self):                                          # Call once at the very beginning of handshake
        self._total_start_wall = time.perf_counter()                # High-resolution wall clock timer
        self._total_start_cpu = time.process_time()                 # CPU-only timer (excludes I/O wait)

    def start_phase(self, name):                                    # Call at start of each protocol phase
        self._phase_start_wall = time.perf_counter()
        self._phase_start_cpu = time.process_time()
        self._phase_bytes_sent = 0                                  # Reset per-phase byte counters
        self._phase_bytes_recv = 0
        self._current_phase = name                                  # Store phase name for later

    def record_send(self, nbytes):                                  # Called after every send_msg()
        self._phase_bytes_sent += nbytes                            # Add to current phase counter
        self.total_bytes_sent += nbytes                             # Add to running total

    def record_recv(self, nbytes):                                  # Called after every recv_msg()
        self._phase_bytes_recv += nbytes
        self.total_bytes_recv += nbytes

    def end_phase(self):                                            # Call at end of each protocol phase
        wall = time.perf_counter() - self._phase_start_wall         # Elapsed wall-clock time (includes network wait)
        cpu = time.process_time() - self._phase_start_cpu           # Elapsed CPU time (computation only)
        energy = cpu * AS_POWER_WATTS                               # Energy = CPU_time × Power (Joules)
        self.phases.append({                                        # Store phase results for summary table
            'name': self._current_phase,
            'wall_time_ms': wall * 1000,                            # Convert seconds → milliseconds
            'cpu_time_ms': cpu * 1000,
            'energy_mJ': energy * 1000,                             # Convert Joules → milliJoules
            'bytes_sent': self._phase_bytes_sent,
            'bytes_recv': self._phase_bytes_recv,
        })

    def print_summary(self):                                        # Print formatted metrics table at the end
        total_wall = time.perf_counter() - self._total_start_wall
        total_cpu = time.process_time() - self._total_start_cpu
        total_energy = total_cpu * AS_POWER_WATTS

        ru = resource.getrusage(resource.RUSAGE_SELF)               # Get OS-level resource usage stats

        print("\n" + "=" * 70)
        print("   AUTHENTICATION SERVER (AS) — PERFORMANCE METRICS")
        print("=" * 70)
        print(f"  Power Model: {AS_POWER_WATTS} W (set AS_POWER_WATTS to change)")
        print("-" * 70)
        print(f"  {'Phase':<30} {'Wall(ms)':>10} {'CPU(ms)':>10} "
              f"{'Energy(mJ)':>12} {'Sent(B)':>9} {'Recv(B)':>9}")
        print("-" * 70)

        for p in self.phases:                                       # Print each phase's metrics as a table row
            print(f"  {p['name']:<30} {p['wall_time_ms']:>10.3f} "
                  f"{p['cpu_time_ms']:>10.3f} {p['energy_mJ']:>12.4f} "
                  f"{p['bytes_sent']:>9d} {p['bytes_recv']:>9d}")

        print("-" * 70)
        print(f"  {'TOTAL':<30} {total_wall*1000:>10.3f} "
              f"{total_cpu*1000:>10.3f} {total_energy*1000:>12.4f} "
              f"{self.total_bytes_sent:>9d} {self.total_bytes_recv:>9d}")
        print("=" * 70)
        print(f"  Total Wall-Clock Time : {total_wall*1000:.3f} ms")
        print(f"  Total CPU Time        : {total_cpu*1000:.3f} ms")
        print(f"  Total Energy (est.)   : {total_energy*1000:.4f} mJ "
              f"({total_energy*1e6:.2f} µJ)")
        print(f"  Total Bytes Sent      : {self.total_bytes_sent} bytes")
        print(f"  Total Bytes Received  : {self.total_bytes_recv} bytes")
        print(f"  Total Communication   : {self.total_bytes_sent + self.total_bytes_recv} bytes")
        print("-" * 70)
        print(f"  Max RSS Memory        : {ru.ru_maxrss} KB")       # Peak memory usage
        print(f"  User CPU Time (OS)    : {ru.ru_utime*1000:.3f} ms")  # User-space CPU from OS
        print(f"  System CPU Time (OS)  : {ru.ru_stime*1000:.3f} ms")  # Kernel CPU from OS
        print("=" * 70)

metrics = Metrics()                                                 # Global metrics instance shared across all functions

# --- CRYPTO HELPERS ---
def sha256(*args):                                                  # Hash multiple byte strings with SHA-256
    h = hashlib.sha256()                                            # Create SHA-256 hash object
    for a in args: h.update(a)                                      # Feed each argument into the hash
    return h.digest()                                               # Return 32-byte hash digest

def xor_bytes(b1, b2):                                              # XOR two byte strings element-by-element
    return bytes(x ^ y for x, y in zip(b1, b2))                    # zip truncates to shorter length

def pad_16(b):                                                      # Pad bytes to 32 bytes with null bytes
    return b.ljust(32, b'\x00')                                     # Used before XOR to ensure equal-length operands

def aes_encrypt(key, data):                                         # AES-256-CBC encryption with random IV
    iv = os.urandom(16)                                             # Generate random 16-byte Initialization Vector
    pad_len = 16 - (len(data) % 16)                                 # Calculate PKCS7 padding needed (1-16 bytes)
    data += bytes([pad_len]) * pad_len                              # Append padding bytes (each byte = pad_len value)
    cipher = Cipher(algorithms.AES(key[:32]), modes.CBC(iv))        # Create AES-256-CBC cipher (uses first 32 bytes of key)
    enc = cipher.encryptor()                                        # Get encryptor object
    ct = enc.update(data) + enc.finalize()                          # Encrypt and finalize
    return iv + ct                                                  # Return: [16-byte IV][ciphertext] concatenated

def aes_decrypt(key, enc_data):                                     # AES-256-CBC decryption, returns original plaintext
    iv, ct = enc_data[:16], enc_data[16:]                           # Split: first 16 bytes = IV, rest = ciphertext
    cipher = Cipher(algorithms.AES(key[:32]), modes.CBC(iv))        # Create cipher with same key and extracted IV
    dec = cipher.decryptor()                                        # Get decryptor object
    pt = dec.update(ct) + dec.finalize()                            # Decrypt ciphertext
    return pt[:-pt[-1]]                                             # Remove PKCS7 padding (last byte tells how many to remove)

# --- NETWORK HELPERS (instrumented) ---
def send_msg(sock, data):                                           # Send a JSON message with 4-byte length prefix
    msg = json.dumps(data).encode('utf-8')                          # Serialize dict → JSON string → UTF-8 bytes
    raw = len(msg).to_bytes(4, 'big') + msg                         # Prepend 4-byte big-endian length header
    sock.sendall(raw)                                               # Send ALL bytes (handles partial sends)
    metrics.record_send(len(raw))                                   # Track bytes sent for metrics

def recv_msg(sock):                                                 # Receive a length-prefixed JSON message
    raw = recvall(sock, 4)                                          # Read exactly 4 bytes (length header)
    if not raw: return None                                         # Connection closed
    msglen = int.from_bytes(raw, 'big')                             # Parse length as big-endian integer
    data = recvall(sock, msglen)                                    # Read exactly msglen bytes (the payload)
    if not data: return None                                        # Connection closed mid-message
    metrics.record_recv(4 + msglen)                                 # Track bytes received (header + payload)
    return json.loads(data.decode('utf-8'))                          # Decode UTF-8 → parse JSON → return dict

def recvall(sock, n):                                               # Read exactly n bytes from socket (TCP may fragment)
    data = bytearray()                                              # Buffer to accumulate received bytes
    while len(data) < n:                                            # Keep reading until we have n bytes
        pkt = sock.recv(n - len(data))                              # Read remaining bytes needed
        if not pkt: return None                                     # Connection closed unexpectedly
        data.extend(pkt)                                            # Append received chunk to buffer
    return data                                                     # Return exactly n bytes

# --- PROTOCOL ---
class ASProtocol:                                                   # Server-side authentication protocol handler
    def __init__(self):
        self.sidi = os.urandom(16)                                  # Server Identity — random 16 bytes
        self.sks = ec.generate_private_key(ec.SECP256R1())          # Server's ECDH private key (NIST P-256 curve)
        self.pks = self.sks.public_key()                            # Server's ECDH public key (shared with IoT)
        self.aps = os.urandom(32)                                   # Server secret for ticket encryption (32 bytes)
        self.db = {}                                                # In-memory device database: midi → device_record

    def execute_handshake(self, conn):                               # Run the full registration + authentication protocol
        metrics.start_total()                                       # Begin timing the entire handshake

        # === PRE-REGISTRATION (Offline — No network message) ===
        # PKS: Pre-provisioned to IoT via shared Docker volume at startup
        #       (simulates manufacturing/offline provisioning).
        # PSW: Generated locally on the IoT device — AS never sees it.
        #       AS only learns device identity (I_i) via encrypted E1.
        print("\n[AS] --- PRE-REGISTRATION (Offline) ---")
        print("[AS] PKS: pre-provisioned to IoT via shared volume (/shared/pks.pem).")
        print("[AS] PSW: generated locally on IoT device (AS never receives it).")

        # === ALGORITHM 2 — Server Registration Processing ===     # Phase 2: Process IoT's registration request
        metrics.start_phase("Algo 2 — Reg Processing")
        print("\n[AS] --- REGISTRATION PHASE (Algorithm 2) ---")
        reg_req = recv_msg(conn)                                    # Receive {E1, H1, eph_pub} from IoT
        if not reg_req:
            print("[AS] ERROR: No registration request received.")
            return None
        e1 = base64.b64decode(reg_req['E1'])                        # Decode E1 ciphertext from base64
        h1 = base64.b64decode(reg_req['H1'])                        # Decode H1 integrity hash from base64
        eph_pub_bytes = base64.b64decode(reg_req['eph_pub'])        # Decode IoT's ephemeral public key from base64

        eph_pub = serialization.load_pem_public_key(eph_pub_bytes)  # Load IoT's ephemeral EC public key from PEM
        shared_secret = self.sks.exchange(ec.ECDH(), eph_pub)       # ECDH key exchange: AS_private × IoT_ephemeral_public
        aes_key_e1 = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake').derive(shared_secret)  # Derive 32-byte AES key from ECDH shared secret

        decrypted_e1 = aes_decrypt(aes_key_e1, e1)                  # Decrypt E1 to get IoT's registration data

        i_i = decrypted_e1[:32]                                     # I_i: Device Identity (32 bytes, SHA-256 hash)
        n_a = decrypted_e1[32:48]                                   # N_a: IoT's nonce for freshness (16 bytes)
        t_1 = decrypted_e1[48:56]                                   # T_1: Timestamp (8 bytes)
        et = decrypted_e1[56:64]                                    # ET: Expiry Time (8 bytes)
        lia_i = decrypted_e1[64:80]                                 # LIA_i: Location/Identity Attribute (16 bytes)
        tid_i = decrypted_e1[80:96]                                 # TID_i: Temporary ID (16 bytes)
        w = decrypted_e1[96:112]                                    # W: Random value (16 bytes)
        p_list_mock = decrypted_e1[112:128]                         # P_list: Policy list mock (16 bytes)

        h1_check = sha256(i_i, n_a, t_1, et, lia_i, tid_i, w, p_list_mock)  # Recompute hash of all extracted fields
        if h1_check != h1:                                          # INTEGRITY CHECK: computed hash must match received H1
            print("[AS] ERROR: Integrity check failed on E1.")
            return None

        msk = sha256(n_a, self.sks.private_numbers().private_value.to_bytes(32, 'big'), i_i)  # MSK = SHA256(N_a, private_key_bytes, I_i) — Master Secret Key
        r1 = os.urandom(16)                                         # R1: Random value for masking identities (16 bytes)
        midi = aes_encrypt(msk, i_i + r1)                           # MIDI = AES(MSK, I_i||R1) — Masked IoT Device Identity
        msidi = aes_encrypt(msk, self.sidi + r1)                    # MSIDI = AES(MSK, SIDI||R1) — Masked Server Identity

        n_b = os.urandom(16)                                        # N_b: Server's nonce for freshness (16 bytes)
        k_reg = sha256(pad_16(n_a), pad_16(n_b), i_i)              # K_reg = SHA256(pad(N_a), pad(N_b), I_i) — Registration Key

        ot_list = [os.urandom(16) for _ in range(10)]               # Generate 10 one-time tokens (each 16 bytes)
        ot_list_bytes = b''.join(ot_list)                           # Concatenate all OT tokens into one byte string
        ot_enc = aes_encrypt(k_reg, ot_list_bytes)                  # Encrypt OT list with registration key
        msk_enc = aes_encrypt(k_reg, msk)                           # Encrypt MSK with registration key

        t_3 = str(123456).encode('utf-8').ljust(8, b'\x00')        # T_3: Timestamp for registration response (8 bytes)
        e2_key = sha256(xor_bytes(pad_16(n_a), i_i))               # E2 encryption key = SHA256(pad(N_a) ⊕ I_i)
        e2_payload = midi + msidi + n_b + t_3 + msk_enc + ot_enc   # E2 plaintext: all registration credentials concatenated
        e2 = aes_encrypt(e2_key, e2_payload)                        # Encrypt E2 payload
        h2 = sha256(midi, msidi, n_b, t_3, msk_enc, ot_enc)        # H2: Integrity hash over all E2 contents

        self.db[midi] = {                                           # STORE device record in database, keyed by MIDI
            'i_i': i_i, 'msk': msk, 'r1': r1,                     # Device identity, master key, random value
            'k_reg': k_reg, 'ot_list': ot_list, 'msidi': msidi     # Registration key, OT tokens, masked server ID
        }

        send_msg(conn, {                                            # Send registration response to IoT
            'E2': base64.b64encode(e2).decode('utf-8'),             # Encrypted credentials
            'H2': base64.b64encode(h2).decode('utf-8')              # Integrity hash
        })
        print("[AS] Registration successful. Sent E2, H2 to IoT (via AP).")
        metrics.end_phase()

        # === ALGORITHM 5 — Device Authentication by Server ===    # Phase 3: Verify IoT device's authentication request
        metrics.start_phase("Algo 5 — Device Auth")
        print("\n[AS] --- AUTHENTICATION PHASE (Algorithm 5) ---")
        auth_req = recv_msg(conn)                                   # Receive {Midi, M1, HA1} from IoT
        if not auth_req:
            print("[AS] ERROR: No auth request received.")
            return None
        midi_recv = base64.b64decode(auth_req['Midi'])              # Decode received MIDI (device lookup key)
        m1 = base64.b64decode(auth_req['M1'])                       # Decode M1 ciphertext
        ha1 = base64.b64decode(auth_req['HA1'])                     # Decode HA1 integrity hash

        if midi_recv not in self.db:                                # LOOKUP: Check if this device is registered
            print("[AS] ERROR: Unknown device.")
            return None

        record = self.db[midi_recv]                                 # Retrieve stored device record
        k_reg_db = record['k_reg']                                  # Get stored registration key
        decrypted_m1 = aes_decrypt(k_reg_db, m1)                    # Decrypt M1 with stored K_reg

        i_u = decrypted_m1[:32]                                     # I_u: Updated device identity (32 bytes)
        msidi_recv = decrypted_m1[32:96]                            # MSIDI: Masked server ID from IoT (64 bytes)
        n_c = decrypted_m1[96:112]                                  # N_c: IoT's authentication nonce (16 bytes)
        t_1_auth = decrypted_m1[112:120]                            # T_1: Authentication timestamp (8 bytes)
        r_1_auth = decrypted_m1[120:136]                            # R_1: Random value for identity update (16 bytes)
        lia_i_recv = decrypted_m1[136:152]                          # LIA_i: Location/Identity Attribute (16 bytes)
        ot_idx = int.from_bytes(decrypted_m1[152:156], 'big')       # OT index: Which one-time token to use (4 bytes)

        ha1_check = sha256(i_u, msidi_recv, n_c, t_1_auth, r_1_auth, lia_i_recv, ot_idx.to_bytes(4, 'big'))  # Recompute integrity hash
        if ha1_check != ha1:                                        # INTEGRITY CHECK: must match received HA1
            print("[AS] ERROR: Auth integrity check failed.")
            return None

        print("[AS] Device authenticated by Server.")               # IoT device is verified ✓

        ot_j = record['ot_list'][ot_idx]                            # Retrieve the one-time token at requested index
        r_2 = os.urandom(16)                                        # R_2: Server's random value for identity update
        n_d = os.urandom(16)                                        # N_d: Server's authentication nonce

        k_new = sha256(k_reg_db, ot_j, n_c, r_1_auth)              # K_new = SHA256(K_reg, OT_j, N_c, R_1) — new derivation key
        i_u_n = sha256(xor_bytes(xor_bytes(record['i_i'], pad_16(r_1_auth)), pad_16(r_2)))  # I_u_n = SHA256(I_i ⊕ R_1 ⊕ R_2) — next updated identity
        sk = sha256(k_new, n_d, i_u_n)                              # ⭐ SK = SHA256(K_new, N_d, I_u_n) — THE SESSION KEY

        midi_new = aes_encrypt(record['msk'], record['i_i'] + r_2)  # New MIDI for next session
        msidi_new = aes_encrypt(record['msk'], self.sidi + r_2)     # New MSIDI for next session

        tsk = os.urandom(16)                                        # TSK: Temporary Session Key (16 bytes)
        et_fr = b"EXP_TIME"                                         # ET_fr: Expiry time for session (8 bytes)
        mtid_t = aes_encrypt(self.aps, midi_new)                    # MTID_t: Encrypted ticket = AES(APS, MIDI_new)

        t_3_auth = str(123457).encode('utf-8').ljust(8, b'\x00')   # T_3: Authentication response timestamp
        m2_payload = i_u_n + midi_new + msidi_new + n_d + t_3_auth + r_2 + tsk + et_fr + mtid_t  # M2 plaintext
        m2 = aes_encrypt(k_new, m2_payload)                         # Encrypt M2 with K_new
        ha2 = sha256(i_u_n, midi_new, msidi_new, n_d, t_3_auth, r_2, tsk, et_fr, mtid_t)  # HA2: Integrity hash

        send_msg(conn, {                                            # Send authentication response to IoT
            'M2': base64.b64encode(m2).decode('utf-8'),
            'HA2': base64.b64encode(ha2).decode('utf-8')
        })
        print("[AS] Sent M2, HA2. Handshake COMPLETE!")
        print(f"[AS] Session Key: {sk.hex()}")                      # Print session key (should match IoT's SK)
        metrics.end_phase()

        return sk                                                   # Return the session key for secure communication


def main():                                                         # Main entry point — start server and handle connections
    print("=" * 55)
    print("       AUTHENTICATION SERVER (AS) — Docker")
    print("=" * 55)
    print(f"  Listening on port {PORT}")
    print("=" * 55)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)     # Create TCP server socket
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # Allow port reuse on restart
    server.bind((HOST, PORT))                                       # Bind to all interfaces on port 55556
    server.listen(5)                                                # Queue up to 5 pending connections

    print(f"\n[AS] Waiting for connections on port {PORT} ...")

    auth = ASProtocol()                                             # Create protocol instance (generates keys, empty DB)

    # Pre-provision PKS to shared volume (simulates manufacturing/offline setup)
    shared_dir = '/shared'
    os.makedirs(shared_dir, exist_ok=True)                          # Create /shared if it doesn't exist
    pks_pem = auth.pks.public_bytes(                                # Serialize AS public key to PEM format
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pks_path = os.path.join(shared_dir, 'pks.pem')
    with open(pks_path, 'wb') as f:                                 # Write PKS to shared volume
        f.write(pks_pem)
    print(f"[AS] PKS written to {pks_path} (offline pre-provisioning)")

    while True:                                                     # Main loop: accept connections forever
        conn, addr = server.accept()                                # Block until AP connects (relaying IoT traffic)
        print(f"\n[AS] Connection from {addr[0]}:{addr[1]} (via AP)")

        try:
            sk = auth.execute_handshake(conn)                       # Run the full 4-phase handshake protocol
        except Exception as e:
            print(f"[AS] Handshake error (possibly a probe): {e}")  # Handle probe/malformed connections gracefully
            conn.close()
            continue

        if not sk:                                                  # Handshake failed (integrity check, unknown device, etc.)
            print("[AS] Protocol FAILED.")
            conn.close()
            continue

        # Receive test message                                     # Phase 4: Secure message exchange after handshake
        metrics.start_phase("Secure Message Exchange")
        try:
            enc_data = conn.recv(4096)                              # Receive AES-encrypted test message from IoT
            if enc_data:
                metrics.record_recv(len(enc_data))
                msg = aes_decrypt(sk, enc_data)                     # Decrypt with session key
                print(f"[AS] Received from IoT: {msg.decode('utf-8')}")

                # Send response
                resp = b"Hello from AS! Secure session confirmed."
                enc_resp = aes_encrypt(sk, resp)                    # Encrypt response with session key
                conn.sendall(enc_resp)                              # Send encrypted response back to IoT
                metrics.record_send(len(enc_resp))
                print("[AS] Sent encrypted response to IoT.")
        except Exception as e:
            print(f"[AS] Error: {e}")
        metrics.end_phase()

        print("\n[AS] Protocol demonstration complete.")
        metrics.print_summary()                                     # Print full performance metrics table
        conn.close()                                                # Close connection, ready for next device


if __name__ == '__main__':
    main()
