"""
IoT Device — Connects to AP (which relays to AS).
Full authentication protocol with timing, energy, and communication metrics.
"""

import socket                                                       # TCP client socket to connect to AP
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

AP_HOST = os.environ.get('AP_HOST', 'ap')                           # Hostname of Access Point (Docker DNS resolves this)
AP_PORT = int(os.environ.get('AP_PORT', '55555'))                   # Port of Access Point

# Typical IoT device power draw in watts (e.g., ESP32 ~0.24W active, RPi ~2.5W)
# Configurable via environment variable
IOT_POWER_WATTS = float(os.environ.get('IOT_POWER_WATTS', '0.24')) # Power model for energy estimation (ESP32 ~0.24W)

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
        energy = cpu * IOT_POWER_WATTS                              # Energy = CPU_time × Power (Joules) — IoT uses 0.24W
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
        total_energy = total_cpu * IOT_POWER_WATTS

        ru = resource.getrusage(resource.RUSAGE_SELF)               # Get OS-level resource usage stats

        print("\n" + "=" * 70)
        print("   IoT DEVICE — PERFORMANCE METRICS")
        print("=" * 70)
        print(f"  Power Model: {IOT_POWER_WATTS} W (set IOT_POWER_WATTS to change)")
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

def simulate_puf(challenge):                                        # Simulate a Physical Unclonable Function (hardware-bound)
    HARDWARE_SEED = b"DEVICE_SPECIFIC_HARDWARE_ROOT_MACRO"          # Fixed seed — in real HW, this is a circuit response
    return sha256(HARDWARE_SEED, challenge)                         # Returns deterministic hash: same challenge → same output

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
class IoTProtocol:                                                  # Client-side IoT authentication protocol handler
    def __init__(self):
        self.uidd = os.urandom(16)                                  # Unique Device Identifier — random 16 bytes

    def execute_handshake(self, sock):                               # Run the full registration + authentication protocol
        metrics.start_total()                                       # Begin timing the entire handshake

        # === PRE-REGISTRATION (Offline — No network message) ===
        # PSW: Generated locally on the IoT device.
        #       In a real deployment, the user chooses this password during setup.
        # PKS: Read from shared volume (/shared/pks.pem).
        #       In a real deployment, PKS is pre-loaded at manufacturing.
        print("\n[IoT] --- PRE-REGISTRATION (Offline) ---")

        psw = os.urandom(16)                                        # IoT generates its own PSW locally (AS never sees it)
        print("[IoT] PSW: generated locally on device (AS never receives it).")

        pks_path = '/shared/pks.pem'                                # Path to pre-provisioned server public key
        while not os.path.exists(pks_path):                         # Wait for AS to write it (startup timing)
            print(f"[IoT] Waiting for PKS at {pks_path}...")
            time.sleep(1)
        with open(pks_path, 'rb') as f:                             # Read PKS from shared volume
            pks = serialization.load_pem_public_key(f.read())       # Load AS's ECDH public key from PEM
        print(f"[IoT] PKS: loaded from {pks_path} (pre-provisioned).")

        # === ALGORITHM 1 — Registration Initialization ===        # Phase 2: Compute PUF-based identity & send registration
        metrics.start_phase("Algo 1 — Reg Init (compute)")
        print("\n[IoT] --- REGISTRATION PHASE (Algorithm 1) ---")
        challenge = sha256(self.uidd, b"PUF CHALLENGE")             # PUF challenge = SHA256(device_id, "PUF CHALLENGE")
        r = simulate_puf(challenge)                                 # PUF response — simulates hardware-bound secret
        puf_secret = sha256(r, self.uidd)                           # PUF secret = SHA256(PUF_response, device_id)
        combined_secret = sha256(psw, puf_secret)                   # Combine PSW and PUF secret: SHA256(PSW, puf_secret)
        i_i = sha256(xor_bytes(combined_secret, pad_16(self.uidd))) # ⭐ I_i = SHA256(combined_secret ⊕ pad(uidd)) — DEVICE IDENTITY

        n_a = os.urandom(16)                                        # N_a: IoT's nonce for freshness (16 bytes)
        t_1 = str(123456).encode('utf-8').ljust(8, b'\x00')        # T_1: Timestamp (8 bytes, mock value)
        et = b"EXP_TIME"                                            # ET: Expiry Time (8 bytes, mock value)
        lia_i = os.urandom(16)                                      # LIA_i: Location/Identity Attribute (16 random bytes)
        tid_i = os.urandom(16)                                      # TID_i: Temporary ID (16 random bytes)
        w = os.urandom(16)                                          # W: Random value (16 bytes)
        p_list_mock = os.urandom(16)                                # P_list: Policy list mock (16 random bytes)

        eph_sks = ec.generate_private_key(ec.SECP256R1())           # Generate EPHEMERAL ECDH private key (one-time use)
        eph_pks = eph_sks.public_key()                              # Derive ephemeral public key from private key
        eph_shared = eph_sks.exchange(ec.ECDH(), pks)               # ECDH key exchange: IoT_ephemeral_private × AS_public
        aes_key_e1 = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,    info=b'handshake').derive(eph_shared)  # Derive 32-byte AES key from ECDH shared secret via HKDF

        e1_payload = i_i + n_a + t_1 + et + lia_i + tid_i + w + p_list_mock  # E1 plaintext: all registration data concatenated
        e1 = aes_encrypt(aes_key_e1, e1_payload)                    # Encrypt E1 payload with HKDF-derived AES key
        h1 = sha256(i_i, n_a, t_1, et, lia_i, tid_i, w, p_list_mock)  # H1: Integrity hash over all E1 fields

        eph_pks_pem = eph_pks.public_bytes(                         # Serialize ephemeral public key to PEM format
            encoding=serialization.Encoding.PEM,                    # PEM = Base64 text with -----BEGIN/END----- headers
            format=serialization.PublicFormat.SubjectPublicKeyInfo   # Standard public key format
        )
        metrics.end_phase()

        metrics.start_phase("Algo 1 — Reg Init (send)")             # Phase 2b: Send registration data to AS
        send_msg(sock, {                                            # Send {E1, H1, eph_pub} as base64-encoded JSON
            'E1': base64.b64encode(e1).decode('utf-8'),             # Encrypted registration payload
            'H1': base64.b64encode(h1).decode('utf-8'),             # Integrity hash for verification
            'eph_pub': base64.b64encode(eph_pks_pem).decode('utf-8')  # Ephemeral public key so AS can do ECDH too
        })
        print("[IoT] Sent E1, H1 to AS (via AP).")
        metrics.end_phase()

        # === ALGORITHM 3 — Device Storage Setup ===               # Phase 3: Receive and decrypt registration credentials
        metrics.start_phase("Algo 3 — Storage Setup")
        print("\n[IoT] --- ALGORITHM 3 — Device Storage Setup ---")
        reg_resp = recv_msg(sock)                                   # Receive {E2, H2} from AS
        e2 = base64.b64decode(reg_resp['E2'])                       # Decode E2 ciphertext from base64
        h2 = base64.b64decode(reg_resp['H2'])                       # Decode H2 integrity hash from base64

        e2_key = sha256(xor_bytes(pad_16(n_a), i_i))               # Derive E2 decryption key = SHA256(pad(N_a) ⊕ I_i)
        decrypted_e2 = aes_decrypt(e2_key, e2)                      # Decrypt E2 to get registration credentials

        midi = decrypted_e2[:80]                                    # MIDI: Masked IoT Device Identity (80 bytes, AES output)
        msidi = decrypted_e2[80:144]                                # MSIDI: Masked Server Identity (64 bytes, AES output)
        n_b = decrypted_e2[144:160]                                 # N_b: Server's nonce (16 bytes)
        t_3 = decrypted_e2[160:168]                                 # T_3: Server timestamp (8 bytes)
        msk_enc = decrypted_e2[168:232]                             # MSK_enc: Encrypted Master Secret Key (64 bytes)
        ot_enc = decrypted_e2[232:]                                 # OT_enc: Encrypted One-Time token list (remaining bytes)

        h2_check = sha256(midi, msidi, n_b, t_3, msk_enc, ot_enc)  # Recompute integrity hash over all extracted fields
        if h2_check != h2:                                          # INTEGRITY CHECK: computed hash must match received H2
            print("[IoT] ERROR: Integrity check failed on E2.")
            return None

        k_reg = sha256(pad_16(n_a), pad_16(n_b), i_i)              # K_reg = SHA256(pad(N_a), pad(N_b), I_i) — Registration Key
        ot_list_bytes = aes_decrypt(k_reg, ot_enc)                  # Decrypt OT list with registration key
        ot_list = [ot_list_bytes[i:i+16] for i in range(0, len(ot_list_bytes), 16)]  # Split into 16-byte tokens → list of 10
        msk = aes_decrypt(k_reg, msk_enc)                           # Decrypt Master Secret Key with registration key

        print("[IoT] Registration successful. E2 decrypted.")       # All credentials stored locally ✓
        metrics.end_phase()

        # === ALGORITHM 4 — Authentication Request ===             # Phase 4: Build and send authentication request
        metrics.start_phase("Algo 4 — Auth Request")
        print("\n[IoT] --- AUTHENTICATION PHASE (Algorithm 4) ---")
        ot_index = 0                                                # Use first one-time token (index 0)
        ot_j = ot_list[ot_index]                                    # Retrieve OT token at index 0 (16 bytes)
        r_1 = os.urandom(16)                                        # R_1: Random value for identity update (16 bytes)
        n_c = os.urandom(16)                                        # N_c: IoT's authentication nonce (16 bytes)
        t_1_auth = str(123457).encode('utf-8').ljust(8, b'\x00')   # T_1: Authentication timestamp (8 bytes, mock)
        i_u = sha256(xor_bytes(i_i, pad_16(r_1)))                   # I_u = SHA256(I_i ⊕ pad(R_1)) — Updated device identity

        m1_payload = i_u + msidi + n_c + t_1_auth + r_1 + lia_i + ot_index.to_bytes(4, 'big')  # M1 plaintext: auth data
        m1 = aes_encrypt(k_reg, m1_payload)                         # Encrypt M1 with registration key K_reg
        ha1 = sha256(i_u, msidi, n_c, t_1_auth, r_1, lia_i, ot_index.to_bytes(4, 'big'))  # HA1: Integrity hash

        send_msg(sock, {                                            # Send {Midi, M1, HA1} to AS
            'Midi': base64.b64encode(midi).decode('utf-8'),         # MIDI as device lookup key (AS uses this to find record)
            'M1': base64.b64encode(m1).decode('utf-8'),             # Encrypted authentication payload
            'HA1': base64.b64encode(ha1).decode('utf-8')            # Integrity hash for verification
        })
        print("[IoT] Sent M1, HA1 to AS (via AP).")
        metrics.end_phase()

        # === ALGORITHM 6 — Server Authentication by Device ===    # Phase 5: Verify AS's response to authenticate the server
        metrics.start_phase("Algo 6 — Server Auth")
        print("\n[IoT] --- ALGORITHM 6 — Server Auth by Device ---")
        auth_resp = recv_msg(sock)                                  # Receive {M2, HA2} from AS
        if not auth_resp:                                           # Connection closed — handshake failed
            print("[IoT] ERROR: Connection closed during auth.")
            return None

        m2 = base64.b64decode(auth_resp['M2'])                      # Decode M2 ciphertext from base64
        ha2 = base64.b64decode(auth_resp['HA2'])                    # Decode HA2 integrity hash from base64

        k_new = sha256(k_reg, ot_j, n_c, r_1)                      # K_new = SHA256(K_reg, OT_j, N_c, R_1) — new derivation key
        decrypted_m2 = aes_decrypt(k_new, m2)                       # Decrypt M2 with K_new

        i_u_n = decrypted_m2[:32]                                   # I_u_n: Next updated identity (32 bytes)
        midi_new = decrypted_m2[32:112]                             # MIDI_new: New masked device ID for next session (80 bytes)
        msidi_new = decrypted_m2[112:176]                           # MSIDI_new: New masked server ID for next session (64 bytes)
        n_d = decrypted_m2[176:192]                                 # N_d: Server's authentication nonce (16 bytes)
        t_3_auth = decrypted_m2[192:200]                            # T_3: Server timestamp (8 bytes)
        r_2 = decrypted_m2[200:216]                                 # R_2: Server's random value (16 bytes)
        tsk = decrypted_m2[216:232]                                 # TSK: Temporary Session Key (16 bytes)
        et_fr = decrypted_m2[232:240]                               # ET_fr: Expiry time for session (8 bytes)
        mtid_t = decrypted_m2[240:]                                 # MTID_t: Encrypted ticket from AS (remaining bytes)

        ha2_check = sha256(i_u_n, midi_new, msidi_new, n_d, t_3_auth, r_2, tsk, et_fr, mtid_t)  # Recompute integrity hash
        if ha2_check != ha2:                                        # INTEGRITY CHECK: must match received HA2
            print("[IoT] ERROR: Integrity check failed on M2.")     # If mismatch → server is NOT authentic
            return None

        sk = sha256(k_new, n_d, i_u_n)                              # ⭐ SK = SHA256(K_new, N_d, I_u_n) — THE SESSION KEY
        print("[IoT] Server authenticated. Handshake COMPLETE!")    # Server is verified ✓
        print(f"[IoT] Session Key: {sk.hex()}")                     # Should match AS's SK exactly
        metrics.end_phase()

        return sk                                                   # Return session key for secure communication


def main():                                                         # Main entry point — connect to AP and run protocol
    print("=" * 55)
    print("       IoT DEVICE — Docker Container")
    print("=" * 55)
    print(f"  Connecting to AP at {AP_HOST}:{AP_PORT}")
    print("=" * 55)

    # Wait for AP to be ready
    while True:                                                     # Retry loop until AP is reachable
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP client socket
            sock.connect((AP_HOST, AP_PORT))                        # Attempt to connect to AP on port 55555
            print(f"\n[IoT] Connected to AP at {AP_HOST}:{AP_PORT}")
            break                                                   # Connection successful — exit retry loop
        except (ConnectionRefusedError, OSError):                   # AP not ready yet
            print("[IoT] Waiting for AP...")
            time.sleep(2)                                           # Wait 2 seconds before retrying

    proto = IoTProtocol()                                           # Create protocol instance (generates device ID)
    sk = proto.execute_handshake(sock)                               # Run the full 5-phase handshake protocol

    if not sk:                                                      # Handshake failed
        print("[IoT] Protocol FAILED.")
        sock.close()
        sys.exit(1)                                                 # Exit with error code

    # Send a test encrypted message                                # Phase 6: Secure message exchange after handshake
    metrics.start_phase("Secure Message Exchange")
    print("\n[IoT] Sending encrypted test message...")
    test_msg = b"Hello from IoT! Secure session verified."          # Plaintext test message
    enc_msg = aes_encrypt(sk, test_msg)                             # Encrypt with session key (AES-256-CBC)
    sock.sendall(enc_msg)                                           # Send encrypted bytes directly (no JSON wrapper)
    metrics.record_send(len(enc_msg))                               # Track bytes sent

    # Receive response
    try:
        enc_resp = sock.recv(4096)                                  # Receive encrypted response from AS (via AP)
        if enc_resp:
            metrics.record_recv(len(enc_resp))                      # Track bytes received
            resp = aes_decrypt(sk, enc_resp)                        # Decrypt with session key
            print(f"[IoT] Received from AS: {resp.decode('utf-8')}")  # Print decrypted response
    except Exception as e:
        print(f"[IoT] Error receiving response: {e}")
    metrics.end_phase()

    print("\n[IoT] Protocol demonstration complete.")
    metrics.print_summary()                                         # Print full performance metrics table
    sock.close()                                                    # Close TCP connection


if __name__ == '__main__':
    main()
