"""
IoT Device Client — Hardware Deployment
Full 6-Algorithm EAP-IMP Authentication Protocol with timing, energy, and communication metrics.
Runs on Raspberry Pi 3B+ (ARM Cortex-A53).
Directly connects to Laptop AS at 192.168.137.1:55556.
"""

import socket
import json
import base64
import hashlib
import os
import sys
import time
try:
    import resource
except ImportError:
    resource = None
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AS_HOST = os.environ.get('AS_HOST', '192.168.137.1')
AS_PORT = int(os.environ.get('AS_PORT', '55556'))
IOT_POWER_WATTS = float(os.environ.get('IOT_POWER_WATTS', '1.2'))  # RPi 3B+ active ~1.2W

class Metrics:
    def __init__(self):
        self.phases = []
        self.total_bytes_sent = 0
        self.total_bytes_recv = 0
        self._phase_start_wall = None
        self._phase_start_cpu = None
        self._phase_bytes_sent = 0
        self._phase_bytes_recv = 0
        self._total_start_wall = None
        self._total_start_cpu = None

    def start_total(self):
        self._total_start_wall = time.perf_counter()
        self._total_start_cpu = time.process_time()

    def start_phase(self, name):
        self._phase_start_wall = time.perf_counter()
        self._phase_start_cpu = time.process_time()
        self._phase_bytes_sent = 0
        self._phase_bytes_recv = 0
        self._current_phase = name

    def record_send(self, nbytes):
        self._phase_bytes_sent += nbytes
        self.total_bytes_sent += nbytes

    def record_recv(self, nbytes):
        self._phase_bytes_recv += nbytes
        self.total_bytes_recv += nbytes

    def end_phase(self):
        wall = time.perf_counter() - self._phase_start_wall
        cpu = time.process_time() - self._phase_start_cpu
        energy = cpu * IOT_POWER_WATTS
        self.phases.append({
            'name': self._current_phase,
            'wall_time_ms': wall * 1000,
            'cpu_time_ms': cpu * 1000,
            'energy_mJ': energy * 1000,
            'bytes_sent': self._phase_bytes_sent,
            'bytes_recv': self._phase_bytes_recv,
        })

    def print_summary(self):
        total_wall = time.perf_counter() - self._total_start_wall
        total_cpu = time.process_time() - self._total_start_cpu
        total_energy = total_cpu * IOT_POWER_WATTS

        print("\n" + "=" * 70)
        print("   IoT DEVICE (Raspberry Pi 3B+) — PERFORMANCE METRICS")
        print("=" * 70)
        print(f"  Power Model: {IOT_POWER_WATTS} W (set IOT_POWER_WATTS to change)")
        print("-" * 70)
        print(f"  {'Phase':<30} {'Wall(ms)':>10} {'CPU(ms)':>10} "
              f"{'Energy(mJ)':>12} {'Sent(B)':>9} {'Recv(B)':>9}")
        print("-" * 70)

        for p in self.phases:
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
        print(f"  Total Energy (est.)   : {total_energy*1000:.4f} mJ ({total_energy*1e6:.2f} µJ)")
        print(f"  Total Bytes Sent      : {self.total_bytes_sent} bytes")
        print(f"  Total Bytes Received  : {self.total_bytes_recv} bytes")
        print(f"  Total Communication   : {self.total_bytes_sent + self.total_bytes_recv} bytes")
        print("-" * 70)
        if resource:
            ru = resource.getrusage(resource.RUSAGE_SELF)
            print(f"  Max RSS Memory        : {ru.ru_maxrss} KB")
            print(f"  User CPU Time (OS)    : {ru.ru_utime*1000:.3f} ms")
            print(f"  System CPU Time (OS)  : {ru.ru_stime*1000:.3f} ms")
        print("=" * 70)

metrics = Metrics()

def sha256(*args):
    h = hashlib.sha256()
    for a in args: h.update(a)
    return h.digest()

def xor_bytes(b1, b2):
    return bytes(x ^ y for x, y in zip(b1, b2))

def pad_16(b):
    return b.ljust(32, b'\x00')

def aes_encrypt(key, data):
    iv = os.urandom(16)
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len
    cipher = Cipher(algorithms.AES(key[:32]), modes.CBC(iv))
    enc = cipher.encryptor()
    ct = enc.update(data) + enc.finalize()
    return iv + ct

def aes_decrypt(key, enc_data):
    iv, ct = enc_data[:16], enc_data[16:]
    cipher = Cipher(algorithms.AES(key[:32]), modes.CBC(iv))
    dec = cipher.decryptor()
    pt = dec.update(ct) + dec.finalize()
    return pt[:-pt[-1]]

def simulate_puf(challenge):
    HARDWARE_SEED = b"RPI3BPLUS_PHYSICAL_PUF_CHALLENGE"
    return sha256(HARDWARE_SEED, challenge)

def send_msg(sock, data):
    msg = json.dumps(data).encode('utf-8')
    raw = len(msg).to_bytes(4, 'big') + msg
    sock.sendall(raw)
    metrics.record_send(len(raw))

def recv_msg(sock):
    raw = recvall(sock, 4)
    if not raw: return None
    msglen = int.from_bytes(raw, 'big')
    data = recvall(sock, msglen)
    metrics.record_recv(4 + msglen)
    return json.loads(data.decode('utf-8'))

def recvall(sock, n):
    data = bytearray()
    while len(data) < n:
        pkt = sock.recv(n - len(data))
        if not pkt: return None
        data.extend(pkt)
    return data

class IoTProtocol:
    def __init__(self):
        self.uidd = os.urandom(16)

    def execute_handshake(self, sock):
        metrics.start_total()

        # === PRE-REGISTRATION ===
        print("\n[IoT] --- PRE-REGISTRATION (Offline) ---")
        psw = os.urandom(16)
        print("[IoT] PSW: generated locally on device (AS never receives it).")

        pks_path = 'pks.pem'
        while not os.path.exists(pks_path):
            print(f"[IoT] Waiting for PKS at {pks_path}...")
            time.sleep(1)
        with open(pks_path, 'rb') as f:
            pks = serialization.load_pem_public_key(f.read())
        print(f"[IoT] PKS: loaded from {pks_path} (pre-provisioned).")

        # === ALGORITHM 1 — Registration Initialization ===
        metrics.start_phase("Algo 1 — Reg Init")
        print("\n[IoT] --- REGISTRATION PHASE (Algorithm 1) ---")
        challenge = sha256(self.uidd, b"PUF CHALLENGE")
        r = simulate_puf(challenge)
        puf_secret = sha256(r, self.uidd)
        combined_secret = sha256(psw, puf_secret)
        i_i = sha256(xor_bytes(combined_secret, pad_16(self.uidd)))

        n_a = os.urandom(16)
        t_1 = str(123456).encode('utf-8').ljust(8, b'\x00')
        et = b"EXP_TIME"
        lia_i = os.urandom(16)
        tid_i = os.urandom(16)
        w = os.urandom(16)
        p_list_mock = os.urandom(16)

        eph_sks = ec.generate_private_key(ec.SECP256R1())
        eph_pks = eph_sks.public_key()
        eph_shared = eph_sks.exchange(ec.ECDH(), pks)
        aes_key_e1 = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake').derive(eph_shared)

        e1_payload = i_i + n_a + t_1 + et + lia_i + tid_i + w + p_list_mock
        e1 = aes_encrypt(aes_key_e1, e1_payload)
        h1 = sha256(i_i, n_a, t_1, et, lia_i, tid_i, w, p_list_mock)

        eph_pks_pem = eph_pks.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        send_msg(sock, {
            'E1': base64.b64encode(e1).decode('utf-8'),
            'H1': base64.b64encode(h1).decode('utf-8'),
            'eph_pub': base64.b64encode(eph_pks_pem).decode('utf-8')
        })
        print("[IoT] Sent E1, H1 to AS.")
        metrics.end_phase()

        # === ALGORITHM 3 — Device Storage Setup ===
        metrics.start_phase("Algo 3 — Storage Setup")
        print("\n[IoT] --- ALGORITHM 3 — Device Storage Setup ---")
        reg_resp = recv_msg(sock)
        e2 = base64.b64decode(reg_resp['E2'])
        h2 = base64.b64decode(reg_resp['H2'])

        e2_key = sha256(xor_bytes(pad_16(n_a), i_i))
        decrypted_e2 = aes_decrypt(e2_key, e2)

        midi = decrypted_e2[:80]
        msidi = decrypted_e2[80:144]
        n_b = decrypted_e2[144:160]
        t_3 = decrypted_e2[160:168]
        msk_enc = decrypted_e2[168:232]
        ot_enc = decrypted_e2[232:]

        h2_check = sha256(midi, msidi, n_b, t_3, msk_enc, ot_enc)
        if h2_check != h2:
            print("[IoT] ERROR: Integrity check failed on E2.")
            return None

        k_reg = sha256(pad_16(n_a), pad_16(n_b), i_i)
        ot_list_bytes = aes_decrypt(k_reg, ot_enc)
        ot_list = [ot_list_bytes[i:i+16] for i in range(0, len(ot_list_bytes), 16)]
        msk = aes_decrypt(k_reg, msk_enc)

        print("[IoT] Registration successful. Credentials decrypted.")
        metrics.end_phase()

        # === ALGORITHM 4 — Authentication Request ===
        metrics.start_phase("Algo 4 — Auth Request")
        print("\n[IoT] --- AUTHENTICATION PHASE (Algorithm 4) ---")
        ot_index = 0
        ot_j = ot_list[ot_index]
        r_1 = os.urandom(16)
        n_c = os.urandom(16)
        t_1_auth = str(123457).encode('utf-8').ljust(8, b'\x00')
        i_u = sha256(xor_bytes(i_i, pad_16(r_1)))

        m1_payload = i_u + msidi + n_c + t_1_auth + r_1 + lia_i + ot_index.to_bytes(4, 'big')
        m1 = aes_encrypt(k_reg, m1_payload)
        ha1 = sha256(i_u, msidi, n_c, t_1_auth, r_1, lia_i, ot_index.to_bytes(4, 'big'))

        send_msg(sock, {
            'Midi': base64.b64encode(midi).decode('utf-8'),
            'M1': base64.b64encode(m1).decode('utf-8'),
            'HA1': base64.b64encode(ha1).decode('utf-8')
        })
        print("[IoT] Sent M1, HA1 to AS.")
        metrics.end_phase()

        # === ALGORITHM 6 — Server Authentication by Device ===
        metrics.start_phase("Algo 6 — Server Auth")
        print("\n[IoT] --- ALGORITHM 6 — Server Auth by Device ---")
        auth_resp = recv_msg(sock)
        if not auth_resp:
            print("[IoT] ERROR: Connection closed during auth.")
            return None

        m2 = base64.b64decode(auth_resp['M2'])
        ha2 = base64.b64decode(auth_resp['HA2'])

        k_new = sha256(k_reg, ot_j, n_c, r_1)
        decrypted_m2 = aes_decrypt(k_new, m2)

        i_u_n = decrypted_m2[:32]
        midi_new = decrypted_m2[32:112]
        msidi_new = decrypted_m2[112:176]
        n_d = decrypted_m2[176:192]
        t_3_auth = decrypted_m2[192:200]
        r_2 = decrypted_m2[200:216]
        tsk = decrypted_m2[216:232]
        et_fr = decrypted_m2[232:240]
        mtid_t = decrypted_m2[240:]

        ha2_check = sha256(i_u_n, midi_new, msidi_new, n_d, t_3_auth, r_2, tsk, et_fr, mtid_t)
        if ha2_check != ha2:
            print("[IoT] ERROR: Integrity check failed on M2.")
            return None

        sk = sha256(k_new, n_d, i_u_n)
        print("[IoT] Server authenticated. Handshake COMPLETE!")
        print(f"[IoT] Session Key: {sk.hex()}")
        metrics.end_phase()

        return sk

def main():
    print("=" * 65)
    print("  IoT DEVICE CLIENT (RPi 3B+) — HARDWARE EXPERIMENT")
    print(f"  Connecting to AS at {AS_HOST}:{AS_PORT}")
    print("=" * 65)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((AS_HOST, AS_PORT))
        print(f"[IoT] Connected to AS server successfully!\n")
    except Exception as e:
        print(f"[IoT] Connection failed: {e}")
        return

    proto = IoTProtocol()
    sk = proto.execute_handshake(s)

    if sk:
        metrics.start_phase("Secure Message Exchange")
        msg = b"Hello from Raspberry Pi 3B+! Protocol verified on hardware."
        enc_msg = aes_encrypt(sk, msg)
        s.sendall(enc_msg)
        metrics.record_send(len(enc_msg))

        enc_resp = s.recv(4096)
        if enc_resp:
            metrics.record_recv(len(enc_resp))
            resp = aes_decrypt(sk, enc_resp)
            print(f"[IoT] Server Response: {resp.decode('utf-8')}")
        metrics.end_phase()

        print("\n[IoT] Protocol execution complete.")
        metrics.print_summary()

    s.close()

if __name__ == '__main__':
    main()
