"""
Authentication Server (AS) — Hardware Deployment
Full 6-Algorithm EAP-IMP Authentication Protocol with timing, energy, and communication metrics.
Runs on Laptop / Desktop (Intel Core i5 benchmarked in paper).
Directly communicates with Raspberry Pi 3B+ over Ethernet (192.168.137.1:55556).
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

HOST = '0.0.0.0'
PORT = int(os.environ.get('AS_PORT', '55556'))
AS_POWER_WATTS = float(os.environ.get('AS_POWER_WATTS', '65.0'))

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
        energy = cpu * AS_POWER_WATTS
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
        total_energy = total_cpu * AS_POWER_WATTS

        print("\n" + "=" * 70)
        print("   AUTHENTICATION SERVER (AS) — PERFORMANCE METRICS")
        print("=" * 70)
        print(f"  Power Model: {AS_POWER_WATTS} W (set AS_POWER_WATTS to change)")
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

class ASProtocol:
    def __init__(self):
        priv_path = 'as_private_key.pem'
        pub_path = 'pks.pem'
        if os.path.exists(priv_path):
            with open(priv_path, 'rb') as f:
                self.sks = serialization.load_pem_private_key(f.read(), password=None)
            self.pks = self.sks.public_key()
            print("[AS] Loaded existing server key from as_private_key.pem")
        else:
            self.sks = ec.generate_private_key(ec.SECP256R1())
            self.pks = self.sks.public_key()
            with open(priv_path, 'wb') as f:
                f.write(self.sks.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(pub_path, 'wb') as f:
                f.write(self.pks.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            print(f"[AS] Generated new persistent keypair -> {priv_path}, {pub_path}")
        self.sidi = b"SERVER_ID_000001"
        self.db = {}

    def execute_handshake(self, conn):
        metrics.start_total()

        print("\n[AS] --- PRE-REGISTRATION (Offline) ---")
        print("[AS] PKS: pre-provisioned to IoT via ./pks.pem.")
        print("[AS] PSW: generated locally on IoT device (AS never receives it).")

        # === ALGORITHM 2 — Server Registration Processing ===
        metrics.start_phase("Algo 2 — Reg Processing")
        print("\n[AS] --- REGISTRATION PHASE (Algorithm 2) ---")
        reg_req = recv_msg(conn)
        if not reg_req:
            print("[AS] ERROR: No registration request received.")
            return None
        e1 = base64.b64decode(reg_req['E1'])
        h1 = base64.b64decode(reg_req['H1'])
        eph_pub_bytes = base64.b64decode(reg_req['eph_pub'])

        eph_pub = serialization.load_pem_public_key(eph_pub_bytes)
        shared_secret = self.sks.exchange(ec.ECDH(), eph_pub)
        aes_key_e1 = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake').derive(shared_secret)

        decrypted_e1 = aes_decrypt(aes_key_e1, e1)

        i_i = decrypted_e1[:32]
        n_a = decrypted_e1[32:48]
        t_1 = decrypted_e1[48:56]
        et = decrypted_e1[56:64]
        lia_i = decrypted_e1[64:80]
        tid_i = decrypted_e1[80:96]
        w = decrypted_e1[96:112]
        p_list_mock = decrypted_e1[112:128]

        h1_check = sha256(i_i, n_a, t_1, et, lia_i, tid_i, w, p_list_mock)
        if h1_check != h1:
            print("[AS] ERROR: Integrity check failed on E1.")
            return None

        msk = sha256(n_a, self.sks.private_numbers().private_value.to_bytes(32, 'big'), i_i)
        r1 = os.urandom(16)
        midi = aes_encrypt(msk, i_i + r1)
        msidi = aes_encrypt(msk, self.sidi + r1)

        n_b = os.urandom(16)
        t_3 = str(123457).encode('utf-8').ljust(8, b'\x00')
        ot_list = [os.urandom(16) for _ in range(10)]
        ot_concat = b''.join(ot_list)

        k_reg = sha256(pad_16(n_a), pad_16(n_b), i_i)
        msk_enc = aes_encrypt(k_reg, msk)
        ot_enc = aes_encrypt(k_reg, ot_concat)

        self.db[midi] = {
            'i_i': i_i,
            'msk': msk,
            'r1': r1,
            'msidi': msidi,
            'k_reg': k_reg,
            'ot_list': ot_list,
            'used_ot': set(),
            'auth_count': 0
        }

        e2_payload = midi + msidi + n_b + t_3 + msk_enc + ot_enc
        e2_key = sha256(xor_bytes(pad_16(n_a), i_i))
        e2 = aes_encrypt(e2_key, e2_payload)
        h2 = sha256(midi, msidi, n_b, t_3, msk_enc, ot_enc)

        send_msg(conn, {
            'E2': base64.b64encode(e2).decode('utf-8'),
            'H2': base64.b64encode(h2).decode('utf-8')
        })
        print("[IoT/AS] Registration complete.")
        metrics.end_phase()

        # === ALGORITHM 5 — Device Authentication by Server ===
        metrics.start_phase("Algo 5 — Device Auth")
        print("\n[AS] --- AUTHENTICATION PHASE (Algorithm 5) ---")
        auth_req = recv_msg(conn)
        if not auth_req:
            print("[AS] ERROR: No authentication request received.")
            return None

        midi_in = base64.b64decode(auth_req['Midi'])
        m1 = base64.b64decode(auth_req['M1'])
        ha1 = base64.b64decode(auth_req['HA1'])

        if midi_in not in self.db:
            print("[AS] ERROR: MIDI not found in database.")
            return None

        rec = self.db[midi_in]
        k_reg = rec['k_reg']

        decrypted_m1 = aes_decrypt(k_reg, m1)
        i_u = decrypted_m1[:32]
        msidi_in = decrypted_m1[32:96]
        n_c = decrypted_m1[96:112]
        t_1_auth = decrypted_m1[112:120]
        r_1 = decrypted_m1[120:136]
        lia_i_in = decrypted_m1[136:152]
        ot_idx = int.from_bytes(decrypted_m1[152:156], 'big')

        ha1_check = sha256(i_u, msidi_in, n_c, t_1_auth, r_1, lia_i_in, ot_idx.to_bytes(4, 'big'))
        if ha1_check != ha1:
            print("[AS] ERROR: Integrity check failed on M1.")
            return None

        if ot_idx in rec['used_ot']:
            print("[AS] ERROR: One-Time Token already used! Replay attack detected.")
            return None
        rec['used_ot'].add(ot_idx)
        rec['auth_count'] += 1

        ot_j = rec['ot_list'][ot_idx]
        k_new = sha256(k_reg, ot_j, n_c, r_1)

        r_2 = os.urandom(16)
        n_d = os.urandom(16)
        t_3_auth = str(123458).encode('utf-8').ljust(8, b'\x00')
        tsk = os.urandom(16)
        et_fr = b"ET_FAST_"
        mtid_t = aes_encrypt(k_new, os.urandom(32))

        i_u_n = sha256(xor_bytes(rec['i_i'], pad_16(r_2)))
        midi_new = aes_encrypt(rec['msk'], rec['i_i'] + r_2)
        msidi_new = aes_encrypt(rec['msk'], self.sidi + r_2)

        m2_payload = i_u_n + midi_new + msidi_new + n_d + t_3_auth + r_2 + tsk + et_fr + mtid_t
        m2 = aes_encrypt(k_new, m2_payload)
        ha2 = sha256(i_u_n, midi_new, msidi_new, n_d, t_3_auth, r_2, tsk, et_fr, mtid_t)

        send_msg(conn, {
            'M2': base64.b64encode(m2).decode('utf-8'),
            'HA2': base64.b64encode(ha2).decode('utf-8')
        })

        sk = sha256(k_new, n_d, i_u_n)
        print("[AS] Device authenticated. Mutual Handshake COMPLETE!")
        print(f"[AS] Session Key: {sk.hex()}")

        # Update DB for fast reconnect / subsequent sessions
        del self.db[midi_in]
        self.db[midi_new] = {
            'i_i': rec['i_i'],
            'msk': rec['msk'],
            'r1': r_2,
            'msidi': msidi_new,
            'k_reg': k_new,
            'ot_list': rec['ot_list'],
            'used_ot': rec['used_ot'],
            'auth_count': rec['auth_count']
        }
        metrics.end_phase()
        return sk

def main():
    print("=" * 65)
    print("  AUTHENTICATION SERVER (AS) — HARDWARE EXPERIMENT")
    print(f"  Listening on {HOST}:{PORT}")
    print("=" * 65)

    auth = ASProtocol()

    # Pre-provision PKS to local pks.pem file
    pks_pem = auth.pks.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pks_path = 'pks.pem'
    with open(pks_path, 'wb') as f:
        f.write(pks_pem)
    print(f"[AS] Server Public Key written to {pks_path} (offline provisioning)")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)

    print(f"\n[AS] Waiting for Raspberry Pi 3B+ on port {PORT}...")

    conn, addr = server.accept()
    print(f"\n[AS] Connection accepted from {addr[0]}:{addr[1]}")

    try:
        sk = auth.execute_handshake(conn)
    except Exception as e:
        print(f"[AS] Handshake error: {e}")
        conn.close()
        server.close()
        return

    if sk:
        metrics.start_phase("Secure Message Exchange")
        try:
            enc_data = conn.recv(4096)
            if enc_data:
                metrics.record_recv(len(enc_data))
                msg = aes_decrypt(sk, enc_data)
                print(f"[AS] Received encrypted message from IoT: {msg.decode('utf-8')}")

                resp = b"Hello from Laptop AS! Secure hardware session verified."
                enc_resp = aes_encrypt(sk, resp)
                conn.sendall(enc_resp)
                metrics.record_send(len(enc_resp))
                print("[AS] Sent encrypted response to IoT.")
        except Exception as e:
            print(f"[AS] Message exchange error: {e}")
        metrics.end_phase()

        print("\n[AS] Protocol execution complete.")
        metrics.print_summary()

    conn.close()
    server.close()

if __name__ == '__main__':
    main()
