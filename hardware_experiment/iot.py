"""
IoT Device Client — Hardware Deployment
Full 6-Algorithm EAP-IMP Authentication Protocol with timing, energy, and communication metrics.
Runs on Raspberry Pi 3B+ (ARM Cortex-A53).

Performs WARMUP + RUNS sequential full handshakes (new connection and new
registration each run), then prints mean/std statistics and writes CSV files.
Start the AS with the same --runs/--warmup values.

  python3 iot.py                                   # 3 warm-up + 50 measured runs
  python3 iot.py --runs 1 --warmup 0 --verbose     # single detailed run

Target (env):  AS_HOST (default 192.168.137.1)   AS_PORT (default 55556)
  Ethernet (direct to AS):  python3 iot.py
  Wireless (via AP relay):  AS_PORT=55555 python3 iot.py
Needs expstats.py in the same folder.
"""

import argparse
import socket
import json
import base64
import hashlib
import os
import sys
import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import expstats

AS_HOST = os.environ.get('AS_HOST', '192.168.137.1')
AS_PORT = int(os.environ.get('AS_PORT', '55556'))
IOT_POWER_WATTS = float(os.environ.get('IOT_POWER_WATTS', '1.2'))  # RPi 3B+ active ~1.2W

VERBOSE = False

metrics = expstats.Metrics(IOT_POWER_WATTS)


def log(*args):
    if VERBOSE:
        print(*args)


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
    if data is None: return None
    metrics.record_recv(4 + msglen)
    return json.loads(data.decode('utf-8'))

def recvall(sock, n):
    data = bytearray()
    while len(data) < n:
        t = time.perf_counter()
        pkt = sock.recv(n - len(data))
        metrics.add_wait(time.perf_counter() - t)
        if not pkt: return None
        data.extend(pkt)
    return data

class IoTProtocol:
    def __init__(self):
        self.uidd = os.urandom(16)

    def execute_handshake(self, sock, pks):
        # === PRE-REGISTRATION ===
        log("\n[IoT] --- PRE-REGISTRATION (Offline) ---")
        psw = os.urandom(16)
        log("[IoT] PSW: generated locally on device (AS never receives it).")
        log("[IoT] PKS: pre-provisioned (loaded from pks.pem).")

        # === ALGORITHM 1 — Registration Initialization ===
        metrics.start_phase("Algo 1 — Reg Init")
        log("\n[IoT] --- REGISTRATION PHASE (Algorithm 1) ---")
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
        log("[IoT] Sent E1, H1 to AS.")
        metrics.end_phase()

        # === ALGORITHM 3 — Device Storage Setup ===
        metrics.start_phase("Algo 3 — Storage Setup")
        log("\n[IoT] --- ALGORITHM 3 — Device Storage Setup ---")
        reg_resp = recv_msg(sock)
        if not reg_resp:
            print("[IoT] ERROR: Connection closed during registration.")
            return None
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

        log("[IoT] Registration successful. Credentials decrypted.")
        metrics.end_phase()

        # === ALGORITHM 4 — Authentication Request ===
        metrics.start_phase("Algo 4 — Auth Request")
        log("\n[IoT] --- AUTHENTICATION PHASE (Algorithm 4) ---")
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
        log("[IoT] Sent M1, HA1 to AS.")
        metrics.end_phase()

        # === ALGORITHM 6 — Server Authentication by Device ===
        metrics.start_phase("Algo 6 — Server Auth")
        log("\n[IoT] --- ALGORITHM 6 — Server Auth by Device ---")
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
        log("[IoT] Server authenticated. Handshake COMPLETE!")
        log(f"[IoT] Session Key: {sk.hex()}")
        metrics.end_phase()

        return sk


def secure_exchange(s, sk):
    metrics.start_phase("Secure Message Exchange")
    try:
        msg = b"Hello from Raspberry Pi 3B+! Protocol verified on hardware."
        enc_msg = aes_encrypt(sk, msg)
        s.sendall(enc_msg)
        metrics.record_send(len(enc_msg))

        t = time.perf_counter()
        enc_resp = s.recv(4096)
        metrics.add_wait(time.perf_counter() - t)
        if not enc_resp:
            return False
        metrics.record_recv(len(enc_resp))
        resp = aes_decrypt(sk, enc_resp)
        log(f"[IoT] Server Response: {resp.decode('utf-8')}")
        return True
    finally:
        metrics.end_phase()


def load_pks(path='pks.pem'):
    while not os.path.exists(path):
        print(f"[IoT] Waiting for PKS at {path}...")
        time.sleep(1)
    with open(path, 'rb') as f:
        return serialization.load_pem_public_key(f.read())


def run_once(pks):
    """One full handshake on a fresh connection. Returns (ok, tcp_connect_ms, error)."""
    metrics.reset()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t = time.perf_counter()
    try:
        s.connect((AS_HOST, AS_PORT))
    except OSError as e:
        s.close()
        return False, None, f"connect failed: {e}"
    connect_ms = (time.perf_counter() - t) * 1000

    ok, err = False, None
    metrics.start_total()
    try:
        sk = IoTProtocol().execute_handshake(s, pks)
        if sk:
            ok = secure_exchange(s, sk)
    except Exception as e:
        err = repr(e)
    finally:
        s.close()
    metrics.finish()
    return ok, connect_ms, err


def report(rows, out_dir):
    if not rows:
        print("[IoT] No runs recorded.")
        return
    notes = [f"Power model: {IOT_POWER_WATTS} W x CPU time (set IOT_POWER_WATTS to change)."]
    expstats.print_summary("IoT DEVICE (Raspberry Pi 3B+) — STATISTICS", rows, notes)
    runs_path, summary_path = expstats.write_csvs(out_dir, 'iot', rows)
    print(f"  CSV (per run) : {runs_path}")
    print(f"  CSV (summary) : {summary_path}")


def main():
    global VERBOSE
    parser = expstats.add_common_args(argparse.ArgumentParser(description=__doc__.split('\n')[1]))
    parser.add_argument('--delay', type=float, default=0.2,
                        help='pause between runs in seconds (default %(default)s)')
    args = parser.parse_args()
    total = args.warmup + args.runs
    VERBOSE = args.verbose or total == 1

    print("=" * 65)
    print("  IoT DEVICE CLIENT (RPi 3B+) — HARDWARE EXPERIMENT")
    print(f"  Target AS/AP: {AS_HOST}:{AS_PORT}")
    print(f"  {args.warmup} warm-up + {args.runs} measured handshakes")
    print("=" * 65)

    pks = load_pks()
    rows = []
    connect_failures = 0
    try:
        for idx in range(1, total + 1):
            warm = idx <= args.warmup
            ok, connect_ms, err = run_once(pks)
            if err:
                print(f"[IoT] Run {idx}: {err}")
            if connect_ms is None:
                connect_failures += 1
                if connect_failures >= 3:
                    print("[IoT] Cannot connect to the AS/AP (3 failures in a row). "
                          "Check that it is running and AS_HOST/AS_PORT are correct.")
                    break
                time.sleep(1)
                continue
            connect_failures = 0

            row = {'run': idx, 'warmup': int(warm), 'ok': int(ok), 'tcp_connect_ms': connect_ms}
            row.update(metrics.as_row())
            rows.append(row)
            t = metrics.total
            print(f"[IoT] run {idx}/{total} {'warm-up' if warm else 'measured'} "
                  f"{'ok' if ok else 'FAILED'}  wall={t['wall_ms']:.2f} ms  cpu={t['cpu_ms']:.2f} ms  "
                  f"connect={connect_ms:.2f} ms")
            if total == 1:
                metrics.print_table("IoT DEVICE (Raspberry Pi 3B+) — PERFORMANCE METRICS")
            if idx < total:
                time.sleep(args.delay)
    except KeyboardInterrupt:
        print("\n[IoT] Interrupted — reporting runs completed so far.")

    report(rows, args.out_dir)


if __name__ == '__main__':
    main()
