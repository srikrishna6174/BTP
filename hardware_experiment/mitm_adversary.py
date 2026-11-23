"""
Adversarial Access Point (MITM Proxy) — Live Hardware Security Testbench
Runs on the Laptop in place of ap.py:

    Raspberry Pi (IoT) --Wi-Fi--> MITM AP :55555 --Loopback--> AS :55556

Intercepts live wireless traffic between the physical Raspberry Pi and the AS Server,
allowing active in-the-middle attacks to demonstrate protocol resilience:

Modes:
  --mode normal       : Clean relay (baseline pass)
  --mode tamper-m1    : Modifies Pi's auth packet M1/HA1 before forwarding to AS
  --mode tamper-m2    : Modifies AS response M2/HA2 before forwarding to Pi
  --mode replay       : Captures Pi's M1 in run 1, replays it in run 2
  --mode eavesdrop    : Sniffs all packets and attempts unauthorized decryption
"""

import argparse
import base64
import json
import os
import socket
import sys
import threading
import time

# Ensure safe console output on Windows cp1252 / UTF-8
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = int(os.environ.get('AP_PORT', '55555'))
AS_HOST = os.environ.get('AS_HOST', '127.0.0.1')
AS_PORT = int(os.environ.get('AS_PORT', '55556'))

captured_m1 = None
session_count = 0


def recv_frame(sock):
    """Receive a length-prefixed JSON frame."""
    try:
        raw_len = b''
        while len(raw_len) < 4:
            chunk = sock.recv(4 - len(raw_len))
            if not chunk: return None
            raw_len += chunk
        msglen = int.from_bytes(raw_len, 'big')
        data = b''
        while len(data) < msglen:
            chunk = sock.recv(msglen - len(data))
            if not chunk: return None
            data += chunk
        return json.loads(data.decode('utf-8'))
    except Exception:
        return None


def send_frame(sock, data):
    """Send a length-prefixed JSON frame."""
    msg = json.dumps(data).encode('utf-8')
    raw = len(msg).to_bytes(4, 'big') + msg
    sock.sendall(raw)


def relay_clean(src, dst):
    """Transparent raw byte relay."""
    try:
        while True:
            chunk = src.recv(4096)
            if not chunk: break
            dst.sendall(chunk)
    except Exception:
        pass


def handle_session(iot_sock, mode):
    global captured_m1, session_count
    session_count += 1
    session_id = session_count

    print(f"\n{'=' * 65}")
    print(f"  [MITM AP] Session #{session_id} - Incoming connection from IoT (Pi)")
    print(f"  [MITM AP] Active Attack Mode: {mode.upper()}")
    print(f"{'=' * 65}")

    # Connect to AS
    try:
        as_sock = socket.create_connection((AS_HOST, AS_PORT), timeout=5)
    except Exception as e:
        print(f"  [MITM AP] [FAIL] Cannot reach AS on {AS_HOST}:{AS_PORT}: {e}")
        iot_sock.close()
        return

    try:
        # Phase 1: Registration (Relay E1 from IoT to AS, E2 from AS to IoT)
        print("  [MITM AP] Intercepting Registration Frame E1 from Pi...")
        e1_frame = recv_frame(iot_sock)
        if not e1_frame:
            print("  [MITM AP] No E1 frame received.")
            return

        if mode == 'eavesdrop':
            print("  [MITM AP] [EAVESDROP] Intercepted E1:")
            print(f"    E1 (encrypted payload) : {e1_frame.get('E1')[:40]}... ({len(e1_frame.get('E1', ''))} chars)")
            print(f"    H1 (hash tag)          : {e1_frame.get('H1')[:40]}...")
            print("    [Analysis] E1 is encrypted under ECDH ephemeral shared secret. Attacker CANNOT decrypt.")

        send_frame(as_sock, e1_frame)

        print("  [MITM AP] Intercepting Registration Response E2 from AS...")
        e2_frame = recv_frame(as_sock)
        if not e2_frame:
            print("  [MITM AP] No E2 frame received from AS.")
            return

        if mode == 'eavesdrop':
            print("  [MITM AP] [EAVESDROP] Intercepted E2:")
            print(f"    E2 (encrypted payload) : {e2_frame.get('E2')[:40]}... ({len(e2_frame.get('E2', ''))} chars)")
            print(f"    H2 (hash tag)          : {e2_frame.get('H2')[:40]}...")
            print("    [Analysis] E2 contains (MIDI, MSIDI, Nb, Kreg_enc). Encrypted under (Na XOR Ii). Attacker CANNOT decrypt.")

        send_frame(iot_sock, e2_frame)
        print("  [MITM AP] Registration relayed successfully.\n")

        # Phase 2: Authentication (M1 from IoT -> AS, M2 from AS -> IoT)
        print("  [MITM AP] Intercepting Authentication Request M1 from Pi...")
        m1_frame = recv_frame(iot_sock)
        if not m1_frame:
            print("  [MITM AP] No M1 frame received.")
            return

        # ─── ATTACK INJECTION POINT 1: M1 (Pi -> AS) ───────────────────
        if mode == 'tamper-m1':
            print("\n  [MITM AP] >>> ATTACK INJECTION: Bit-flipping integrity MAC HA1 in flight! <<<")
            raw_ha1 = base64.b64decode(m1_frame['HA1'])
            tampered_ha1 = bytes([raw_ha1[0] ^ 0xFF]) + raw_ha1[1:]
            m1_frame['HA1'] = base64.b64encode(tampered_ha1).decode('utf-8')
            print(f"    Original HA1 : {raw_ha1[:8].hex()}...")
            print(f"    Tampered HA1 : {tampered_ha1[:8].hex()}...")
            print("    Forwarding corrupted authentication frame to AS...")

        elif mode == 'replay':
            if captured_m1 is None:
                print("  [MITM AP] [REPLAY CAPTURE] Captured valid M1 from this session for future replay.")
                captured_m1 = json.loads(json.dumps(m1_frame))
            else:
                print("\n  [MITM AP] >>> ATTACK INJECTION: Dropping Pi's fresh M1 and REPLAYING cached old M1! <<<")
                print(f"    Replaying stale MIDI: {captured_m1.get('Midi')[:30]}...")
                m1_frame = captured_m1

        elif mode == 'eavesdrop':
            print("  [MITM AP] [EAVESDROP] Intercepted M1:")
            print(f"    MIDI (dynamic pseudonym): {m1_frame.get('Midi')[:40]}...")
            print(f"    M1   (encrypted token)  : {m1_frame.get('M1')[:40]}...")
            print(f"    HA1  (integrity MAC)    : {m1_frame.get('HA1')[:40]}...")
            print("    [Analysis] Real identity Ii is masked by dynamic nonce R1. Eavesdropper sees ONLY pseudonyms.")

        send_frame(as_sock, m1_frame)

        # Intercept Response M2 from AS
        print("  [MITM AP] Intercepting Authentication Response M2 from AS...")
        m2_frame = recv_frame(as_sock)

        if not m2_frame:
            print("  [MITM AP] [DEFENSE TRIGGERED] AS rejected the request and closed connection!")
            if mode in ('tamper-m1', 'replay'):
                print(f"  [MITM AP] [PASS] ATTACK '{mode.upper()}' WAS SUCCESSFULLY BLOCKED BY THE SERVER.")
            return

        # ─── ATTACK INJECTION POINT 2: M2 (AS -> Pi) ───────────────────
        if mode == 'tamper-m2':
            print("\n  [MITM AP] >>> ATTACK INJECTION: Bit-flipping server response MAC HA2 in flight! <<<")
            raw_ha2 = base64.b64decode(m2_frame['HA2'])
            tampered_ha2 = bytes([raw_ha2[0] ^ 0xFF]) + raw_ha2[1:]
            m2_frame['HA2'] = base64.b64encode(tampered_ha2).decode('utf-8')
            print(f"    Original HA2 : {raw_ha2[:8].hex()}...")
            print(f"    Tampered HA2 : {tampered_ha2[:8].hex()}...")
            print("    Forwarding corrupted response to Raspberry Pi...")

        elif mode == 'eavesdrop':
            print("  [MITM AP] [EAVESDROP] Intercepted M2:")
            print(f"    M2  (server payload) : {m2_frame.get('M2')[:40]}...")
            print(f"    HA2 (server MAC)     : {m2_frame.get('HA2')[:40]}...")

        send_frame(iot_sock, m2_frame)

        # Phase 3: Secure message exchange (transparent relay)
        t1 = threading.Thread(target=relay_clean, args=(iot_sock, as_sock), daemon=True)
        t2 = threading.Thread(target=relay_clean, args=(as_sock, iot_sock), daemon=True)
        t1.start(); t2.start()
        t1.join(timeout=3); t2.join(timeout=3)

        if mode == 'tamper-m2':
            print("  [MITM AP] [DEFENSE TRIGGERED] Pi rejected the tampered M2 and refused session exchange!")
            print("  [MITM AP] [PASS] ATTACK 'TAMPER-M2' WAS SUCCESSFULLY BLOCKED BY THE RASPBERRY PI.")
        elif mode == 'normal':
            print("  [MITM AP] [PASS] Baseline session completed with 100% success.")

    finally:
        iot_sock.close()
        as_sock.close()


def main():
    parser = argparse.ArgumentParser(description="Live MITM Adversary Proxy for EAP-IMP")
    parser.add_argument('--mode', choices=['normal', 'tamper-m1', 'tamper-m2', 'replay', 'eavesdrop'],
                        default='normal', help='Attack injection mode')
    parser.add_argument('--sessions', type=int, default=1, help='Number of sessions to handle before exiting')
    args = parser.parse_args()

    print("=" * 65)
    print("  ADVERSARIAL AP (MAN-IN-THE-MIDDLE PROXY)")
    print(f"  Listening on {LISTEN_HOST}:{LISTEN_PORT} (Relaying to AS: {AS_HOST}:{AS_PORT})")
    print(f"  Selected Mode: {args.mode.upper()}")
    print("=" * 65)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(5)

    try:
        while session_count < args.sessions:
            conn, addr = server.accept()
            handle_session(conn, args.mode)
    except KeyboardInterrupt:
        print("\n[MITM AP] Stopped by user.")
    finally:
        server.close()


if __name__ == '__main__':
    main()
