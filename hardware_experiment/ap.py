"""
Access Point (AP) — Transparent TCP Relay (Hardware Deployment)
Runs on the Laptop together with the AS.

    IoT (Pi) --Wi-Fi--> AP :55555 --loopback--> AS :55556

The AP forwards bytes without inspecting or modifying them. For every session it
records the bytes relayed in each direction and the session duration, then prints
mean/std statistics and writes CSV files after WARMUP + RUNS sessions (or on Ctrl+C).
Use the same --runs/--warmup values as the AS and IoT sides.
"""

import argparse
import os
import socket
import threading
import time

import expstats

LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = int(os.environ.get('AP_PORT', '55555'))
AS_HOST = os.environ.get('AS_HOST', '127.0.0.1')
AS_PORT = int(os.environ.get('AS_PORT', '55556'))

rows = []
rows_lock = threading.Lock()


def relay(src, dst, label, counter):
    """Forward bytes from src to dst until either side closes."""
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
            counter[label] += len(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


def connect_to_as():
    for attempt in range(10):
        try:
            s = socket.create_connection((AS_HOST, AS_PORT), timeout=5)
            s.settimeout(None)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return s
        except OSError:
            print(f"[AP] AS not ready, retry {attempt + 1}/10 ...")
            time.sleep(2)
    return None


def handle(iot_conn, args, done):
    iot_conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    as_sock = connect_to_as()
    if not as_sock:
        print("[AP] Cannot reach AS after retries.")
        iot_conn.close()
        return

    counter = {'IoT->AS': 0, 'AS->IoT': 0}
    start = time.perf_counter()
    t1 = threading.Thread(target=relay, args=(iot_conn, as_sock, 'IoT->AS', counter), daemon=True)
    t2 = threading.Thread(target=relay, args=(as_sock, iot_conn, 'AS->IoT', counter), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    elapsed = (time.perf_counter() - start) * 1000

    with rows_lock:
        idx = len(rows) + 1
        warm = idx <= args.warmup
        rows.append({
            'run': idx,
            'warmup': int(warm),
            'ok': 1,
            'iot_to_as_B': counter['IoT->AS'],
            'as_to_iot_B': counter['AS->IoT'],
            'total_B': counter['IoT->AS'] + counter['AS->IoT'],
            'session_ms': elapsed,
        })
        total = args.warmup + args.runs
        print(f"[AP] session {idx}/{total} {'warm-up' if warm else 'measured'}  "
              f"IoT->AS={counter['IoT->AS']} B  AS->IoT={counter['AS->IoT']} B  {elapsed:.2f} ms")
        if idx == total:
            done.set()


def report(args):
    with rows_lock:
        snapshot = list(rows)
    if not snapshot:
        print("[AP] No sessions recorded.")
        return
    expstats.print_summary("ACCESS POINT (AP) — STATISTICS", snapshot,
                           ["Bytes are relayed payload bytes (TCP data, excluding TCP/IP headers)."])
    runs_path, summary_path = expstats.write_csvs(args.out_dir, 'ap', snapshot)
    print(f"  CSV (per run) : {runs_path}")
    print(f"  CSV (summary) : {summary_path}")


def main():
    parser = expstats.add_common_args(argparse.ArgumentParser(description=__doc__.split('\n')[1]))
    args = parser.parse_args()
    total = args.warmup + args.runs

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if os.name != 'nt':  # on Windows SO_REUSEADDR lets two servers share one port
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(5)
    server.settimeout(1.0)  # lets Ctrl+C interrupt accept() on Windows
    print("=" * 60)
    print("  ACCESS POINT (AP) — HARDWARE EXPERIMENT")
    print(f"  Listening on {LISTEN_HOST}:{LISTEN_PORT}  ->  AS {AS_HOST}:{AS_PORT}")
    print(f"  {args.warmup} warm-up + {args.runs} measured sessions (Ctrl+C to stop and report)")
    print("=" * 60)

    done = threading.Event()
    try:
        while not done.is_set():
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle, args=(conn, args, done), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[AP] Interrupted — reporting sessions completed so far.")
    finally:
        server.close()

    time.sleep(0.2)
    report(args)


if __name__ == '__main__':
    main()
