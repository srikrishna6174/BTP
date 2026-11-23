"""
Automated Live MITM Attack & Defense Demonstration Runner
Connects to the Raspberry Pi over Wi-Fi and executes live Man-in-the-Middle attacks!

Usage:
  python run_live_mitm_demo.py --attack tamper-m1
  python run_live_mitm_demo.py --attack tamper-m2
  python run_live_mitm_demo.py --attack eavesdrop
  python run_live_mitm_demo.py --attack normal
"""

import argparse
import os
import subprocess
import sys
import time
import paramiko

# Ensure safe console output on Windows cp1252 / UTF-8
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

BASE_DIR = r"C:\Users\Srikrishna\Desktop\BTP\Implementation\hardware_experiment"
PI_HOST = "192.168.137.251"
PI_USER = "pi"
KEY_PATH = r"C:\Users\Srikrishna\.ssh\pi_key"


def main():
    parser = argparse.ArgumentParser(description="Live MITM Hardware Attack Demonstration")
    parser.add_argument('--attack', choices=['tamper-m1', 'tamper-m2', 'eavesdrop', 'normal'],
                        default='tamper-m1',
                        help='Attack to execute in flight between Pi and AS')
    args = parser.parse_args()

    print("=" * 65)
    print("  LIVE IN-THE-MIDDLE ATTACK EXPERIMENT (PI <--> LAPTOP)")
    print(f"  Target Attack: {args.attack.upper()}")
    print("=" * 65)

    # Step 1: Check SSH to Raspberry Pi with retry
    print(f"\n[1/4] Checking Raspberry Pi at {PI_HOST} over Wi-Fi...")
    key = paramiko.RSAKey.from_private_key_file(KEY_PATH)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connected = False
    for attempt in range(1, 4):
        try:
            ssh.connect(PI_HOST, username=PI_USER, pkey=key, timeout=8)
            print("  Pi is online and connected to Hotspot! [OK]")
            connected = True
            break
        except Exception as e:
            if attempt < 3:
                time.sleep(1.5)
            else:
                print(f"  [FAIL] Cannot reach Pi at {PI_HOST} ({e}).")
                print("\n  👉 Please ensure:")
                print("     1. Windows Mobile Hotspot is turned ON in Settings.")
                print("     2. Raspberry Pi is powered ON and showing in 'Devices connected'.")
                print("     (Unplug and replug Pi power if it was sitting idle).")
                sys.exit(1)

    # Step 2: Start AS in background
    print("\n[2/4] Starting Authentication Server on port 55556...")
    as_proc = subprocess.Popen(
        [sys.executable, "as_server.py", "--runs", "1", "--warmup", "0"],
        cwd=BASE_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    time.sleep(1.5)

    # Step 3: Start MITM Adversary Proxy on port 55555
    print(f"\n[3/4] Starting Adversarial AP Proxy on port 55555 (Mode: {args.attack})...")
    mitm_proc = subprocess.Popen(
        [sys.executable, "mitm_adversary.py", "--mode", args.attack, "--sessions", "1"],
        cwd=BASE_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    time.sleep(1.5)

    # Step 4: Trigger IoT on the Raspberry Pi
    print(f"\n[4/4] Triggering live authentication run on Raspberry Pi (wlan0)...")
    cmd = "AS_HOST=192.168.137.1 AS_PORT=55555 python3 iot.py --runs 1 --warmup 0 --verbose"
    stdin, stdout, stderr = ssh.exec_command(cmd, get_pty=True)

    print("\n" + "─" * 65)
    print("  LIVE STREAM FROM RASPBERRY PI TERMINAL:")
    print("─" * 65)
    for line in iter(stdout.readline, ""):
        print(f"  [Pi] {line.rstrip()}")

    ssh.close()

    # Capture outputs from MITM and AS
    mitm_out, _ = mitm_proc.communicate(timeout=5)
    as_out, _ = as_proc.communicate(timeout=5)

    print("\n" + "─" * 65)
    print("  LIVE STREAM FROM ADVERSARY / MITM PROXY:")
    print("─" * 65)
    print(mitm_out)

    print("\n" + "─" * 65)
    print("  LIVE STREAM FROM AUTHENTICATION SERVER:")
    print("─" * 65)
    print(as_out)

    print("=" * 65)
    print("  LIVE ATTACK DEMONSTRATION COMPLETE")
    print("=" * 65)


if __name__ == '__main__':
    main()
