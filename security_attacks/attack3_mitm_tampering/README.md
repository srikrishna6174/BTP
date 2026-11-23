# Security Experiment: Attack 3 — Man-in-the-Middle (MITM) Integrity Tampering

## 1. Threat Model & Objective

* **Adversary Model (Active In-the-Middle / Rogue AP)**:
  An adversary establishes a rogue Access Point or compromises an intermediate router along the wireless forwarding path between the **IoT Device (Raspberry Pi 3B+)** and the **Authentication Server (AS Laptop)**.
  
  ```
  [Physical Raspberry Pi] ──Wi-Fi──> [MITM Adversary Proxy :55555] ──Loopback──> [AS Server :55556]
  ```

* **Attacker Capabilities**:
  1. Full packet interception on port `55555`.
  2. Ability to inject, drop, modify, or bit-flip any byte in protocol frames ($E1, E2, M1, M2$).
  3. Ability to forward corrupted frames to either endpoint.

* **Objective**:
  - Bypass authentication by modifying tokens or credentials in flight.
  - Deceive the AS into accepting an unauthorized or forged session.
  - Deceive the IoT device into accepting a forged server response.

* **Defense Mechanisms in EAP-IMP**:
  - **Cryptographic HMAC / SHA-256 MACs**:
    - **Device Authentication Tag**: $HA_1 = \text{HMAC}(K_{auth}, M_1 \parallel MIDI \parallel \dots)$
    - **Server Authentication Tag**: $HA_2 = \text{HMAC}(K_{auth}, M_2 \parallel \dots)$
  - **Avalanche Effect & Cryptographic Integrity**: Any single-bit alteration in transit causes the computed MAC to mismatch the expected tag with probability $1 - 2^{-256} \approx 1$.
  - **Fail-Safe Protocol Abort**: Upon MAC verification failure, the receiving entity immediately terminates the TCP connection and purges ephemeral state. No session key is established.

---

## 2. Directory Contents

* [`mitm_adversary.py`](file:///C:/Users/Srikrishna/Desktop/BTP/Implementation/security_attacks/attack3_mitm_tampering/mitm_adversary.py):
  Active proxy listening on port `55555` and relaying to the AS on `55556`. Features 4 operational modes:
  - `--mode tamper-m1`: Bit-flips device authentication MAC $HA_1$ before forwarding to the AS.
  - `--mode tamper-m2`: Bit-flips server authentication MAC $HA_2$ before forwarding to the Raspberry Pi.
  - `--mode replay`: Captures valid $M_1$ from run 1 and attempts to inject it into run 2.
  - `--mode eavesdrop`: Inspects payload data and attempts unauthorized decryption.
  - `--mode normal`: Transparent relay demonstrating baseline success.

* [`run_live_mitm_demo.py`](file:///C:/Users/Srikrishna/Desktop/BTP/Implementation/security_attacks/attack3_mitm_tampering/run_live_mitm_demo.py):
  Automated test runner that coordinates all 3 nodes over Wi-Fi via SSH and outputs synchronized live execution streams.

---

## 3. Step-by-Step Execution Guide

### Method A: Automated One-Click Runner (Recommended)

Run directly in PowerShell:
```powershell
cd C:\Users\Srikrishna\Desktop\BTP\Implementation\security_attacks\attack3_mitm_tampering
python run_live_mitm_demo.py --attack tamper-m1
```

To test server-side response tampering:
```powershell
python run_live_mitm_demo.py --attack tamper-m2
```

---

### Method B: Manual 3-Terminal Execution

#### Terminal 1 (Laptop): Start Authentication Server
```powershell
cd C:\Users\Srikrishna\Desktop\BTP\Implementation\hardware_experiment
python as_server.py --runs 1 --warmup 0 --verbose
```
*(AS listens on port 55556).*

#### Terminal 2 (Laptop): Start Adversarial Proxy
```powershell
cd C:\Users\Srikrishna\Desktop\BTP\Implementation\security_attacks\attack3_mitm_tampering
python mitm_adversary.py --mode tamper-m1 --sessions 1
```
*(Proxy listens on port 55555 and forwards to 55556).*

#### Terminal 3 (Raspberry Pi over SSH): Trigger Protocol Run
```bash
ssh -i ~/.ssh/pi_key pi@192.168.137.251
AS_HOST=192.168.137.1 AS_PORT=55555 python3 iot.py --runs 1 --warmup 0 --verbose
```

---

## 4. Empirical Test Results & Verification

### Test 3A: Tampering with $M_1 / HA_1$ (Device to Server)

```
[MITM AP] >>> ATTACK INJECTION: Bit-flipping integrity MAC HA1 in flight! <<<
  Original HA1 : 3a7f8b9c...
  Tampered HA1 : c57f8b9c...
  Forwarding corrupted authentication frame to AS...

[AS Server] --- ALGORITHM 5 - IoT Device Auth by Server ---
[AS Server] [SECURITY FAILURE] HMAC Verification FAILED!
[AS Server] Computed HA1 does not match received HA1.
[AS Server] Connection dropped. Handshake aborted.

[MITM AP] [DEFENSE TRIGGERED] AS rejected the request and closed connection!
[MITM AP] [PASS] ATTACK 'TAMPER-M1' WAS SUCCESSFULLY BLOCKED BY THE SERVER.
```

### Test 3B: Tampering with $M_2 / HA_2$ (Server to Device)

```
[MITM AP] >>> ATTACK INJECTION: Bit-flipping server response MAC HA2 in flight! <<<
  Original HA2 : 91e2b460...
  Tampered HA2 : 6ee2b460...
  Forwarding corrupted response to Raspberry Pi...

[Pi Client] --- ALGORITHM 6 - Server Auth by Device ---
[Pi Client] [SECURITY FAILURE] Server MAC HA2 Verification FAILED!
[Pi Client] Rejecting session key and terminating connection.

[MITM AP] [DEFENSE TRIGGERED] Pi rejected the tampered M2 and refused session exchange!
[MITM AP] [PASS] ATTACK 'TAMPER-M2' WAS SUCCESSFULLY BLOCKED BY THE RASPBERRY PI.
```

---

## 5. Formal Verification Cross-Reference

This empirical attack validation directly corroborates the formal verification models in:
- **ProVerif** (`formal_verification/proverif/protocol.pv`): All 9 authentication and secrecy queries verified as `RESULT ... is true`.
- **Scyther** (`formal_verification/scyther/protocol_auth.spdl`): All secrecy and mutual agreement claims verified as `Ok : No attacks`.
