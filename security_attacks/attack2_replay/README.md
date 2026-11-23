# Security Experiment: Attack 2 — Active Replay Attack

## 1. Threat Model & Objective
* **Adversary Model (Active Replay / Injection)**: The adversary records valid protocol frames exchanged during a legitimate session and retransmits them across the network in an attempt to:
  1. Bypass authentication by masquerading as the legitimate IoT device.
  2. Obtain an active, authorized Session Key ($SK$) without knowing device credentials.
  3. Induce desynchronization or replay token reuse on the Authentication Server.
* **Defense Mechanism in EAP-IMP**:
  - **One-Time Tokens ($OT_j$)**: Each authentication request consumes an unused token from the pre-shared pool. Re-using an index triggers immediate rejection.
  - **Dynamic Ephemeral Nonces ($n_c, r_1, n_d$)**: Nonces are generated fresh for every handshake. Replaying past messages causes integrity check failures or key mismatch.
  - **ECDH Forward Secrecy**: Registration requests ($E1$) are bound to ephemeral elliptic curve keypairs; replaying $E1$ does not allow the adversary to decrypt $E2$.

---

## 2. Directory Contents
* [`attacker_replay.py`](file:///d:/dev/Projects/btp/security_attacks/attack2_replay/attacker_replay.py): Active replay injection script. Reads captured frames from `attack1_eavesdropping/eavesdrop_traffic.pcap` and attempts to inject them into the live AS.

---

## 3. How to Run the Experiment

### Step 1: Start the Authentication Server
In **Laptop PowerShell Window 1**:
```powershell
cd d:\dev\Projects\btp\hardware_experiment
python as_server.py --runs 2 --warmup 0 --verbose
```
*(AS is now listening on port 55556).*

---

### Step 2: Execute the Replay Attack
In **Laptop PowerShell Window 2**:
```powershell
cd d:\dev\Projects\btp\security_attacks\attack2_replay
python attacker_replay.py
```

---

## 4. Expected Results
The script will perform two tests:
1. **Test 2A (Replaying Stale M1)**: The attacker injects the old Authentication Request ($M1, HA1$) onto a fresh connection. The AS rejects the packet and closes the socket.
2. **Test 2B (Replaying Stale E1 followed by Stale M1)**: The attacker attempts to re-register using the old $E1$ and then authenticate using the old $M1$. The AS rejects the stale nonces and drops the connection.

Both tests confirm that **Replay Attacks are completely thwarted**.
