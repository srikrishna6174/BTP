# Hardware Experiment & Security Verification Reference
## EAP-IMP Protocol — Laptop (AS & AP) ↔ Raspberry Pi 3B+ (IoT)

> **Network Topology:** Direct Ethernet Link (ICS) or Windows Mobile Hotspot (2.4 GHz)  
> **Laptop IP (AS/AP):** `192.168.137.1`  
> **Raspberry Pi 3B+ (IoT):** DHCP assigned (check Windows Hotspot "Devices connected", e.g., `192.168.137.251` or `raspberrypi.local`).  
> **Ports:** AP Relay: `55555`, AS Server: `55556`  
> **Local Project Path:** `C:\Users\Srikrishna\Desktop\BTP\Implementation`

---

## Part 1: Physical Setup & Hotspot Configuration

### 1.1 Hotspot & Internet Connection Sharing (ICS) Setup
For devices (Raspberry Pi, Phone) to obtain DHCP leases and show up in the Windows Hotspot list (`Devices connected: X of 8`):
1. Open Windows **Settings** → **Network & internet** → **Mobile hotspot** → set band to **2.4 GHz**, turn **On**.
2. Press `Win + R`, type `ncpa.cpl`, press Enter.
3. Right-click your active **Wi-Fi** adapter → **Properties** → **Sharing** tab:
   - ☑ Check **"Allow other network users to connect through this computer's Internet connection"**
   - Under **"Home networking connection:"**, select **`Local Area Connection* 4`** (Microsoft Wi-Fi Direct Virtual Adapter).
   - Click **OK**.
4. Power cycle the Raspberry Pi (unplug power, wait 5 seconds, replug).
5. The Pi will automatically receive an IP lease (e.g., `192.168.137.251`) and appear in **Devices connected**.

### 1.2 SSH Access to Raspberry Pi
Run on **Laptop (PowerShell)**:
```powershell
ssh -i C:\Users\Srikrishna\.ssh\pi_key pi@192.168.137.251
```
*(Password if prompted: `raspberry`)*

### 1.3 Sync Project Files from Laptop to Raspberry Pi
Run on **Laptop (PowerShell)**:
```powershell
cd C:\Users\Srikrishna\Desktop\BTP\Implementation\hardware_experiment
scp -i C:\Users\Srikrishna\.ssh\pi_key benchmark_table4.py pks.pem iot.py expstats.py pi@192.168.137.251:~
```

---

## Part 2: Running Performance & Energy Benchmarks

### 2.1 Cryptographic Micro-Benchmark (Table 4 Replication)
Run inside the **Raspberry Pi Terminal** (`pi@raspberrypi:~ $`):
```bash
python3 benchmark_table4.py
```
*(Measures 1,000 iterations of SHA-256, HMAC, AES-256 Enc/Dec, and Point Multiplication on ARM hardware, directly comparing against Table 4 of the JISA paper).*

---

### 2.2 Full Wireless Experiment (50 Measured + 3 Warm-up Handshakes)

```
Pi (IoT Client) --Wi-Fi: 2.4 GHz--> Laptop:55555 (ap.py) --Loopback--> Laptop:55556 (as_server.py)
```

**Step 1 — Start AS Server (Laptop Terminal 1):**
```powershell
cd C:\Users\Srikrishna\Desktop\BTP\Implementation\hardware_experiment
python as_server.py
```

**Step 2 — Start AP Relay (Laptop Terminal 2):**
```powershell
cd C:\Users\Srikrishna\Desktop\BTP\Implementation\hardware_experiment
python ap.py
```

**Step 3 — Run IoT Authentication on Raspberry Pi (Pi Terminal via SSH):**
```bash
AS_HOST=192.168.137.1 AS_PORT=55555 python3 iot.py
```

**Automated All-in-One Execution (Alternative):**
On Laptop PowerShell:
```powershell
python "C:\Users\Srikrishna\.gemini\antigravity\brain\d999af57-1c6d-4271-b1a0-97c0d0ee3eeb\scratch\run_experiment.py"
```

### 2.3 Download and Review CSV Results
Download Pi results to laptop:
```powershell
scp -i C:\Users\Srikrishna\.ssh\pi_key -r pi@192.168.137.251:~/results/* C:\Users\Srikrishna\Desktop\BTP\Implementation\hardware_experiment\results_pi\
```

Output locations:
- **Raspberry Pi IoT Results:** `hardware_experiment\results_pi\iot_summary_*.csv`
- **Laptop AS Results:** `hardware_experiment\results\as_summary_*.csv`
- **Laptop AP Results:** `hardware_experiment\results\ap_summary_*.csv`

---

## Part 3: Live Security Attack Resistance Testbench (Negative Testing)

The testbench (`hardware_experiment\attack_tests.py`) directly validates implementation-level defense mechanisms against 7 adversarial attack vectors:

| Attack Vector | Strategy Tested | Expected Defense | Result |
| :--- | :--- | :--- | :---: |
| **1. Replay Attack** | Intercepting a valid authentication token $\langle MId_i, M_1, HA_1, T_1 \rangle$ and replaying it in an out-of-order session | Nonce/token consumed, out-of-order message dropped | **PASS (Blocked)** |
| **2. MAC Tampering** | Bit-flipping byte 0 of integrity MAC $HA_1$ | Cryptographic hash integrity check fails, connection aborted | **PASS (Blocked)** |
| **3. Ciphertext Tampering** | Corrupting ciphertext $M_1$ (IV flip) simulating MITM modification | AES-CBC decryption produces garbled plaintext; HMAC fails | **PASS (Blocked)** |
| **4. Rogue Device / Unknown ID** | Injecting a fabricated identity ($MId$) not present in AS database | Database lookup fails; rogue handshake dropped | **PASS (Blocked)** |
| **5. Wrong Key Encryption** | Encrypting $M_1$ with an arbitrary key (attacker lacks shared $K_{reg}$) | Server decrypts garbage; MAC verification rejects packet | **PASS (Blocked)** |
| **6. Truncated / Malformed Frame** | Sending JSON payloads with missing fields ($M_1, HA_1$ omitted) | Robust exception handling; zero state leakage | **PASS (Blocked)** |
| **7. Fuzzing / Raw Garbage** | Sending 400 bytes of raw unformatted binary noise | Protocol parser drops stream cleanly without crashing | **PASS (Blocked)** |

### 3.1 Running the Automated Negative Attack Suite
Run on Laptop PowerShell:
```powershell
cd C:\Users\Srikrishna\Desktop\BTP\Implementation\hardware_experiment
python run_and_save_attacks.py
```
*Outputs detailed per-attack logs to `hardware_experiment\attack_tests_output.txt`.*

---

### 3.2 Live In-The-Middle Attack Demonstration on Hardware (Pi ↔ MITM AP ↔ AS)

To perform attacks **live in transit** while the Raspberry Pi is communicating over Wi-Fi:

```
RPi 3B+ (IoT) --Wi-Fi--> Laptop:55555 (mitm_adversary.py) --Loopback--> Laptop:55556 (as_server.py)
```

The script `run_live_mitm_demo.py` automatically boots the AS, runs the adversarial MITM interceptor, triggers the Pi over SSH, and streams the attack and defense results from both sides in real time!

**Command 1 — In-flight Tampering with Pi Message ($M_1$ / $HA_1$):**
```powershell
cd C:\Users\Srikrishna\Desktop\BTP\Implementation\hardware_experiment
python run_live_mitm_demo.py --attack tamper-m1
```
*The MITM flips bits in the Pi's MAC $HA_1$ before forwarding to the AS. The AS detects cryptographic corruption and severs the link.*

**Command 2 — In-flight Tampering with Server Response ($M_2$ / $HA_2$):**
```powershell
python run_live_mitm_demo.py --attack tamper-m2
```
*The MITM flips bits in the server response $HA_2$ before forwarding to the Pi. The Pi detects tampering on ARM hardware and aborts.*

**Command 3 — Live Eavesdropping / Passive Sniffing:**
```powershell
python run_live_mitm_demo.py --attack eavesdrop
```
*Shows all intercepted frames ($E_1, E_2, M_1, M_2$) proving that the eavesdropper sees only dynamic pseudonyms and encrypted tokens, learning zero plaintext.*

**Command 4 — Baseline Clean Pass:**
```powershell
python run_live_mitm_demo.py --attack normal
```
*Runs a clean transparent relay through the proxy to show 100% normal handshake success.*

---

## Part 4: Formal Cryptographic Verification

Formal verification proves the protocol's mathematical soundness under the **Dolev-Yao adversary model** (where the attacker has complete control of the network communications).

### 4.1 ProVerif Verification (`protocol.pv`)
Located at: `C:\Users\Srikrishna\Desktop\BTP\Implementation`

Execute on Laptop PowerShell:
```powershell
cd C:\Users\Srikrishna\Desktop\BTP\Implementation
.\proverif.exe protocol.pv
```

#### Summary of ProVerif Formal Results:
```text
Query not attacker(secret_SK[]) is true.               --> Session Key Secrecy Verified
Query not attacker(secret_Ii[]) is true.               --> Device Pseudo-Identity Anonymity Verified
Query not attacker(secret_Na[]) is true.               --> Registration Nonce Na Secrecy Verified
Query not attacker(secret_Nb[]) is true.               --> Registration Nonce Nb Secrecy Verified
Query not attacker(secret_Kreg[]) is true.             --> Registration Key Kreg Secrecy Verified
Query inj-event(endDeviceAuth) ==> inj-event(...) true --> Injective Server Authentication by Device Verified
Query inj-event(endServerAuth) ==> inj-event(...) true --> Injective Device Authentication by Server Verified
Query event(deviceAlive) ==> true is true.             --> Protocol Executability (Device) Verified
Query event(serverAlive) ==> true is true.             --> Protocol Executability (Server) Verified
```
*Full formal proof trace saved at: `Implementation\proverif_output.txt`.*

---

### 4.2 Scyther Verification (`protocol_auth.spdl` & `protocol_reg.spdl`)
Located at: `C:\Users\Srikrishna\Desktop\BTP\Implementation`

Execute on Laptop PowerShell:
```powershell
cd C:\Users\Srikrishna\Desktop\BTP\Implementation

# 1. Verify Authentication Phase (Algorithms 4, 5, 6)
.\scyther.exe protocol_auth.spdl

# 2. Verify Registration Phase (Algorithms 1, 2, 3)
.\scyther.exe protocol_reg.spdl
```

#### Scyther Verification Results:
- **`protocol_auth.spdl`:**
  - `Secret_D1 (Nc)`, `Secret_D2 (Nd)`, `Secret_D3 (R1)`: **`Ok [proof of correctness]`**
  - `Secret_D4 (Session Key SK)`: **`Ok [proof of correctness]`**
  - `Secret_D9 (Updated Key Knew)`: **`Ok [proof of correctness]`**
  - `Nisynch_D8` (Non-injective Synchronization / Replay Protection): **`Ok [does not occur]`**
  - All AP & AS roles verified with **`Ok [proof of correctness]`**.
- **`protocol_reg.spdl`:**
  - `Secret_D1 (Na)`, `Secret_D2 (Nb)`: **`Ok [no attack within bounds]`**
  - `Secret_D3 (Pseudo-identity Ii)`: **`Ok [no attack within bounds]`**
  - `Secret_D31 (Registration Key Kreg)`: **`Ok [no attack within bounds]`**
  - `Nisynch_D7` & `Nisynch_AS7`: **`Ok [does not occur]`**

*Full Scyther outputs saved at: `Implementation\scyther_auth_output.txt` and `Implementation\scyther_reg_output.txt`.*

---

## Part 5: Comprehensive Security & Performance Summary Table

| Security / Evaluation Property | Base Paper Claim | ProVerif Proof | Scyther Proof | Live Attack Testbench |
| :--- | :--- | :---: | :---: | :---: |
| **Session Key Secrecy ($SK$)** | Proposition 5, 6 | `true` | `Ok` | **PASS (Wrong-Key Test)** |
| **Device Identity Anonymity ($I_i$)** | Proposition 2 | `true` | `Ok` | **PASS (Masking Verified)** |
| **Replay Attack Resistance** | Section 4.2 | `inj-event true` | `Nisynch Ok` | **PASS (Replay Test)** |
| **Man-in-the-Middle (Integrity)** | Section 4.3 | `inj-event true` | `Nisynch Ok` | **PASS (MAC/Ciphertext Tamper)** |
| **Rogue Device Impersonation** | Proposition 1 | `inj-event true` | `Ok` | **PASS (Unknown MIDI Test)** |
| **Fuzzing & Robustness** | Implementation | N/A | N/A | **PASS (Truncated/Garbage Test)** |
| **Hardware Execution (RPi 3B+)** | Table 4, 6 | CPU: ~10.5 ms | Energy: ~12.6 mJ | Wall: ~41 ms (Wi-Fi 2.4 GHz) |
