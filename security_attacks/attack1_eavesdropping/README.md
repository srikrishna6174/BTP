# Security Experiment: Attack 1 — Passive Wireless Eavesdropping

## 1. Threat Model & Objective
* **Adversary Model (Dolev-Yao / Eavesdropper)**: An adversary is connected to the same wireless medium (laptop Wi-Fi hotspot) or listening to raw 802.11 frames over the air using a packet sniffer.
* **Objective**: Intercept on-the-wire communication between the **IoT Device (Raspberry Pi)** and **Authentication Server (AS Laptop)** to attempt:
  1. Recovering plaintext credentials ($PSW$, Device $UID_d$, Pre-shared key $PKS$).
  2. Snooping on application-layer data (Session Key $SK$, secure test messages).
  3. Tracking device identity across protocol messages.
* **Defense Mechanism**:
  - Ephemeral Elliptic Curve Diffie-Hellman (ECDH) key exchange over Curve SECP256R1.
  - AES-256-CBC authenticated encryption with random IVs.
  - Dynamic pseudo-identity masking ($MIDI$, $MSIDI$) using PUF simulation.

---

## 2. Step-by-Step Execution Guide

### Step 1: Start Packet Capture on Raspberry Pi
Open **Raspberry Pi Terminal** (`pi@raspberrypi:~ $`):
```bash
sudo tcpdump -i wlan0 -s 0 -w eavesdrop_traffic.pcap port 55556
```
*(tcpdump is now actively sniffing all incoming and outgoing frames on port 55556).*

---

### Step 2: Start the Authentication Server on Laptop
Open **Laptop PowerShell Window 1**:
```powershell
cd d:\dev\Projects\btp\hardware_experiment
python as_server.py --runs 1 --warmup 0 --verbose
```
*(AS is listening on port 55556).*

---

### Step 3: Execute Protocol Handshake on Raspberry Pi
Open a **second Raspberry Pi Terminal** (or run after starting tcpdump):
```bash
python3 iot.py --runs 1 --warmup 0 --verbose
```
*(The complete 4-algorithm protocol handshake and secure test message exchange will execute).*

---

### Step 4: Stop Packet Capture on Raspberry Pi
In the first Raspberry Pi terminal (where `tcpdump` is running):
* Press **`Ctrl + C`** to stop capturing.
* You will see: `X packets captured, X packets received by filter`.

---

### Step 5: Transfer Capture File from Pi to Laptop
Run in **Laptop PowerShell**:
```powershell
scp pi@192.168.137.XXX:~/eavesdrop_traffic.pcap d:\dev\Projects\btp\security_attacks\
```
*(Replace `192.168.137.XXX` with your Pi's Wi-Fi IP).*

---

## 3. Analyzing the Captured Data

### Method A: Automated Python Security Audit
Run inside `d:\dev\Projects\btp\security_attacks`:
```powershell
cd d:\dev\Projects\btp\security_attacks
python analyze_eavesdrop.py eavesdrop_traffic.pcap
```

**What it will output:**
1. Complete list of all intercepted packets and their payloads.
2. Structure of captured JSON messages showing ciphertexts ($E1, E2, M1, M2$) and integrity tags ($H1, H2, HA1, HA2$).
3. **Confidentiality Audit**: Scans raw bytes for plaintext strings (such as `"Hello from Raspberry Pi"`, device identities, or server secrets) and confirms they are **[SAFE] NOT EXPOSED**.

---

### Method B: Graphical Wireshark Inspection
1. Open Wireshark on your laptop.
2. Open `eavesdrop_traffic.pcap`.
3. Filter by `tcp.port == 55556`.
4. Right-click any packet → **Follow** → **TCP Stream**.
5. **Observation**:
   - You will see JSON objects containing base64 ciphertext fields.
   - None of the session keys, passwords, or test messages appear in plaintext.
   - Take a screenshot of the TCP stream window for your project report!

