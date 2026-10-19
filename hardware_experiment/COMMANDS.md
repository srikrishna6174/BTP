# Hardware Experiment Command Reference
## EAP-IMP Protocol — Laptop (AS) ↔ Raspberry Pi 3B+ (IoT)

> **Network Topology:** Direct Ethernet Link  
> **Laptop IP (AS):** `192.168.137.1`  
> **Raspberry Pi 3B+ IP (IoT):** `192.168.137.204` (Port: `55556`)

---

### Step 1: Connect to Raspberry Pi via SSH
Run on **Laptop (PowerShell Window 1)**:
```powershell
ssh pi@192.168.137.204
```
*(Enter password when prompted, e.g., `raspberry`)*

---

### Step 2: Install Python Cryptography on Raspberry Pi
Run inside the **Raspberry Pi Terminal** (`pi@raspberrypi:~ $`):
```bash
sudo apt update && sudo apt install -y python3-cryptography python3-pip
```

---

### Step 3: Copy Project Files from Laptop to Raspberry Pi
Run on **Laptop (PowerShell Window 2)**:
```powershell
scp d:\dev\Projects\btp\hardware_experiment\benchmark_table4.py pi@192.168.137.204:~
scp d:\dev\Projects\btp\hardware_experiment\pks.pem pi@192.168.137.204:~
scp d:\dev\Projects\btp\hardware_experiment\iot.py pi@192.168.137.204:~
```

---

### Step 4: Run Table 4 Cryptographic Micro-Benchmark
Run inside the **Raspberry Pi Terminal** (`pi@raspberrypi:~ $`):
```bash
python3 benchmark_table4.py
```
*(Measures 1,000 iterations of SHA-256, HMAC, AES-256 Enc/Dec, and Point Multiplication, comparing directly against Table 4 of the paper).*

---

### Step 5: Start the Authentication Server (AS) on Laptop
Run on **Laptop (PowerShell Window 2)**:
```powershell
cd d:\dev\Projects\btp\hardware_experiment
python as_server.py
```
*(Listens on port `55556` for the Raspberry Pi connection).*

---

### Step 6: Run Live IoT Authentication on Raspberry Pi
Run inside the **Raspberry Pi Terminal** (`pi@raspberrypi:~ $`):
```bash
python3 iot.py
```
*(Performs complete 6-algorithm authentication, establishes session key SK, exchanges encrypted test message, and outputs timing/energy summary).*

---

### Fast Re-run (Subsequent Tests)
To run the authentication test again:
1. **Laptop:** `python as_server.py`
2. **Raspberry Pi:** `python3 iot.py`
