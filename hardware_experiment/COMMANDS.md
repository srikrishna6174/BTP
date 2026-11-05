# Hardware Experiment Command Reference
## EAP-IMP Protocol — Laptop (AS) ↔ Raspberry Pi 3B+ (IoT)

> **Network Topology:** Direct Ethernet Link (ICS) or Windows Mobile Hotspot  
> **Laptop IP (AS):** `192.168.137.1` (fixed by Windows ICS / hotspot)  
> **Raspberry Pi 3B+ (IoT):** `raspberrypi.local` (its IP is assigned by DHCP and can change, so always use the hostname). AS Port: `55556`
>
> **If `raspberrypi.local` does not resolve:** run `ipconfig /flushdns`, wait ~1 min after the Pi boots, then retry. As a fallback, find the current IP with `arp -a | findstr 192.168.137` (or the hotspot's "Devices connected" list) and use it in place of `raspberrypi.local`.

---

### Step 1: Connect to Raspberry Pi via SSH
Run on **Laptop (PowerShell Window 1)**:
```powershell
ssh pi@raspberrypi.local
```
*(Enter the password you set in Raspberry Pi Imager. If SSH warns that the host key changed, run `ssh-keygen -R raspberrypi.local` and retry.)*

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
scp d:\dev\Projects\btp\hardware_experiment\benchmark_table4.py pi@raspberrypi.local:~
scp d:\dev\Projects\btp\hardware_experiment\pks.pem pi@raspberrypi.local:~
scp d:\dev\Projects\btp\hardware_experiment\iot.py pi@raspberrypi.local:~
scp d:\dev\Projects\btp\hardware_experiment\expstats.py pi@raspberrypi.local:~
```
*(`iot.py` imports `expstats.py`, so copy both. Re-copy them after any change.)*
*(Run these on the **laptop**, not inside the Pi's SSH session.)*

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
*(Listens on port `55556`. It serves **3 warm-up + 50 measured** handshakes, one new connection each, then prints mean/std statistics and writes CSVs to `results\`. Press Ctrl+C to stop early and still get a report. Use `--runs N --warmup W` to change the counts; the Pi must use the same values. `python as_server.py --runs 1 --warmup 0 --verbose` reproduces the old single detailed run.)*

---

### Step 6: Run Live IoT Authentication on Raspberry Pi
Run inside the **Raspberry Pi Terminal** (`pi@raspberrypi:~ $`):
```bash
python3 iot.py
```
*(Performs 3 warm-up + 50 measured complete 6-algorithm authentications, each with a fresh connection and registration, exchanges an encrypted test message every run, then prints mean/std statistics and writes `results/iot_runs_*.csv` and `results/iot_summary_*.csv`. Use `--runs N --warmup W` to match the AS; `python3 iot.py --runs 1 --warmup 0 --verbose` gives the old single detailed run. To sort the time columns: `wall_ms` includes waiting on the network, `cpu_ms` is process CPU time, `active_ms` is wall time minus time blocked in receive.)*

---

### Fast Re-run (Subsequent Tests)
To run the authentication test again:
1. **Laptop:** `python as_server.py`
2. **Raspberry Pi:** `python3 iot.py`

Each pair of commands now runs the whole 53-handshake series. Copy the Pi's CSVs back to the laptop with:
```powershell
scp -r pi@raspberrypi.local:~/results d:\dev\Projects\btp\hardware_experiment\results_pi
```

---

## Wireless Experiment (Wi-Fi hotspot, AP + AS on the Laptop)

```
Pi (IoT) --Wi-Fi--> Laptop:55555 (ap.py) --loopback--> Laptop:55556 (as_server.py)
```

### W1: One-time Pi setup (over Ethernet, ICS on)
Save the hotspot profile on the Pi (the hotspot does not need to be on yet):
```bash
sudo nmcli connection add type wifi con-name hotspot ifname wlan0 ssid "LAPTOP-L30MEOST 1427" wifi-sec.key-mgmt wpa-psk wifi-sec.psk '<HOTSPOT_PASSWORD>' connection.autoconnect yes connection.autoconnect-priority 100
```
`ap.py` runs on the laptop, so nothing extra needs copying to the Pi.

### W2: Switch the laptop to the hotspot
Windows allows only one sharing session (both use `192.168.137.1`):
1. `ncpa.cpl` -> Wi-Fi / Ethernet -> Properties -> Sharing -> **untick** sharing.
2. Settings -> Network & internet -> **Mobile hotspot** -> share from Wi-Fi, band **2.4 GHz** -> turn **On**.
3. **Power-cycle the Pi** (unplug power, replug) *while the hotspot is on*, then unplug the Ethernet cable.
4. Confirm it joined: the hotspot page's "Devices connected" shows `raspberrypi`, and `ping raspberrypi.local` replies from the laptop.
5. `ssh pi@raspberrypi.local`, then verify on the Pi that only Wi-Fi is active:
   ```bash
   nmcli -t -f NAME,DEVICE connection show --active   # expect: hotspot  wlan0 (no eth0)
   sudo iw dev wlan0 set power_save off                # steadier latency
   ```

### W3: Open the AP port in Windows Firewall (once, admin PowerShell)
```powershell
New-NetFirewallRule -DisplayName "EAP-IMP AP" -Direction Inbound -Protocol TCP -LocalPort 55555 -Action Allow -Profile Any
```
Port `55556` (AS) only receives local connections from the AP and needs no rule.

### W4: Run the experiment
**Laptop, PowerShell window 1 (AS):**
```powershell
cd d:\dev\Projects\btp\hardware_experiment
python as_server.py
```
**Laptop, PowerShell window 2 (AP):**
```powershell
cd d:\dev\Projects\btp\hardware_experiment
python ap.py
```
**Raspberry Pi (connect to the AP port instead of the AS port):**
```bash
AS_HOST=192.168.137.1 AS_PORT=55555 python3 iot.py
```
Start `as_server.py` and `ap.py` with the same `--runs/--warmup` values as `iot.py` (defaults 50 measured + 3 warm-up on all three). Each exits and reports after the last handshake. Start the **AS first, then the AP, then the Pi**. To repeat, restart all three.

> **Before starting:** make sure no old `ap.py` / `as_server.py` is still running (`Get-CimInstance Win32_Process -Filter "Name='python.exe'" | Select ProcessId,CommandLine`). A stale instance holding port 55555 or 55556 will now make the new one fail with "address already in use" instead of silently sharing the port.

### W5: Collect the results
Record the same figures as the Ethernet run, from three places:
| Source | Output | What it contains |
|---|---|---|
| Pi (`iot.py`) | `results/iot_summary_*.csv` (on the Pi) | per-phase wall, CPU, active (ms), energy (mJ), bytes; `tcp_connect_ms` |
| Laptop AS (`as_server.py`) | `results\as_summary_*.csv` | same per-phase columns for the AS |
| Laptop AP (`ap.py`) | `results\ap_summary_*.csv` | bytes relayed each way, session time (ms) |

Each `*_summary` file holds mean, std, min, median and max over the 50 measured runs; `*_runs` holds every run (warm-ups flagged `warmup=1`).

Compare **CPU time** (Pi) against the Ethernet run (should be about the same). **Wall time** will be higher and more variable because every message crosses Wi-Fi. On the Windows laptop use `active_ms`, not `cpu_ms`: the Windows CPU clock only advances every ~15.6 ms, so per-phase CPU there is meaningless.

### Troubleshooting
- **Pi cannot connect (timeout):** firewall rule (W3) missing, or `ap.py` is not running.
- **"Connection refused":** `ap.py` is not running on the laptop.
- **`[AP] AS not ready`:** `as_server.py` is not running or already finished; restart it.
- **Pi not on the hotspot:** it must *boot* while the hotspot is on; power-cycle it. A running Pi will not switch networks on its own.
