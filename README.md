# Formal Security Verification of WLANIoTAuth Protocol

This repository contains the formal security verification models for the authentication protocol proposed in:

> **"An improved privacy preserving authentication protocol with fast reconnection for WLAN-IOT devices"**  
> *Journal of Information Security and Applications (JISA)*, Volume 99, 2026, 104445.

Formal verification has been conducted across **three state-of-the-art cryptographic verification tools**:
1. **Tamarin Prover** (`protocol.spthy`) — Multiset rewriting and first-order logic with trace lemmas.
2. **Scyther Tool** (`protocol.spdl`) — Security Protocol Description Language evaluating trace patterns and synchronization.
3. **ProVerif** (`protocol.pv`) — Applied pi-calculus and Horn clause resolution.

---

## 1. Summary of Verification Results

| Security Property | Paper Reference | Tamarin Prover | Scyther | ProVerif |
| :--- | :--- | :---: | :---: | :---: |
| **Session Key Secrecy ($SK$)** | Propositions 5, 6 | Verified (`true`) | Verified (`Ok`) | Verified (`true`) |
| **Device Identity Anonymity ($I_i$)** | Proposition 2 | Verified (`true`) | Verified (`Ok`) | Verified (`true`) |
| **Server Authentication by Device** | Proposition 1 (part 2) | Verified (`true`) | Verified (`Nisynch`) | Verified (`inj-event true`) |
| **Device Authentication by Server** | Proposition 1 (part 1) | Verified (`true`) | Verified (`Nisynch`) | Verified (`inj-event true`) |
| **Executability / Trace Sanity** | Sanity Check | Verified (`exists-trace`) | Verified (`Ok`) | Verified (`true`) |

---

## 2. File Overview

- [`protocol.spthy`](protocol.spthy): Tamarin Prover theory modeling all phases (Pre-Registration, Registration, Storage Setup, Authentication Request, Server Authentication, Device Verification) and 6 security lemmas.
- [`protocol.spdl`](protocol.spdl): Scyther model evaluating Role $D$ (Device) and Role $S$ (Server), testing claims for secrecy, aliveness, weak agreement, non-injective agreement, and synchronization (`Nisynch`).
- [`protocol.pv`](protocol.pv): ProVerif model verifying session key secrecy, device anonymity, and injective mutual authentication under active attacker capabilities, with timestamps $T_1$ and $T_3$.

---

## 3. How to Run the Verification Tools

### A. ProVerif (`protocol.pv`)

#### WSL / Linux:
If ProVerif was installed via OPAM:
```bash
~/.opam/default/bin/proverif /mnt/d/dev/Projects/btp/protocol.pv
```
Or if installed globally in PATH:
```bash
proverif protocol.pv
```

#### Windows (Native Binary):
If using `proverif.exe` on Windows PowerShell:
```powershell
proverif.exe .\protocol.pv
```

---

### B. Scyther Tool (`protocol.spdl`)

#### WSL / Linux:
Navigate to the directory containing the compiled `scyther-linux` binary:
```bash
cd /mnt/d/dev/projects/scyther
./src/scyther-linux -a ../btp/protocol.spdl
```

#### Windows GUI / CLI:
From the Windows Command Prompt or PowerShell (in the `scyther-w32-v1.3.0` folder):
```powershell
.\scyther.exe -a D:\dev\Projects\btp\protocol.spdl
```
Or launch `Scyther.bat` (or `Scyther-gui.py`) in the Windows folder to view claims interactively.

---

### C. Tamarin Prover (`protocol.spthy`)

#### WSL / Linux:
Ensure `tamarin-prover` and `maude` are installed:
```bash
tamarin-prover --prove protocol.spthy
```

#### Interactive GUI Mode:
To inspect attack trees or proof graphs interactively in your browser:
```bash
tamarin-prover interactive protocol.spthy
```
Then open `http://127.0.0.1:3001` in your browser.

---

## 4. Key Protocol Parameters Modeled

- **$Ii$**: Device pseudo-identity derived from PUF response, password, and device unique identifier.
- **$Kreg$**: Symmetric registration key shared between Device and Authentication Server.
- **$OTj$**: One-time nonce from the pre-distributed list ($OTlist$).
- **$R_1, Nc$**: Device-generated fresh random nonces.
- **$r_2, Nd$**: Server-generated fresh random nonces.
- **$T_1, T_3$**: Timestamps enforcing message freshness and replay protection.
- **$M_1, HA_1$**: Device authentication payload and cryptographic MAC.
- **$M_2, HA_2$**: Server response payload and cryptographic MAC.
- **$SK$**: Derived session key: $h(K_{new} \parallel Nd \parallel IuN)$.
