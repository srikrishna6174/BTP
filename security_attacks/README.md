# Hardware Security Attack Experiments (EAP-IMP Protocol)

This directory contains live, empirical hardware attack simulations conducted on the physically deployed EAP-IMP testbed:
- **IoT Device**: Raspberry Pi 3B+ (ARM Cortex-A53 @ 1.2 GHz)
- **Access Point (AP)**: 2.4 GHz 802.11 Wireless Broadcast Hotspot
- **Authentication Server (AS)**: Dedicated Server on Laptop (`192.168.137.1:55556`)

---

## Directory Structure

```
security_attacks/
├── README.md                      <-- Overview & Attack Matrix
│
├── attack1_eavesdropping/         <-- [COMPLETED] Passive Wireless Eavesdropping
│   ├── README.md                  <-- Threat model & step-by-step instructions
│   ├── pcap_sniffer.py            <-- Raw AF_PACKET sniffer for Raspberry Pi
│   ├── eavesdrop_traffic.pcap     <-- Recorded physical 802.11 Wi-Fi frames
│   └── analyze_eavesdrop.py       <-- Automated forensic audit tool
│
├── attack2_replay/                <-- [IN PROGRESS] Replay Attack on Authentication Tokens
│   ├── README.md                  <-- Attack design, token consumption & instructions
│   └── attacker_replay.py         <-- Active replay adversary script
│
├── attack3_mitm_tampering/        <-- [COMPLETED] Man-in-the-Middle Integrity Tampering
│   ├── README.md                  <-- Threat model, mathematical proof & instructions
│   ├── mitm_adversary.py          <-- Live active MITM proxy (bit-flipping / eavesdropping)
│   └── run_live_mitm_demo.py      <-- 1-click live orchestrator over Wi-Fi / SSH
├── attack4_impersonation/         <-- [PLANNED] Fake Device Impersonation Attack
└── attack5_dos_flood/             <-- [PLANNED] TCP SYN / Request Flooding Attack
```

---

## Attack Verification Matrix

| Attack # | Attack Name | Adversary Type | Security Property Verified | Status |
|---|---|---|---|---|
| **Attack 1** | **Passive Eavesdropping** | Passive (Sniffer) | Confidentiality & Untraceability | **PASSED (Thwarted)** |
| **Attack 2** | **Replay Attack** | Active (Injector) | Replay Resistance (One-Time Tokens) | **In Progress** |
| **Attack 3** | **MITM Tampering** | Active (Interception) | Message Integrity ($H1, HA1, HA2$) | **PASSED (Thwarted)** |
| **Attack 4** | **Impersonation** | Active (Fake IoT) | Mutual Authentication & PUF Binding | Planned |
| **Attack 5** | **DoS Flooding** | Network (Resource) | Graceful Degradation & Handshake Limits | Planned |
