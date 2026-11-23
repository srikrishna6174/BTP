#!/usr/bin/env python3
"""
Zero-dependency raw socket packet sniffer and PCAP writer for Linux (Raspberry Pi).
Captures raw Ethernet/IP/TCP frames on port 55556 without requiring tcpdump or internet.
Produces standard .pcap files compatible with Wireshark.
"""

import socket
import struct
import time
import sys
import os

FILTER_PORT = 55556
OUTPUT_FILE = "eavesdrop_traffic.pcap"

# PCAP Global Header (Standard libpcap format, Ethernet DLT = 1)
PCAP_GLOBAL_HEADER = struct.pack(
    '<IHHIIII',
    0xa1b2c3d4,  # magic number (little endian)
    2, 4,        # version 2.4
    0,           # thiszone (GMT)
    0,           # sigfigs
    65535,       # snaplen (max packet length)
    1            # network link-layer (1 = Ethernet)
)

def main():
    if os.geteuid() != 0:
        print("[!] Error: Raw packet sniffing requires root privileges.")
        print("[!] Please run: sudo python3 pcap_sniffer.py")
        sys.exit(1)

    print("=" * 65)
    print(f"  OFFLINE PACKET SNIFFER (Listening on port {FILTER_PORT})")
    print(f"  Saving capture to: {OUTPUT_FILE}")
    print("  Press Ctrl+C when finished capturing.")
    print("=" * 65)

    # Open raw Ethernet socket
    # 0x0003 = ETH_P_ALL (all protocols)
    try:
        raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except Exception as e:
        print(f"[!] Failed to open raw socket: {e}")
        sys.exit(1)

    count = 0
    with open(OUTPUT_FILE, 'wb') as pcap:
        pcap.write(PCAP_GLOBAL_HEADER)
        pcap.flush()

        try:
            while True:
                data, _ = raw_sock.recvfrom(65535)
                # Need at least Ethernet (14) + IPv4 (20) + TCP (20) = 54 bytes
                if len(data) < 54:
                    continue

                # Ethernet Type: 0x0800 for IPv4
                eth_proto = struct.unpack('!H', data[12:14])[0]
                if eth_proto != 0x0800:
                    continue

                # IP Header
                ip_header = data[14:34]
                ip_proto = ip_header[9]
                if ip_proto != 6:  # TCP
                    continue

                ihl = (ip_header[0] & 0x0F) * 4
                tcp_header = data[14 + ihl : 14 + ihl + 20]
                src_port, dst_port = struct.unpack('!HH', tcp_header[:4])

                # Filter on target port
                if src_port == FILTER_PORT or dst_port == FILTER_PORT:
                    now = time.time()
                    sec = int(now)
                    usec = int((now - sec) * 1e6)
                    pkt_len = len(data)

                    # Write PCAP Packet Record Header: ts_sec, ts_usec, incl_len, orig_len
                    rec_header = struct.pack('<IIII', sec, usec, pkt_len, pkt_len)
                    pcap.write(rec_header + data)
                    pcap.flush()

                    count += 1
                    direction = "IoT -> AS" if dst_port == FILTER_PORT else "AS -> IoT"
                    print(f"  [Sniffed #{count}] {direction} ({pkt_len} bytes)")

        except KeyboardInterrupt:
            print(f"\n[✓] Sniffing stopped. {count} packets saved to '{OUTPUT_FILE}'.")

if __name__ == '__main__':
    main()

