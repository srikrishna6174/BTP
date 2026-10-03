"""
Access Point (AP) — Transparent TCP Relay
Bridges IoT and AS without inspecting or modifying any messages.
"""

import socket                                                      # For TCP socket programming (server + client)
import threading                                                    # For running two relay threads (bidirectional)
import os                                                           # For reading environment variables
import time                                                         # For sleep() delays during retries

IOT_LISTEN_PORT = 55555                                             # Port where IoT devices connect to AP
AS_HOST = os.environ.get('AS_HOST', 'as_server')                    # Hostname of Auth Server (Docker DNS resolves this)
AS_PORT = int(os.environ.get('AS_PORT', '55556'))                   # Port of Auth Server


def relay(src, dst, label):                                         # Forwards all bytes from src socket → dst socket
    """Forward all bytes from src to dst."""
    try:
        while True:                                                 # Keep forwarding until connection closes
            data = src.recv(4096)                                   # Read up to 4KB at a time from source
            if not data:                                            # Empty data = connection closed by peer
                print(f"[AP] {label}: closed.")
                break
            dst.sendall(data)                                       # Forward ALL bytes to destination (no modification!)
    except (ConnectionResetError, BrokenPipeError, OSError) as e:   # Handle network errors gracefully
        print(f"[AP] {label}: ended — {e}")
    finally:                                                        # Cleanup: close both sockets no matter what
        try: src.close()
        except OSError: pass
        try: dst.close()
        except OSError: pass


def wait_for_as():                                                  # Blocks until AS container is reachable via DNS
    """Wait for AS by resolving its hostname (no TCP connect to avoid
    the probe being consumed by AS's accept loop)."""
    print(f"[AP] Waiting for AS at {AS_HOST}:{AS_PORT} ...")
    while True:                                                     # Retry loop until AS hostname resolves
        try:
            socket.getaddrinfo(AS_HOST, AS_PORT)                    # DNS lookup only — does NOT open TCP connection
            print("[AP] AS hostname resolved. Ready.")              # Why not TCP? A probe would be consumed by AS's accept()
            return
        except socket.gaierror:                                     # DNS resolution failed — AS not up yet
            time.sleep(1)                                           # Wait 1 second before retrying


def connect_to_as():                                                # Opens TCP connection to AS with up to 10 retries
    """Connect to AS with retries."""
    for attempt in range(10):                                       # Try 10 times max
        try:
            as_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create new TCP socket
            as_sock.connect((AS_HOST, AS_PORT))                     # Connect to AS on port 55556
            return as_sock                                          # Success — return connected socket
        except (ConnectionRefusedError, OSError):                   # AS not ready yet
            print(f"[AP] AS not ready, retry {attempt+1}/10 ...")
            time.sleep(2)                                           # Wait 2 seconds between retries
    return None                                                     # All retries exhausted — return None


def main():                                                         # Main entry point — accept IoT, relay to AS
    wait_for_as()                                                   # Step 1: Wait until AS is reachable
    # Give AS a moment to start listening
    time.sleep(2)                                                   # Step 2: Extra 2s wait for AS to call listen()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)     # Step 3: Create TCP server socket
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # Allow port reuse (avoids "address in use" error)
    server.bind(('', IOT_LISTEN_PORT))                              # Bind to all interfaces on port 55555
    server.listen(5)                                                # Accept up to 5 queued connections
    print(f"[AP] Listening for IoT on port {IOT_LISTEN_PORT} ...")

    while True:                                                     # Step 4: Main loop — handle IoT connections forever
        iot_conn, iot_addr = server.accept()                        # Block until an IoT device connects
        print(f"[AP] IoT connected from {iot_addr[0]}:{iot_addr[1]}")

        as_sock = connect_to_as()                                   # Step 5: Open a NEW connection to AS for this IoT
        if not as_sock:                                             # If AS unreachable after 10 retries
            print("[AP] Cannot reach AS after retries.")
            iot_conn.close()                                        # Close IoT connection — can't relay
            continue
        print(f"[AP] Connected to AS at {AS_HOST}:{AS_PORT}")

        t1 = threading.Thread(target=relay, args=(iot_conn, as_sock, "IoT→AS"), daemon=True)   # Thread 1: IoT → AS relay
        t2 = threading.Thread(target=relay, args=(as_sock, iot_conn, "AS→IoT"), daemon=True)   # Thread 2: AS → IoT relay
        t1.start()                                                  # Start forwarding IoT→AS
        t2.start()                                                  # Start forwarding AS→IoT
        print(f"[AP] Relaying traffic for {iot_addr[0]}:{iot_addr[1]}")  # Both directions now active


if __name__ == '__main__':
    main()
