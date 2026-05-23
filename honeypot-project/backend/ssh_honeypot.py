import socket
import threading
import json
import logging
import time
from datetime import datetime

# Configure logging
LOG_FILE = "honeypot_logs.json"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(message)s")


def log_event(service, attacker_ip, port, data=""):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "service": service,
        "attacker_ip": attacker_ip,
        "port": port,
        "data": data[:200],
    }
    logging.info(json.dumps(entry))
    print(f"[ALERT] {service} hit from {attacker_ip}:{port} — {data[:60]}")


# --- Fake Services ---

def fake_ssh(conn, addr):
    try:
        conn.send(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n")
        data = conn.recv(1024).decode(errors="ignore")
        log_event("SSH", addr[0], addr[1], data)
        time.sleep(1)  # mimic delay
        conn.send(b"Permission denied (publickey,password).\r\n")
    except Exception as e:
        print(f"[ERROR] SSH handler: {e}")
    finally:
        conn.close()


def fake_http(conn, addr):
    try:
        data = conn.recv(4096).decode(errors="ignore")
        log_event("HTTP", addr[0], addr[1], data)
        time.sleep(1)
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Apache/2.4.41 (Ubuntu)\r\n"
            b"Content-Type: text/html\r\n\r\n"
            b"<h1>Admin Panel</h1>"
        )
        conn.send(resp)
    except Exception as e:
        print(f"[ERROR] HTTP handler: {e}")
    finally:
        conn.close()


def fake_smb(conn, addr):
    try:
        data = conn.recv(1024)
        log_event("SMB", addr[0], addr[1], str(data[:50]))
        time.sleep(1)
        # SMB decoy response; scanners should log the hit.
        conn.send(b"\x00\x00\x00\x00")
    except Exception as e:
        print(f"[ERROR] SMB handler: {e}")
    finally:
        conn.close()


def fake_rdp(conn, addr):
    # Lightweight RDP decoy: send a recognizable RDP Negotiation-like byte pattern.
    try:
        # RDP uses the connection negotiation (TPKT/CRTP). We send a harmless-looking
        # sequence so scanners record the banner/behavior.
        conn.send(b"\x03\x00\x00\x0b\x06\xD0\x00\x00\x00\x00\x00")
        data = conn.recv(2048)
        log_event("RDP", addr[0], addr[1], str(data[:200]))
        time.sleep(1)
    except Exception as e:
        print(f"[ERROR] RDP handler: {e}")
    finally:
        conn.close()


# --- Listener ---

def start_listener(port, handler, name):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
    except OSError as e:
        print(f"[ERROR] Could not bind {name} on port {port}: {e}")
        return
    s.listen(5)
    print(f"[*] {name} honeypot listening on port {port}")
    while True:
        try:
            conn, addr = s.accept()
            threading.Thread(target=handler, args=(conn, addr), daemon=True).start()
        except Exception as e:
            print(f"[ERROR] Listener {name}: {e}")


# --- Main ---

if __name__ == "__main__":
    services = [
        (2222, "SSH", fake_ssh),
        (8080, "HTTP", fake_http),
        (4445, "SMB", fake_smb),
        (3389, "RDP", fake_rdp),
    ]

    for port, name, handler in services:
        t = threading.Thread(target=start_listener, args=(port, handler, name), daemon=True)
        t.start()

    print("[*] All honeypot services running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")

