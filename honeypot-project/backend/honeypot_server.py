import socket
import threading
import time
from typing import Callable, Tuple


def start_listener(port: int, handler: Callable[[socket.socket, Tuple[str, int]], None], name: str):
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


def run_all_services():
    # Late imports so module load is clean
    from ssh_service import fake_ssh
    from http_service import fake_http
    from smb_service import fake_smb
    from rdp_service import fake_rdp

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


if __name__ == "__main__":
    run_all_services()

