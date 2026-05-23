import socket
import time
from typing import Tuple

from logger import log_event


def fake_smb(conn: socket.socket, addr: Tuple[str, int]):
    try:
        data = conn.recv(1024)
        log_event("SMB", addr[0], addr[1], str(data[:50]))
        time.sleep(1)
        # Minimal decoy response so scanners see the service
        conn.send(b"\x00\x00\x00\x00")
    except Exception as e:
        print(f"[ERROR] SMB handler: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass

