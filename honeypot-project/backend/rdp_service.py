import socket
import time
from typing import Tuple

from logger import log_event


def fake_rdp(conn: socket.socket, addr: Tuple[str, int]):
    """Lightweight RDP decoy: sends a recognizable negotiation-ish blob."""
    try:
        conn.send(b"\x03\x00\x00\x0b\x06\xD0\x00\x00\x00\x00\x00")
        data = conn.recv(2048)
        log_event("RDP", addr[0], addr[1], str(data[:200]))
        time.sleep(1)
    except Exception as e:
        print(f"[ERROR] RDP handler: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass

