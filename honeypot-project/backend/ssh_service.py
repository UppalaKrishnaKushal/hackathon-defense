import socket
import time
from typing import Tuple

from logger import log_event


def fake_ssh(conn: socket.socket, addr: Tuple[str, int]):
    try:
        conn.send(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n")
        data = conn.recv(1024).decode(errors="ignore")
        log_event("SSH", addr[0], addr[1], data)
        time.sleep(1)
        conn.send(b"Permission denied (publickey,password).\r\n")
    except Exception as e:
        print(f"[ERROR] SSH handler: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass

