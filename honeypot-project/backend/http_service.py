import socket
import time
from typing import Tuple

from logger import log_event


def fake_http(conn: socket.socket, addr: Tuple[str, int]):
    try:
        data = conn.recv(4096).decode(errors="ignore")
        log_event("HTTP", addr[0], addr[1], data[:100])
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
        try:
            conn.close()
        except Exception:
            pass

