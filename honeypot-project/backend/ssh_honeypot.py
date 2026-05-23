"""Backward-compatible entrypoint for the honeypot network.

War-room guide expects a single runnable file named `ssh_honeypot.py`.
Implementation is now split into multiple components to satisfy architecture:
- logger.py
- honeypot_server.py
- service handlers: *_service.py

Run:
  py ssh_honeypot.py
"""

from honeypot_server import run_all_services


if __name__ == "__main__":
    run_all_services()

