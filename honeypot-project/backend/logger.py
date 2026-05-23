import json
import logging
from datetime import datetime


LOG_FILE = "honeypot_logs.json"

# Configure logging to append JSON lines
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(message)s")


def log_event(service: str, attacker_ip: str, port: int, data: str = ""):
    """Write one JSONL event to honeypot_logs.json."""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "service": service,
        "attacker_ip": attacker_ip,
        "port": port,
        # Keep preview small so logs are manageable
        "data": str(data)[:200],
    }
    logging.info(json.dumps(entry))
    print(f"[ALERT] {service} hit from {attacker_ip}:{port} — {str(data)[:60]}")

