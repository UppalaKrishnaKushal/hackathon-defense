from flask import Flask, request
from datetime import datetime
import os

app = Flask(__name__)

LOG_FILE = "/app/logs/attacks.log"

os.makedirs("logs", exist_ok=True)

@app.route("/")
def home():
    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent")
    severity = "LOW"
    tool = "Unknown"

    if "nmap" in user_agent.lower():
        severity = "HIGH"
        tool = "Nmap Scanner"

    elif "python" in user_agent.lower():
        severity = "MEDIUM"
        tool = "Python Script"

    elif "curl" in user_agent.lower():
        severity = "MEDIUM"
        tool = "Curl"


    log = f"""
TIME: {datetime.now()}
IP: {ip}
USER-AGENT: {user_agent}
PATH: /
TOOL: {tool}
SEVERITY: {severity}
-----------------------------------
"""


    with open(LOG_FILE, "a") as f:
        f.write(log)

    return """
    <h1>Welcome to Secure Internal Server</h1>
    <p>Authorized users only.</p>
    """

@app.route("/admin")
def admin():
    ip = request.remote_addr
    print(f"[ALERT] Suspicious admin access attempt from {ip}")

    severity = "LOW"
    tool = "Unknown"

    if "nmap" in (request.headers.get("User-Agent") or "").lower():
        severity = "HIGH"
        tool = "Nmap Scanner"

    elif "python" in (request.headers.get("User-Agent") or "").lower():
        severity = "MEDIUM"
        tool = "Python Script"

    elif "curl" in (request.headers.get("User-Agent") or "").lower():
        severity = "MEDIUM"
        tool = "Curl"

    log = f"""

[ADMIN ACCESS ATTEMPT]
TIME: {datetime.now()}
IP: {ip}
PATH: /admin
TOOL: {tool}
SEVERITY: {severity}
-----------------------------------
"""


    with open(LOG_FILE, "a") as f:
        f.write(log)

    return "403 Forbidden", 403

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)