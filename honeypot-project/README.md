# Honeypot Network with Deception Technology
## Problem
Our network has no deception layer — attackers scan freely and can map out real services without detection.
## Solution
We deployed a Honeypot Network with 4 fake services (SSH, HTTP, SMB, FTP) that do nothing except log every attacker who touches them. Attackers think they found real servers, but every connection they make is silently recorded, fingerprinted, and reported. This provides us with instant alerts and threat intelligence about the scanning tools being used.
## How to Run
Install requirements:
```bash
pip install flask
```
Start the services (run each in a separate terminal):
```bash
python3 ssh_honeypot.py
python3 dashboard.py
python3 fingerprint.py
```
## MITRE ATT&CK Mapping
- **T1046 (Network Service Discovery):** The honeypot logs when attackers scan our ports, recording timestamps, IP addresses, and which ports are hit.
- **T1595 (Active Scanning):** The fingerprinter tool identifies the tools used based on behavior (e.g., Nmap pattern = many services in a short time).
Detection maps to MITRE ATT&CK T1046 + T1595 with <1s response
