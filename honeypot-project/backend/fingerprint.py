import json, os
from collections import defaultdict, Counter
from datetime import datetime

LOG_FILE = "honeypot_logs.json"

def fingerprint_tool(events_from_ip):
    services = [e.get("service", "") for e in events_from_ip]
    datas = " ".join([e.get("data", "") for e in events_from_ip])

    if len(services) > 3 and len(set(services)) > 2:
        return "Nmap / Port Scanner"
    if "USER" in datas or "PASS" in datas or "password" in datas.lower():
        return "Hydra / Brute Forcer"
    if any(s.upper() == "SSH" for s in services):
        return "SSH Client / Exploit Attempt"
    if any(s.upper() == "HTTP" for s in services) and ("admin" in datas.lower() or "login" in datas.lower()):
        return "Web Scanner (gobuster / nikto)"
    return "Unknown Tool"

def generate_report():
    if not os.path.exists(LOG_FILE):
        print("No logs found. Run the honeypot and trigger some connections first.")
        return

    events = []
    with open(LOG_FILE, "r") as f:
        for line in f:
            try:
                events.append(json.loads(line.strip()))
            except:
                pass

    by_ip = defaultdict(list)
    for e in events:
        if "attacker_ip" in e:
            by_ip[e["attacker_ip"]].append(e)

    print("\n" + "=" * 60)
    print("   THREAT INTELLIGENCE REPORT")
    print(f"   Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   Total events: {len(events)}")
    print(f"   Unique attacker IPs: {len(by_ip)}")
    print("=" * 60)

    for ip, ip_events in sorted(by_ip.items(), key=lambda x: -len(x[1])):
        tool = fingerprint_tool(ip_events)
        services_hit = Counter([e.get("service", "UNKNOWN") for e in ip_events])
        first_seen = min(e.get("timestamp", "") for e in ip_events)
        last_seen = max(e.get("timestamp", "") for e in ip_events)

        print(f"\n  ATTACKER IP : {ip}")
        print(f"  Tool        : {tool}")
        print(f"  Total hits  : {len(ip_events)}")
        print(f"  Services    : {dict(services_hit)}")
        print(f"  First seen  : {first_seen[11:19] if len(first_seen) >= 19 else first_seen}")
        print(f"  Last seen   : {last_seen[11:19] if len(last_seen) >= 19 else last_seen}")
        print(f"  MITRE       : T1046 (Network Service Discovery)")
        print(f"                T1595 (Active Scanning)")

    print("\n" + "=" * 60)

if __name__ == "__main__":
    generate_report()