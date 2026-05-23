from flask import Flask, render_template_string
import json
import os
from collections import Counter, defaultdict

app = Flask(__name__)
LOG_FILE = "honeypot_logs.json"

# Keep the auto-refresh + provide a much richer UI (live alerts, attacker IPs, ports hit, tool identified, severity colors)
HTML = """
<!DOCTYPE html><html><head>
<title>Honeypot Dashboard</title>
<meta http-equiv="refresh" content="5">
<style>
body{font-family:Arial,sans-serif;background:#0a0a0a;color:#e6e6e6;padding:20px;}
.hdr{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;flex-wrap:wrap;}
h1{color:#00ff41;border-bottom:1px solid #333;padding-bottom:10px;margin:0;}
.small{color:#9aa0a6;font-size:12px;}

.statrow{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;}
.stat{min-width:200px;background:#111;border:1px solid #333;
      padding:15px 18px;border-radius:10px;text-align:center;}
.stat-num{font-size:28px;color:#00ff41;font-weight:bold;}
.stat-label{font-size:12px;color:#666;margin-top:4px;}

.panel{background:#0f0f0f;border:1px solid #222;border-radius:12px;padding:14px;margin-top:15px;}

/* Live alerts */
.alertbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;}
.alertpill{padding:8px 12px;border-radius:999px;border:1px solid #333;background:#111;color:#ddd;font-size:12px;}

/* severity colors */
.sev-LOW{border-color:#2d7d2d;background:#0b2a0b;color:#7CFF7C;}
.sev-MED{border-color:#7a6b00;background:#2b2407;color:#ffe08a;}
.sev-HIGH{border-color:#7a0000;background:#2b0707;color:#ff8a8a;}
.sev-CRIT{border-color:#ff0000;background:#3a0000;color:#ff4d4d;}

.tablewrap{margin-top:10px;}
.table-title{color:#bbb;font-size:13px;margin-bottom:8px;}

table{width:100%;border-collapse:collapse;}
th{background:#1a1a1a;color:#00ff41;padding:10px;text-align:left;position:sticky;top:0;}
td{padding:10px 10px;border-bottom:1px solid #222;color:#ccc;vertical-align:top;}
tr:hover{background:#111;}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;}
.badge{display:inline-block;padding:3px 8px;border-radius:8px;border:1px solid #333;background:#111;color:#d7d7d7;font-size:12px;}

.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
@media (max-width: 900px){.grid2{grid-template-columns:1fr;}}
</style></head><body>
<div class="hdr">
  <div>
    <h1>Honeypot Threat Dashboard</h1>
    <div class="small">Auto-refresh every 5 seconds · Source: <span class="mono">{{log_file}}</span></div>
  </div>
  <div class="small">MITRE mapping: <span class="mono">T1046</span> Service Discovery · <span class="mono">T1595</span> Active Scanning</div>
</div>

<div class="statrow">
  <div class="stat"><div class="stat-num">{{total}}</div><div class="stat-label">Total hits</div></div>
  <div class="stat"><div class="stat-num">{{unique_ips}}</div><div class="stat-label">Unique attacker IPs</div></div>
  <div class="stat"><div class="stat-num">{{top_service}}</div><div class="stat-label">Most attacked service</div></div>
  <div class="stat"><div class="stat-num">{{top_port}}</div><div class="stat-label">Most targeted port</div></div>
</div>

<div class="panel">
  <div class="table-title">Live Alerts (color-coded severity)</div>
  <div class="alertbar">
    {% if alerts %}
      {% for a in alerts %}
        <div class="alertpill sev-{{a.sev}}"><strong>{{a.sev}}</strong> · {{a.text}}</div>
      {% endfor %}
    {% else %}
      <div class="alertpill">No suspicious bursts detected yet</div>
    {% endif %}
  </div>

  <div class="tablewrap">
    <div class="grid2">
      <div>
        <div class="table-title">Attacker IPs (burst + tool)</div>
        <table>
          <tr><th>Attacker IP</th><th>Hits</th><th>Severity</th><th>Tool identified</th></tr>
          {% for row in attacker_rows %}
          <tr>
            <td class="mono">{{row.ip}}</td>
            <td>{{row.hits}}</td>
            <td><span class="badge">{{row.sev}}</span></td>
            <td class="mono">{{row.tool}}</td>
          </tr>
          {% endfor %}
        </table>
      </div>
      <div>
        <div class="table-title">Ports hit (recent)</div>
        <table>
          <tr><th>Port</th><th>Service</th><th>Hits</th></tr>
          {% for p in port_rows %}
          <tr>
            <td class="mono">{{p.port}}</td>
            <td>{{p.service}}</td>
            <td>{{p.hits}}</td>
          </tr>
          {% endfor %}
        </table>
      </div>
    </div>
  </div>
</div>

<div class="panel">
  <div class="table-title">Latest Interaction Events (fingerprinting + severity)</div>
  <table>
    <tr>
      <th>Time</th><th>Service</th><th>Port</th><th>Attacker IP</th>
      <th>Tool identified</th><th>Severity</th><th>Data preview</th>
    </tr>
    {% for e in events %}
    <tr>
      <td class="mono">{{e.timestamp[11:19]}}</td>
      <td>{{e.service}}</td>
      <td class="mono">{{e.port}}</td>
      <td class="mono">{{e.attacker_ip}}</td>
      <td class="mono">{{e.tool}}</td>
      <td><span class="badge">{{e.sev}}</span></td>
      <td class="mono">{{e.data[:60]}}</td>
    </tr>
    {% endfor %}
  </table>
</div>

</body></html>
"""


def read_logs():
    events = []
    if not os.path.exists(LOG_FILE):
        return events
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                events.append(json.loads(line.strip()))
            except Exception:
                pass
    return events


def fingerprint_tool(events_from_ip):
    """Heuristic matcher aligned to fingerprint.py style."""
    services = [e.get("service") for e in events_from_ip if e.get("service")]
    datas = " ".join([str(e.get("data", "")) for e in events_from_ip])

    # Nmap-style: multiple services probed in short burst
    if len(set(services)) >= 3:
        return "Nmap / Port Scanner"

    low = datas.lower()
    if any(k in low for k in ("user", "pass", "password")):
        return "Hydra / Brute Forcer"

    if "SSH" in services:
        return "SSH Client / Exploit Attempt"

    if "HTTP" in services and ("admin" in low or "login" in low):
        return "Web Scanner (gobuster / nikto)"

    return "Unknown Tool"


def severity_for(ip_hits: int) -> str:
    # burst-based severity thresholds
    if ip_hits >= 10:
        return "CRIT"
    if ip_hits >= 6:
        return "HIGH"
    if ip_hits >= 3:
        return "MED"
    return "LOW"


@app.route("/")
def index():
    events = read_logs()
    events_sorted = sorted(events, key=lambda x: x.get("timestamp", ""), reverse=True)
    recent = events_sorted[:200]

    ips = [e.get("attacker_ip") for e in recent if e.get("attacker_ip")]
    services = [e.get("service") for e in recent if e.get("service")]

    ip_counts = Counter(ips)
    top_service = Counter(services).most_common(1)[0][0] if services else "None"

    port_counts = Counter([(e.get("port"), e.get("service")) for e in recent])
    if port_counts:
        (top_port, _), _hits = port_counts.most_common(1)[0]
    else:
        top_port = "-"

    # attacker table
    by_ip = defaultdict(list)
    for e in recent:
        ip = e.get("attacker_ip")
        if ip:
            by_ip[ip].append(e)

    attacker_rows = []
    for ip, ip_events in sorted(by_ip.items(), key=lambda kv: -len(kv[1]))[:10]:
        hits = len(ip_events)
        sev = severity_for(hits)
        tool = fingerprint_tool(ip_events)
        attacker_rows.append({"ip": ip, "hits": hits, "sev": sev, "tool": tool})

    # live alerts
    alerts = []
    for ip, hits in ip_counts.items():
        sev = severity_for(hits)
        if sev in ("HIGH", "CRIT") and hits >= 6:
            tool = fingerprint_tool(by_ip.get(ip, []))
            alerts.append({"sev": sev, "text": f"{ip} · {hits} hits · {tool}"})

    # newest events enriched with tool/severity
    enriched_events = []
    for e in events_sorted[:50]:
        ip = e.get("attacker_ip")
        tool = fingerprint_tool(by_ip.get(ip, [])) if ip else "Unknown Tool"
        sev = severity_for(ip_counts.get(ip, 0)) if ip else "LOW"
        enriched_events.append(
            {
                **e,
                "data": "" if e.get("data") is None else str(e.get("data", "")),
                "tool": tool,
                "sev": sev,
                "port": e.get("port", ""),
            }
        )

    port_rows = []
    for (port, service), hits in port_counts.most_common(10):
        port_rows.append({"port": port, "service": service, "hits": hits})

    return render_template_string(
        HTML,
        events=enriched_events,
        total=len(events),
        unique_ips=len(set(ips)),
        top_service=top_service,
        top_port=top_port,
        alerts=alerts,
        attacker_rows=attacker_rows,
        port_rows=port_rows,
        log_file=LOG_FILE,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

