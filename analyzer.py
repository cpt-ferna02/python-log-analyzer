import os
import pandas as pd
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
from datetime import datetime

# ── MITRE ATT&CK Event ID Mapping ──────────────────────────────────────────
THREAT_SIGNATURES = {
    4625: ("Failed Logon",                  "T1110 - Brute Force"),
    4648: ("Logon with Explicit Credentials","T1550 - Use Alternate Auth"),
    4672: ("Special Privileges Assigned",   "T1078 - Valid Accounts"),
    4688: ("New Process Created",           "T1059 - Command Execution"),
    4698: ("Scheduled Task Created",        "T1053 - Scheduled Task"),
    4720: ("User Account Created",          "T1136 - Create Account"),
    4732: ("User Added to Admin Group",     "T1098 - Account Manipulation"),
    4776: ("Credential Validation",         "T1003 - Credential Dumping"),
    7045: ("New Service Installed",         "T1543 - Create/Modify Service"),
}

# ── Parse a single EVTX file ────────────────────────────────────────────────
def parse_evtx(filepath):
    findings = []
    ns = "http://schemas.microsoft.com/win/2004/08/events/event"

    with Evtx(filepath) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
                event_id_el = root.find(f".//{{{ns}}}EventID")
                time_el     = root.find(f".//{{{ns}}}TimeCreated")

                if event_id_el is None:
                    continue

                event_id  = int(event_id_el.text)
                timestamp = time_el.attrib.get("SystemTime", "N/A") if time_el is not None else "N/A"

                if event_id in THREAT_SIGNATURES:
                    name, mitre = THREAT_SIGNATURES[event_id]
                    findings.append({
                        "Timestamp":   timestamp,
                        "Event ID":    event_id,
                        "Threat":      name,
                        "MITRE ATT&CK":mitre,
                        "Source File": os.path.basename(filepath),
                    })
            except Exception:
                continue

    return findings

# ── Scan all EVTX files in /logs ────────────────────────────────────────────
def scan_logs(log_dir="logs"):
    all_findings = []
    files = [f for f in os.listdir(log_dir) if f.endswith(".evtx")]

    if not files:
        print("No .evtx files found in logs/ folder.")
        return []

    for filename in files:
        path = os.path.join(log_dir, filename)
        print(f"[*] Scanning: {filename}")
        results = parse_evtx(path)
        print(f"    → {len(results)} threat(s) found")
        all_findings.extend(results)

    return all_findings

# ── Save CSV report ─────────────────────────────────────────────────────────
def save_csv(findings, output="reports/findings.csv"):
    df = pd.DataFrame(findings)
    df.to_csv(output, index=False)
    print(f"\n[+] CSV report saved: {output}")

# ── Save HTML report ────────────────────────────────────────────────────────
def save_html(findings, output="reports/findings.html"):
    df = pd.DataFrame(findings)
    html = df.to_html(index=False, border=1)
    with open(output, "w") as f:
        f.write(f"<h2>Log Analyzer - Threat Report</h2>{html}")
    print(f"[+] HTML report saved: {output}")

# ── Main ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== Windows Event Log Analyzer ===\n")
    findings = scan_logs("logs")

    if findings:
        save_csv(findings)
        save_html(findings)
        print(f"\n[✓] Total threats detected: {len(findings)}")
    else:
        print("[-] No threats detected.")