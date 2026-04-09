import psutil
import datetime
import time
import hashlib
import json
import os
import streamlit as st

# ---------------- UI ----------------
st.title("🛡️ Process Monitoring Agent (Live)")

# ---------------- Config ----------------
WHITELIST = [
    "explorer.exe", "svchost.exe", "chrome.exe",
    "brave.exe", "python.exe", "system", "registry"
]

LOG_FILE = "monitor_log.json"
seen_alerts = set()

# ---------------- Logging ----------------
def log_event(level, message, process, path):
    log_entry = {
        "timestamp": str(datetime.datetime.now()),
        "level": level,
        "process": process,
        "path": path,
        "message": message
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

# ---------------- Hash ----------------
def get_file_hash(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return "N/A"

# ---------------- Detection Rules ----------------
def is_suspicious(parent, child):
    rules = [
        ("winword.exe", "powershell.exe"),
        ("excel.exe", "cmd.exe"),
        ("chrome.exe", "cmd.exe")
    ]
    return (parent, child) in rules

# ---------------- Monitoring ----------------
def scan_processes():
    alerts = []

    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe']):
        try:
            parent = psutil.Process(proc.info['ppid']).name().lower()
            name = proc.info['name'].lower() if proc.info['name'] else "unknown"
            path = proc.info['exe']

            alert_key = f"{parent}-{name}-{path}"

            # Suspicious chain
            if is_suspicious(parent, name) and alert_key not in seen_alerts:
                msg = f"🚨 Suspicious Chain: {parent} → {name}"
                alerts.append(msg)
                log_event("HIGH", msg, name, path)
                seen_alerts.add(alert_key)

            # Unknown process
            if name not in WHITELIST and alert_key not in seen_alerts:
                msg = f"⚠ Unknown Process: {name}"
                alerts.append(msg)
                log_event("MEDIUM", msg, name, path)
                seen_alerts.add(alert_key)

            # Suspicious path
            if path and ("temp" in path.lower() or "appdata" in path.lower()):
                if alert_key not in seen_alerts:
                    msg = f"🚨 Suspicious Path: {path}"
                    alerts.append(msg)
                    log_event("HIGH", msg, name, path)
                    seen_alerts.add(alert_key)

            # Hash logging
            if path and os.path.exists(path):
                file_hash = get_file_hash(path)
                log_event("INFO", f"Hash: {file_hash}", name, path)

        except:
            continue

    return alerts

# ---------------- UI Button ----------------
if st.button("🔍 Scan Now"):
    st.write("Scanning processes...\n")
    alerts = scan_processes()

    if alerts:
        for alert in alerts:
            st.error(alert)
    else:
        st.success("✅ No major threats detected")