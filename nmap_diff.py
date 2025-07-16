import os
import time
import difflib
import subprocess
import platform
from libnmap.parser import NmapParser
from datetime import datetime

target = input("Enter the target IP or subnet: ")
interval = input("Enter the interval in minutes: ")

TARGET = target
SCAN_DIR = "nmap_scans"
INTERVAL = int(interval) * 60

def get_nmap_path():
    system = platform.system()
    if system == "Windows":
        return r"C:\Program Files (x86)\Nmap\nmap.exe"
    elif system == "Linux" or system == "Darwin":
        return "/usr/bin/nmap"
    else:
        raise RuntimeError(f"Unsupported OS: {system}")

NMAP_PATH = get_nmap_path()

def run_nmap_scan():
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"{SCAN_DIR}/scan_{timestamp}.xml"
    os.makedirs(SCAN_DIR, exist_ok=True)
    
    cmd = [NMAP_PATH, "-oX", filename, TARGET]
    subprocess.run(cmd, check=True)
    return filename

def compare_scans(file1, file2):
    with open(file1, 'r') as f1, open(file2, 'r') as f2:
        lines1 = f1.readlines()
        lines2 = f2.readlines()
        diff = difflib.unified_diff(lines1, lines2, fromfile=file1, tofile=file2)
        return list(diff)
    
def summarize_changes(old_file, new_file):
    old_report = NmapParser.parse_fromfile(old_file)
    new_report = NmapParser.parse_fromfile(new_file)

    changes = []

    old_hosts = {h.address: h for h in old_report.hosts}
    new_hosts = {h.address: h for h in new_report.hosts}

    for ip in sorted(set(old_hosts.keys()).union(new_hosts.keys())):
        old_host = old_hosts.get(ip)
        new_host = new_hosts.get(ip)

        if not old_host:
            changes.append(f"🆕 New host detected: {ip}")
        elif not new_host:
            changes.append(f"❌ Host disappeared: {ip}")
        else:
            # Compare ports
            old_ports = {(s.port, s.protocol): s.state for s in old_host.services}
            new_ports = {(s.port, s.protocol): s.state for s in new_host.services}

            all_ports = set(old_ports) | set(new_ports)
            for port_info in sorted(all_ports):
                old_state = old_ports.get(port_info, "closed")
                new_state = new_ports.get(port_info, "closed")
                if old_state != new_state:
                    changes.append(f"🔁 {ip} port {port_info[0]}/{port_info[1]} changed: {old_state} → {new_state}")

    return changes

def alert_user(changes):
    if not changes:
        print("✅ No relevant changes.")
        return

    print("🔔 Network changes detected:")
    for line in changes:
        print(" -", line)

def get_last_two_scans():
    files = sorted([f for f in os.listdir(SCAN_DIR) if f.endswith(".xml")])
    if len(files) < 2:
        return None, None
    return os.path.join(SCAN_DIR, files[-2]), os.path.join(SCAN_DIR, files[-1])

def monitor():
    while True:
        start_time = datetime.now()
        print("🔍 Starting new nmap scan at", start_time.strftime("%Y-%m-%d %H:%M:%S"))
        new_scan = run_nmap_scan()

        old_scan, _ = get_last_two_scans()
        if old_scan:
            diffs = compare_scans(old_scan, new_scan)
            if diffs:
                alert_user(diffs)
            else:
                print("✅ No changes detected.")
        else:
            print("🆕 First scan completed at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            print("Scan took", datetime.now() - start_time)

        time.sleep(INTERVAL)

if __name__ == "__main__":
    monitor()
