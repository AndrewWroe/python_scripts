import os
import time
import difflib
import subprocess
import platform
from libnmap.parser import NmapParser
from datetime import datetime
from colorama import init, Fore, Style
import signal
import sys

# Initialize colorama for colored output
init(autoreset=True)

# Handle Ctrl+C gracefully
def signal_handler(sig, frame):
    print(f"\n{Fore.YELLOW}🛑 Monitoring stopped by user.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# User inputs
target = input("Enter the target IP or subnet: ")
interval = input("Enter the interval in minutes: ")

TARGET = target
SCAN_DIR = "nmap_scans"
LOG_FILE = "network_changes.log"
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
    
    cmd = [NMAP_PATH, "-oX", filename, "-sn", TARGET]
    subprocess.run(cmd, check=True)
    return filename

def get_port_service(port):
    """Return a common service name for a given port (basic mapping)."""
    common_ports = {
        22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS",
        445: "SMB", 3389: "RDP", 21: "FTP", 25: "SMTP"
    }
    return common_ports.get(port, "Unknown")

def summarize_changes(old_file, new_file):
    old_report = NmapParser.parse_fromfile(old_file)
    new_report = NmapParser.parse_fromfile(new_file)

    changes = {"new_hosts": [], "removed_hosts": [], "port_changes": []}

    old_hosts = {h.address: h for h in old_report.hosts}
    new_hosts = {h.address: h for h in new_report.hosts}

    for ip in sorted(set(old_hosts.keys()).union(new_hosts.keys())):
        old_host = old_hosts.get(ip)
        new_host = new_hosts.get(ip)

        hostname = new_host.hostnames[0] if new_host and new_host.hostnames else ip

        if not old_host:
            changes["new_hosts"].append(f"🆕 New host: {hostname} ({ip})")
        elif not new_host:
            changes["removed_hosts"].append(f"❌ Host removed: {hostname} ({ip})")
        else:
            old_ports = {(s.port, s.protocol): s.state for s in old_host.services}
            new_ports = {(s.port, s.protocol): s.state for s in new_host.services}

            all_ports = set(old_ports) | set(new_ports)
            for port, proto in sorted(all_ports):
                old_state = old_ports.get((port, proto), "closed")
                new_state = new_ports.get((port, proto), "closed")
                if old_state != new_state:
                    service = get_port_service(port)
                    changes["port_changes"].append(
                        f"🔁 {hostname} ({ip}) port {port}/{proto} ({service}) changed: {old_state} → {new_state}"
                    )

    return changes

def log_changes(changes):
    """Log changes to a file with a timestamp."""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"\n--- Scan at {timestamp} ---\n")
        if not any(changes.values()):
            f.write("No changes detected.\n")
        else:
            for category, items in changes.items():
                if items:
                    f.write(f"{category.replace('_', ' ').title()}:\n")
                    for item in items:
                        f.write(f" - {item}\n")

def alert_user(changes, old_file, new_file):
    """Display changes in a formatted, human-readable way."""
    old_time = datetime.strptime(old_file.split("_")[-1].split(".")[0], "%Y%m%d-%H%M%S")
    new_time = datetime.strptime(new_file.split("_")[-1].split(".")[0], "%Y%m%d-%H%M%S")
    
    print(f"\n{Fore.CYAN}=== Network Scan Comparison ===")
    print(f"Old scan: {old_time.strftime('%Y-%m-%d %H:%M:%S')} ({old_file})")
    print(f"New scan: {new_time.strftime('%Y-%m-%d %H:%M:%S')} ({new_file})")
    print(f"Target: {TARGET}")
    print(f"{Fore.CYAN}{'=' * 30}\n")

    if not any(changes.values()):
        print(f"{Fore.GREEN}✅ No changes detected.")
        return

    print(f"{Fore.YELLOW}🔔 Network Changes Detected:")
    if changes["new_hosts"]:
        print(f"\n{Fore.GREEN}New Hosts:")
        for change in changes["new_hosts"]:
            print(f"  {change}")
    if changes["removed_hosts"]:
        print(f"\n{Fore.RED}Removed Hosts:")
        for change in changes["removed_hosts"]:
            print(f"  {change}")
    if changes["port_changes"]:
        print(f"\n{Fore.YELLOW}Port Changes:")
        for change in changes["port_changes"]:
            print(f"  {change}")

def get_last_two_scans():
    files = sorted([f for f in os.listdir(SCAN_DIR) if f.endswith(".xml")])
    if len(files) < 2:
        return None, None
    return os.path.join(SCAN_DIR, files[-2]), os.path.join(SCAN_DIR, files[-1])

def monitor():
    print(f"{Fore.CYAN}🚀 Starting Network Monitor")
    print(f"Target: {TARGET}")
    print(f"Scan interval: {interval} minutes")
    print(f"Output directory: {SCAN_DIR}")
    print(f"Log file: {LOG_FILE}")
    print(f"Press Ctrl+C to stop monitoring.\n")

    while True:
        start_time = datetime.now()
        print(f"{Fore.BLUE}🔍 Starting new scan at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        new_scan = run_nmap_scan()
        scan_duration = datetime.now() - start_time

        old_scan, _ = get_last_two_scans()
        if old_scan:
            changes = summarize_changes(old_scan, new_scan)
            alert_user(changes, old_scan, new_scan)
            log_changes(changes)
            print(f"\n{Fore.BLUE}Scan completed in {scan_duration.total_seconds():.2f} seconds.")
        else:
            print(f"{Fore.GREEN}🆕 First scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Scan took {scan_duration.total_seconds():.2f} seconds.")
            with open(LOG_FILE, "a") as f:
                f.write(f"First scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        print(f"{Fore.BLUE}⏳ Waiting {interval} minutes for next scan...")
        time.sleep(INTERVAL)

if __name__ == "__main__":
    monitor()