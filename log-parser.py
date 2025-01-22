import os
import re
import csv
import argparse
from rich.console import Console

# Console for enhanced terminal output
console = Console()

# Suspicious activity patterns
suspicious_patterns = {
    "Brute Force": r"(failed login|login failure|authentication failed|too many attempts)",
    "Unauthorized Access": r"(unauthorized|access denied|permission denied|invalid credentials)",
    "VPN Issues": r"(vpn disconnection|vpn failed|vpn error|authentication timeout)",
    "Anonymous Login": r"(anonymous login|guest login|unauthenticated login)",
    "Logon Failure": r"(logon failed|login attempt failed|invalid user)",
    "Critical Error": r"(critical|error|warning|unexpected failure)",
    "Unusual Activity": r"(suspicious|unusual|unexpected behavior|malicious)",
    "Malicious IP Access": r"(203\.0\.113\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
    "Privilege Escalation": r"(sudo|su|elevated privileges|root access|root privilege)",
    "Port Scanning": r"(nmap|masscan|portscan|scanning ports|service probe)",
    "Outbound Connections": r"(outbound connection|sending data|external connection|uploading)",
    "System Compromise": r"(rootkit|trojan|exploit|compromised system|malware)",
    "Suspicious File Access": r"(access to /etc/passwd|access to /bin/bash|critical file accessed)",
    "Suspicious Processes": r"(unknown process|new process|suspicious process|exec /bin/bash)",
    "Ransomware Activity": r"(ransomware|encryption failure|file lock|ransom note|decrypt files)",
    "Data Exfiltration": r"(data exfiltration|stolen data|uploading sensitive files|sending data out)",
    "DNS Tunneling": r"(dns request|dns query|dns data|dns tunnel)",
    "Web Shell Access": r"(webshell|cmd.exe|/bin/sh|/bin/bash|web terminal)",
    "Privilege Abuse": r"(abused privilege|excessive permissions|admin access|changed privileges)",
    "IP Spoofing": r"(spoofed ip|ip address mismatch|ip deception)",
    "Keylogger Activity": r"(keylogger|logging keystrokes|capture keystrokes)",
    "SQL Injection": r"(sql injection|union select|drop table|or 1=1|-- ')",
    "Cross-Site Scripting (XSS)": r"(xss|<script>|javascript:|onerror=)",
    "Command Injection": r"(command injection|bash -i|cmd /c)",
    "Exploit Attempt": r"(exploit attempt|vulnerability found|remote code execution|arbitrary code execution)",
    "Fileless Malware": r"(fileless malware|memory resident malware|in-memory attack)",
    "Botnet Activity": r"(botnet|zombie machine|ddos attack|bot traffic)",
    "Abnormal Network Traffic": r"(spike in traffic|network anomaly|traffic surge|suspicious bandwidth usage)",
    "Suspicious Login Locations": r"(unusual login location|location mismatch|geographical login anomaly)",
    "Session Hijacking": r"(session hijack|stolen session|cookie theft)",
    "Suspicious Downloads": r"(suspicious download|unknown file|download from untrusted source)",
    "Data Integrity Violation": r"(data corruption|integrity check failed|tampered data)",
    "File Integrity Violation": r"(file integrity check failed|file tampered|file altered)",
    "Suspicious Network Connection": r"(suspicious network connection|unusual network destination|network port scan)",
    "Privilege Escalation via Vulnerability": r"(elevation of privilege|escalating privileges|privilege escalation attempt)",
    "USB Malware": r"(usb malware|usb device connected|malicious usb)",
    "External Media Usage": r"(usb device|external media|usb drive inserted|removable disk)",
    "Email Spoofing": r"(email spoofing|fake sender|forged email|spoofed email)",
    "Phishing Attempt": r"(phishing|fake login|malicious link|fake website|phish)",
    "Insider Threat": r"(insider threat|disgruntled employee|data theft|unauthorized access by employee)",
    "Suspicious Service Restart": r"(service restart|unexpected service stop|service failure)",
    "DNS Amplification Attack": r"(dns amplification|amplification attack|dns flood)",
    "Cryptojacking": r"(cryptojacking|mining malware|cryptocurrency mining)",
    "Network Bridge Attack": r"(network bridge attack|arp poisoning|man-in-the-middle)",
    "Buffer Overflow": r"(buffer overflow|memory corruption|segfault)",
    "Zero-Day Exploit": r"(zero-day exploit|undocumented vulnerability|new exploit)",
}

private_ranges = [
    (10, 10, 0, 0, 255, 255, 255, 255),
    (172, 16, 0, 0, 172, 31, 255, 255),
    (192, 168, 0, 0, 192, 168, 255, 255),
    (127, 0, 0, 0, 127, 255, 255, 255),
    (224, 0, 0, 0, 239, 255, 255, 255)  # Multicast range
]

def is_public_ip(ip):
    octets = list(map(int, ip.split('.')))
    for r in private_ranges:
        if r[0] <= octets[0] <= r[4] and r[1] <= octets[1] <= r[5] and r[2] <= octets[2] <= r[6] and r[3] <= octets[3] <= r[7]:
            return False
    return True

def get_geo_location(ip):
    """Placeholder function for getting geolocation of a public IP."""
    if not is_public_ip(ip):
        return "Private IP"
    # In a real implementation, integrate with a geolocation API like ipstack or GeoIP
    return "GeoLocation Placeholder"

def extract_metadata(line):
    """Extract metadata from a log line."""
    date_match = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line)
    ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
    hostname_match = re.search(r"hostname\s*[:=]\s*(\S+)", line, re.IGNORECASE)
    event_id_match = re.search(r"event\s*id\s*[:=]\s*(\d+)", line, re.IGNORECASE)
    record_id_match = re.search(r"record\s*id\s*[:=]\s*(\d+)", line, re.IGNORECASE)
    sha1_match = re.search(r"sha1\s*[:=]\s*([a-fA-F0-9]{40})", line, re.IGNORECASE)
    user_match = re.search(r"user\s*[:=]\s*(\S+)", line, re.IGNORECASE)

    return {
        "Date": date_match.group() if date_match else "N/A",
        "Source IP": ip_matches[0] if ip_matches else "N/A",
        "Destination IP": ip_matches[1] if len(ip_matches) > 1 else "N/A",
        "Source Geo Location": get_geo_location(ip_matches[0]) if ip_matches else "N/A",
        "Destination Geo Location": get_geo_location(ip_matches[1]) if len(ip_matches) > 1 else "N/A",
        "Hostname": hostname_match.group(1) if hostname_match else "N/A",
        "Event ID": event_id_match.group(1) if event_id_match else "N/A",
        "Record ID": record_id_match.group(1) if record_id_match else "N/A",
        "SHA1": sha1_match.group(1) if sha1_match else "N/A",
        "User": user_match.group(1) if user_match else "N/A",
    }

def analyze_file(file_path, results):
    """Analyze a single log file for suspicious patterns."""
    try:
        with open(file_path, "r", errors="ignore") as file:
            for line_no, line in enumerate(file, 1):
                metadata = extract_metadata(line)
                for activity, pattern in suspicious_patterns.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        results[activity].append({
                            "File": os.path.basename(file_path),
                            "Line": line_no,
                            **metadata,
                            "Detections": activity,
                            "Path": os.path.abspath(file_path),
                            "Threat Name": activity,
                            "Threat Path": "N/A",
                            "Threat Type": "Suspicious Activity",
                            "Timestamp": metadata["Date"],
                        })
    except Exception as e:
        console.print(f"[bold red]Error reading {file_path}: {e}[/bold red]")

def analyze_logs(directory):
    """Analyze all files in a directory and save results to separate CSVs."""
    log_files = [
        os.path.join(root, file)
        for root, _, files in os.walk(directory)
        for file in files
    ]
    total_files = len(log_files)
    console.print(f"[bold cyan]Found {total_files} files. Starting analysis...[/bold cyan]")

    results = {pattern: [] for pattern in suspicious_patterns}

    for file_path in log_files:
        analyze_file(file_path, results)

    # Save each pattern's results to a separate CSV file
    for pattern, data in results.items():
        sanitized_pattern = re.sub(r"[^a-zA-Z0-9]", "_", pattern)
        save_to_csv(f"{sanitized_pattern}.csv", data, [
            "File", "Line", "Date", "Source IP", "Destination IP", "Source Geo Location", "Destination Geo Location",
            "Hostname", "Timestamp", "Detections", "Path", "Event ID", "Record ID", "Computer",
            "Threat Name", "Threat Path", "SHA1", "User", "Threat Type"
        ])
    console.print("[bold green]Analysis complete! Results saved to CSV files.[/bold green]")

def save_to_csv(filename, data, headers):
    """Save data to a CSV file."""
    with open(filename, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        writer.writerows(data)

def main():
    """Main function to run the script."""
    parser = argparse.ArgumentParser(description="Log Analysis Script")
    parser.add_argument("-f", "--folder", required=True, help="Folder path containing log files")
    args = parser.parse_args()

    directory = args.folder
    if os.path.isdir(directory):
        analyze_logs(directory)
    else:
        console.print("[bold red]Invalid directory path![/bold red]")

if __name__ == "__main__":
    main()
