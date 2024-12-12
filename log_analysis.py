import re

# File path to the log file
log_file = "firewall.log"

# Parse log file
def parse_logs(log_file):
    with open(log_file, "r") as f:
        logs = f.readlines()

    threats = []
    for log in logs:
        match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (.+?) from (.+)", log)
        if match:
            timestamp, threat_type, src_ip = match.groups()
            threats.append({"timestamp": timestamp, "threat_type": threat_type, "src_ip": src_ip})
    return threats

# Analyze logs
def analyze_threats(threats):
    ip_count = {}
    for threat in threats:
        ip_count[threat["src_ip"]] = ip_count.get(threat["src_ip"], 0) + 1

    print("Threat Analysis:")
    for ip, count in ip_count.items():
        print(f"IP: {ip}, Threats Detected: {count}")

# Main function
if __name__ == "__main__":
    threats = parse_logs(log_file)
    analyze_threats(threats)
