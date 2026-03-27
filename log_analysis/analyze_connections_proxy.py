import re
import sys
from collections import Counter

def analyze_log(filepath):
    connection_pattern = re.compile(
        r"\[\+\] Connection from \('([\d.]+)', (\d+)\)"
    )

    total_connections = 0
    unique_ips = set()
    ip_counts = Counter()

    with open(filepath, "r") as f:
        for line in f:
            match = connection_pattern.search(line)
            if match:
                ip = match.group(1)
                total_connections += 1
                unique_ips.add(ip)
                ip_counts[ip] += 1

    print("-" * 10)
    print("CONNECTION LOG ANALYSIS")
    print("-" * 10)
    print(f"Total connections:   {total_connections}")
    print(f"Unique IPs:          {len(unique_ips)}")
    print()
    print("Connections per IP (sorted by count):")
    print("-" * 40)
    for ip, count in ip_counts.most_common():
        print(f"  {ip:<22} {count:>4} connection(s)")
    print("=" * 50)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_connections.py <logfile>")
        sys.exit(1)

    analyze_log(sys.argv[1])