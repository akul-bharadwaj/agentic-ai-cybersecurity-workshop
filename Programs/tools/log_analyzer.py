from collections import defaultdict
from datetime import datetime
import re
import sys


# --------------------------------------------------
# Configuration
# --------------------------------------------------

FAILED_LOGIN_THRESHOLD = 3


# --------------------------------------------------
# Log parsing
# --------------------------------------------------

LOG_PATTERN = re.compile(
    r"(?P<timestamp>\S+\s+\S+)\s+"
    r"(?P<event>\S+)\s+"
    r"user=(?P<user>\S+)\s+"
    r"ip=(?P<ip>\S+)"
)


def parse_log_line(line):
    """
    Parse one security log line.

    Expected format:
    2026-09-29 18:01:22 LOGIN_FAILED user=admin ip=10.0.0.5
    """

    match = LOG_PATTERN.search(line)

    if not match:
        return None

    data = match.groupdict()

    try:
        data["timestamp"] = datetime.strptime(
            data["timestamp"],
            "%Y-%m-%d %H:%M:%S"
        )
    except ValueError:
        return None

    return data


# --------------------------------------------------
# Detection
# --------------------------------------------------

def analyze_logs(lines):
    findings = []

    failed_logins = defaultdict(list)
    successful_logins = []

    for line in lines:
        event = parse_log_line(line)

        if not event:
            continue

        if event["event"] == "LOGIN_FAILED":
            key = (event["user"], event["ip"])
            failed_logins[key].append(event)

        elif event["event"] == "LOGIN_SUCCESS":
            successful_logins.append(event)

    # Detect repeated failed logins
    for (user, ip), attempts in failed_logins.items():

        if len(attempts) >= FAILED_LOGIN_THRESHOLD:

            findings.append({
                "severity": "HIGH",
                "type": "Possible brute-force attack",
                "user": user,
                "ip": ip,
                "details": f"{len(attempts)} failed login attempts"
            })

    # Detect successful login after failures
    for success in successful_logins:

        key = (success["user"], success["ip"])

        failures = failed_logins.get(key, [])

        if failures:
            findings.append({
                "severity": "HIGH",
                "type": "Successful login after failed attempts",
                "user": success["user"],
                "ip": success["ip"],
                "details": (
                    f"{len(failures)} failed attempts followed "
                    "by successful login"
                )
            })

    return findings


# --------------------------------------------------
# Reporting
# --------------------------------------------------

def print_report(findings):

    print("\n" + "=" * 60)
    print("SECURITY LOG ANALYZER")
    print("=" * 60)

    if not findings:
        print("\nNo suspicious activity detected.")
        return

    print(f"\nFindings: {len(findings)}\n")

    for number, finding in enumerate(findings, start=1):

        print(f"[{number}] {finding['severity']}")
        print(f"    Type:    {finding['type']}")
        print(f"    User:    {finding['user']}")
        print(f"    IP:      {finding['ip']}")
        print(f"    Details: {finding['details']}")
        print()


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():

    if len(sys.argv) != 2:
        print("Usage: python log_analyzer.py <log_file>")
        sys.exit(1)

    log_file = sys.argv[1]

    try:
        with open(log_file, "r", encoding="utf-8") as file:
            lines = file.readlines()

    except FileNotFoundError:
        print(f"Error: log file not found: {log_file}")
        sys.exit(1)

    findings = analyze_logs(lines)

    print_report(findings)


if __name__ == "__main__":
    main()
