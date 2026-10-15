from collections import defaultdict
from datetime import datetime, timedelta
import re


FAILED_LOGIN_THRESHOLD = 3
FAILED_LOGIN_WINDOW_MINUTES = 5


LOG_PATTERN = re.compile(
    r"(?P<timestamp>\S+\s+\S+)\s+"
    r"(?P<event>\S+)\s+"
    r"user=(?P<user>\S+)\s+"
    r"ip=(?P<ip>\S+)"
)


def parse_log_line(line):
    """
    Parse one security log line.
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


def analyze_logs(lines):

    findings = []

    failed_logins = defaultdict(list)
    successful_logins = []

    # ------------------------------------------
    # Parse log events
    # ------------------------------------------

    for line in lines:

        event = parse_log_line(line)

        if not event:
            continue

        if event["event"] == "LOGIN_FAILED":

            key = (event["user"], event["ip"])
            failed_logins[key].append(event)

        elif event["event"] == "LOGIN_SUCCESS":

            successful_logins.append(event)

    # ------------------------------------------
    # Detect brute-force attempts
    # ------------------------------------------

    window = timedelta(minutes=FAILED_LOGIN_WINDOW_MINUTES)

    for (user, ip), attempts in failed_logins.items():

        attempts.sort(key=lambda x: x["timestamp"])

        for i in range(len(attempts)):

            start = attempts[i]["timestamp"]
            end = start + window

            attempts_in_window = [
                attempt
                for attempt in attempts
                if start <= attempt["timestamp"] <= end
            ]

            if len(attempts_in_window) >= FAILED_LOGIN_THRESHOLD:

                findings.append({
                    "severity": "HIGH",
                    "type": "Possible brute-force attack",
                    "user": user,
                    "ip": ip,
                    "details": (
                        f"{len(attempts_in_window)} failed login attempts "
                        f"within {FAILED_LOGIN_WINDOW_MINUTES} minutes"
                    )
                })

                break

    # ------------------------------------------
    # Detect successful login after recent failures
    # ------------------------------------------

    for success in successful_logins:

        key = (success["user"], success["ip"])

        failures = failed_logins.get(key, [])

        recent_failures = [
            failure
            for failure in failures
            if (
                timedelta(0)
                <= success["timestamp"] - failure["timestamp"]
                <= window
            )
        ]

        if recent_failures:

            findings.append({
                "severity": "HIGH",
                "type": "Successful login after failed attempts",
                "user": success["user"],
                "ip": success["ip"],
                "details": (
                    f"{len(recent_failures)} failed attempts within "
                    f"{FAILED_LOGIN_WINDOW_MINUTES} minutes before "
                    "successful login"
                )
            })

    return findings
