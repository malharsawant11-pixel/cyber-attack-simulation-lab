
from collections import Counter


def simulate_authentication(attempts=5, failures=5):
    """Generate synthetic authentication events without real logins."""
    if attempts < 1:
        raise ValueError("attempts must be at least 1")

    if failures < 0 or failures > attempts:
        raise ValueError("failures must be between 0 and attempts")

    events = []

    for number in range(attempts):
        events.append({
            "attempt": number + 1,
            "source": "SIMULATED_CLIENT_01",
            "username": "lab_user",
            "result": (
                "FAILURE" if number < failures else "SUCCESS"
            ),
        })

    return events


def detect_repeated_failures(events, threshold=3):
    """Flag simulated sources with failures at or above threshold."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    counts = Counter(
        event["source"]
        for event in events
        if event.get("result") == "FAILURE"
    )

    findings = []

    for source, count in counts.items():
        if count < threshold:
            continue

        if count >= 10:
            severity = "HIGH"
        elif count >= 5:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        findings.append({
            "source": source,
            "failed_attempts": count,
            "severity": severity,
            "finding": "REPEATED_AUTHENTICATION_FAILURES",
        })

    return findings






