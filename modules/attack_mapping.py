
ATTACK_MAPPINGS = {
    "REPEATED_AUTHENTICATION_FAILURES": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Repeated authentication failures may indicate "
            "attempts to guess valid credentials."
        ),
        "recommendation": (
            "Review authentication logs, enforce MFA, "
            "and apply account lockout policies."
        ),
    }
}


def map_finding_to_attack(finding):
    """Map a simulated security finding to MITRE ATT&CK."""

    finding_type = finding.get("finding")

    mapping = ATTACK_MAPPINGS.get(finding_type)

    if not mapping:
        return {
            "finding": finding_type,
            "mapped": False,
            "message": "No ATT&CK mapping available.",
        }

    return {
        "finding": finding_type,
        "mapped": True,
        **mapping,
    }


def map_all_findings(findings):
    """Map a list of security findings."""

    return [
        map_finding_to_attack(finding)
        for finding in findings
    ]
