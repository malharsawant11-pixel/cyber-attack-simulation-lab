
import json
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

ALLOWED_TARGETS = {"127.0.0.1"}
ALLOWED_PORTS = [22, 80, 443, 8000, 8501]


def run_nmap_scan(target="127.0.0.1"):
    """Run a restricted Nmap TCP connect scan."""

    if target not in ALLOWED_TARGETS:
        raise ValueError("Target is not in the authorized allowlist.")

    ports = ",".join(map(str, ALLOWED_PORTS))

    command = [
        "nmap",
        "-sT",
        "-sV",
        "-T3",
        "-p", ports,
        "-oX", "-",
        target,
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Nmap scan failed: {result.stderr.strip()}"
        )

    root = ET.fromstring(result.stdout)
    scan_results = []

    for host in root.findall("host"):
        for port in host.findall(".//port"):
            state_element = port.find("state")
            service_element = port.find("service")

            scan_results.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target": target,
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "state": (
                    state_element.get("state")
                    if state_element is not None
                    else "unknown"
                ),
                "service": (
                    service_element.get("name")
                    if service_element is not None
                    else "unknown"
                ),
                "version": (
                    service_element.get("version", "unknown")
                    if service_element is not None
                    else "unknown"
                ),
            })

    return scan_results
