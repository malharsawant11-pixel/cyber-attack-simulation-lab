
import socket
from datetime import datetime, timezone


ALLOWED_TARGETS = {"127.0.0.1"}
ALLOWED_PORTS = {22, 80, 443, 8000, 8501}
CONNECT_TIMEOUT = 0.5


def scan_local_target(target="127.0.0.1"):
    """Check a small allowlist of TCP ports on localhost only."""
    if target not in ALLOWED_TARGETS:
        raise ValueError("Only the explicitly allowed localhost target is supported.")

    results = []

    for port in sorted(ALLOWED_PORTS):
        state = "closed"

        try:
            with socket.create_connection(
                (target, port),
                timeout=CONNECT_TIMEOUT,
            ):
                state = "open"
        except (ConnectionRefusedError, TimeoutError, OSError):
            pass

        results.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "port": port,
            "state": state,
        })

    return results
