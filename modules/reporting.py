
import json
from datetime import datetime, timezone
from pathlib import Path


def save_auth_report(events, findings, report_dir="reports"):
    """Save synthetic authentication simulation results as JSON."""
    output_dir = Path(report_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "simulation": "MOCK_AUTHENTICATION",
        "events": events,
        "findings": findings,
    }

    report_path = output_dir / "auth_simulation_report.json"

    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    return report_path


def save_recon_report(results, report_dir="reports"):
    """Save localhost reconnaissance results as JSON."""
    import json
    from datetime import datetime, timezone
    from pathlib import Path

    output_dir = Path(report_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_type": "LOCALHOST_ALLOWLISTED_TCP_CHECK",
        "target": "127.0.0.1",
        "results": results,
    }

    report_path = output_dir / "recon_report.json"
    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    return report_path

def save_consolidated_report(
    auth_findings,
    recon_results,
    report_dir="reports",
):
    """Save authentication and reconnaissance findings together."""
    import json
    from datetime import datetime, timezone
    from pathlib import Path

    output_dir = Path(report_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report_type": "CONSOLIDATED_SECURITY_INVESTIGATION",
        "authentication_findings": auth_findings,
        "reconnaissance_results": recon_results,
        "summary": {
            "total_authentication_findings": len(auth_findings),
            "ports_checked": len(recon_results),
            "open_ports": sum(
                result.get("state") == "open"
                for result in recon_results
            ),
        },
    }

    report_path = output_dir / "consolidated_incident_report.json"
    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    return report_path
