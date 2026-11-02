
import json
import tempfile
import unittest
from pathlib import Path

from modules.reporting import save_auth_report


class TestReporting(unittest.TestCase):

    def test_report_saves_events_and_findings(self):
        events = [
            {
                "attempt": 1,
                "source": "SIMULATED_CLIENT_01",
                "username": "lab_user",
                "result": "FAILURE",
            }
        ]
        findings = [
            {
                "source": "SIMULATED_CLIENT_01",
                "failed_attempts": 1,
                "severity": "MEDIUM",
                "finding": "REPEATED_AUTHENTICATION_FAILURES",
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            path = save_auth_report(events, findings, temp_dir)
            report = json.loads(path.read_text(encoding="utf-8"))

            self.assertEqual(report["events"], events)
            self.assertEqual(report["findings"], findings)
            self.assertEqual(report["simulation"], "MOCK_AUTHENTICATION")
            self.assertIn("generated_at", report)

    def test_report_supports_empty_results(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = save_auth_report([], [], temp_dir)
            report = json.loads(path.read_text(encoding="utf-8"))

            self.assertEqual(report["events"], [])
            self.assertEqual(report["findings"], [])


if __name__ == "__main__":
    unittest.main()

import json
import tempfile
import unittest
from pathlib import Path

from modules.reporting import save_recon_report


class ReconReportingTests(unittest.TestCase):

    def test_recon_report_saves_results(self):
        results = [
            {
                "timestamp": "2026-10-15T07:48:28+00:00",
                "target": "127.0.0.1",
                "port": 8501,
                "state": "open",
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = save_recon_report(results, temp_dir)
            report = json.loads(
                Path(report_path).read_text(encoding="utf-8")
            )

            self.assertEqual(report["target"], "127.0.0.1")
            self.assertEqual(report["results"], results)
            self.assertEqual(
                report["scan_type"],
                "LOCALHOST_ALLOWLISTED_TCP_CHECK",
            )

    def test_recon_report_supports_empty_results(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = save_recon_report([], temp_dir)
            report = json.loads(
                Path(report_path).read_text(encoding="utf-8")
            )

            self.assertEqual(report["results"], [])


if __name__ == "__main__":
    unittest.main()

class ConsolidatedReportingTests(unittest.TestCase):

    def test_consolidated_report_saves_both_results(self):
        import json
        import tempfile
        from pathlib import Path
        from modules.reporting import save_consolidated_report

        auth_findings = [
            {
                "source": "SIMULATED_CLIENT_01",
                "failed_attempts": 5,
                "severity": "MEDIUM",
            }
        ]

        recon_results = [
            {
                "target": "127.0.0.1",
                "port": 8501,
                "state": "open",
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = save_consolidated_report(
                auth_findings,
                recon_results,
                temp_dir,
            )

            report = json.loads(
                Path(report_path).read_text(encoding="utf-8")
            )

            self.assertEqual(
                report["authentication_findings"], auth_findings
            )
            self.assertEqual(
                report["reconnaissance_results"], recon_results
            )
            self.assertEqual(report["summary"]["open_ports"], 1)

    def test_consolidated_report_supports_empty_results(self):
        import json
        import tempfile
        from pathlib import Path
        from modules.reporting import save_consolidated_report

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = save_consolidated_report(
                [], [], temp_dir
            )

            report = json.loads(
                Path(report_path).read_text(encoding="utf-8")
            )

            self.assertEqual(report["authentication_findings"], [])
            self.assertEqual(report["reconnaissance_results"], [])
            self.assertEqual(report["summary"]["open_ports"], 0)
