
import unittest
import tempfile
from pathlib import Path

from modules.pdf_generator import generate_incident_pdf


class TestPDFGenerator(unittest.TestCase):

    def test_generates_incident_pdf(self):
        auth_findings = [
            {
                "source": "SIMULATED_CLIENT_01",
                "failed_attempts": 5,
                "severity": "MEDIUM",
                "finding": "REPEATED_AUTHENTICATION_FAILURES",
            }
        ]

        recon_results = [
            {
                "target": "127.0.0.1",
                "port": 8501,
                "protocol": "tcp",
                "state": "open",
                "service": "http",
            }
        ]

        attack_mappings = [
            {
                "mapped": True,
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "tactic": "Credential Access",
                "description": "Repeated authentication failures.",
                "recommendation": "Review authentication logs.",
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "incident_report.pdf"

            result = generate_incident_pdf(
                auth_findings,
                recon_results,
                attack_mappings,
                output_path,
            )

            self.assertTrue(result.exists())
            self.assertGreater(result.stat().st_size, 0)
            self.assertEqual(
                result.read_bytes()[:5],
                b"%PDF-",
            )

    def test_generates_pdf_with_empty_results(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "empty_report.pdf"

            result = generate_incident_pdf(
                [],
                [],
                [],
                output_path,
            )

            self.assertTrue(result.exists())
            self.assertGreater(result.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
