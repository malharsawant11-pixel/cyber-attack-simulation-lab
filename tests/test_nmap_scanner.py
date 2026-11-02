
import unittest
from unittest.mock import patch, Mock

from modules.nmap_scanner import run_nmap_scan


class TestNmapScanner(unittest.TestCase):

    def test_rejects_unauthorized_target(self):
        with self.assertRaises(ValueError):
            run_nmap_scan("192.168.1.100")

    @patch("modules.nmap_scanner.subprocess.run")
    def test_parses_nmap_results(self, mock_run):
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""<?xml version="1.0"?>
            <nmaprun>
              <host>
                <ports>
                  <port protocol="tcp" portid="8501">
                    <state state="open"/>
                    <service name="http" version="unknown"/>
                  </port>
                </ports>
              </host>
            </nmaprun>""",
            stderr="",
        )

        results = run_nmap_scan()

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["port"], 8501)
        self.assertEqual(results[0]["state"], "open")
        self.assertEqual(results[0]["service"], "http")

    @patch("modules.nmap_scanner.subprocess.run")
    def test_handles_nmap_failure(self, mock_run):
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="Nmap execution failed",
        )

        with self.assertRaises(RuntimeError):
            run_nmap_scan()


if __name__ == "__main__":
    unittest.main()
