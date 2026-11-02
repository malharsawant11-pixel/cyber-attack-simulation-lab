
import unittest
from unittest.mock import patch

from modules.recon import scan_local_target


class TestLocalRecon(unittest.TestCase):

    def test_rejects_non_local_targets(self):
        with self.assertRaises(ValueError):
            scan_local_target("10.0.2.15")

    @patch("modules.recon.socket.create_connection")
    def test_records_open_port(self, mock_connect):
        mock_connect.return_value.__enter__.return_value = None

        results = scan_local_target("127.0.0.1")

        self.assertTrue(results)
        self.assertTrue(
            all(item["target"] == "127.0.0.1" for item in results)
        )
        self.assertTrue(
            all(item["state"] in {"open", "closed"} for item in results)
        )
        self.assertTrue(
            any(item["state"] == "open" for item in results)
        )


if __name__ == "__main__":
    unittest.main()
