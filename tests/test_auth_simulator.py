
import unittest

from modules.auth_simulator import (
    simulate_authentication,
    detect_repeated_failures,
)


class TestAuthSimulator(unittest.TestCase):

    def test_generates_synthetic_failures(self):
        events = simulate_authentication(attempts=5, failures=5)
        self.assertEqual(len(events), 5)
        self.assertTrue(
            all(event["result"] == "FAILURE" for event in events)
        )

    def test_detects_repeated_failures(self):
        events = simulate_authentication(attempts=5, failures=4)
        findings = detect_repeated_failures(events, threshold=3)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["failed_attempts"], 4)

    def test_below_threshold_is_not_flagged(self):
        events = simulate_authentication(attempts=5, failures=2)
        findings = detect_repeated_failures(events, threshold=3)
        self.assertEqual(findings, [])

    def test_invalid_attempt_count_is_rejected(self):
        with self.assertRaises(ValueError):
            simulate_authentication(attempts=0)

    def test_invalid_threshold_is_rejected(self):
        with self.assertRaises(ValueError):
            detect_repeated_failures([], threshold=0)


if __name__ == "__main__":
    unittest.main()
