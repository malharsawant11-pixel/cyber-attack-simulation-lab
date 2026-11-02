
import unittest

from modules.attack_mapping import (
    map_finding_to_attack,
    map_all_findings,
)


class TestAttackMapping(unittest.TestCase):

    def test_maps_repeated_authentication_failures(self):
        finding = {
            "finding": "REPEATED_AUTHENTICATION_FAILURES",
            "failed_attempts": 5,
            "severity": "MEDIUM",
        }

        result = map_finding_to_attack(finding)

        self.assertTrue(result["mapped"])
        self.assertEqual(result["technique_id"], "T1110")
        self.assertEqual(result["tactic"], "Credential Access")

    def test_handles_unknown_finding(self):
        finding = {
            "finding": "UNKNOWN_SECURITY_EVENT"
        }

        result = map_finding_to_attack(finding)

        self.assertFalse(result["mapped"])
        self.assertEqual(
            result["message"],
            "No ATT&CK mapping available."
        )

    def test_maps_multiple_findings(self):
        findings = [
            {
                "finding": "REPEATED_AUTHENTICATION_FAILURES"
            },
            {
                "finding": "UNKNOWN_SECURITY_EVENT"
            },
        ]

        results = map_all_findings(findings)

        self.assertEqual(len(results), 2)
        self.assertTrue(results[0]["mapped"])
        self.assertFalse(results[1]["mapped"])


if __name__ == "__main__":
    unittest.main()
