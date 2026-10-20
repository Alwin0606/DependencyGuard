
import unittest
from unittest.mock import patch, Mock

from scanner import scan_package


class TestDependencyGuard(unittest.TestCase):

    @patch("scanner.requests.post")
    def test_package_without_vulnerabilities(self, mock_post):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"vulns": []}
        mock_post.return_value = response

        result = scan_package("packaging", "25.0")

        self.assertEqual(result, [])

    @patch("scanner.requests.post")
    def test_vulnerability_is_detected(self, mock_post):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-TEST-1234",
                    "summary": "Test vulnerability",
                    "aliases": ["CVE-2026-12345"]
                }
            ]
        }
        mock_post.return_value = response

        result = scan_package("demo-package", "1.0.0")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["id"], "GHSA-TEST-1234")

    @patch("scanner.requests.post")
    def test_network_error_is_reported(self, mock_post):
        mock_post.side_effect = __import__(
            "requests"
        ).exceptions.Timeout("Request timed out")

        result = scan_package("demo-package", "1.0.0")

        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
