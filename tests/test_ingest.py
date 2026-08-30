"""Tests for ingest.py: parsing of real logs and status by IP."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ingest import PerIPWindow, parse_log_line  # noqa: E402


class TestParseLogLine(unittest.TestCase):

  def test_valid_combined_log_line(self):
    line = (
        '190.119.1.5 - - [29/Aug/2026:10:15:32 +0000] '
        '"GET /index.html HTTP/1.1" 200 1024'
    )
    result = parse_log_line(line)
    self.assertIsNotNone(result)
    self.assertEqual(result["ip"], "190.119.1.5")
    self.assertEqual(result["path"], "/index.html")
    self.assertEqual(result["status"], "200")

  def test_malformed_line_returns_none(self):
    self.assertIsNone(parse_log_line("this is not a log line"))

  def test_empty_line_returns_none(self):
    self.assertIsNone(parse_log_line(""))


class TestPerIPWindow(unittest.TestCase):

  def test_records_paths_per_ip(self):
    window = PerIPWindow()
    window.record("1.1.1.1", "/a")
    window.record("1.1.1.1", "/b")
    window.record("2.2.2.2", "/c")

    self.assertEqual(window.recent_paths("1.1.1.1"), ["/a", "/b"])
    self.assertEqual(window.recent_paths("2.2.2.2"), ["/c"])

  def test_unknown_ip_has_no_paths(self):
    window = PerIPWindow()
    self.assertEqual(window.recent_paths("9.9.9.9"), [])

  def test_rps_zero_for_ip_with_no_traffic(self):
    window = PerIPWindow()
    self.assertEqual(window.requests_per_second("9.9.9.9"), 0.0)

  def test_rps_increases_with_more_requests_in_window(self):
    window = PerIPWindow(rps_window_seconds=10.0)
    for _ in range(5):
      window.record("1.1.1.1", "/x")
    rps = window.requests_per_second("1.1.1.1")
    self.assertGreater(rps, 0.0)


if __name__ == "__main__":
  unittest.main()