"""Tests for GeoEngine (geo.py): IP validation and binary search."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from geo import GeoEngine  # noqa: E402


class TestIpToInt(unittest.TestCase):

  def setUp(self):
    self.geo = GeoEngine()

  def test_valid_ip(self):
    self.assertEqual(self.geo._ip_to_int("0.0.0.1"), 1)
    self.assertEqual(self.geo._ip_to_int("1.0.0.0"), 16777216)

  def test_invalid_ip_wrong_octet_count_returns_sentinel(self):
    self.assertEqual(self.geo._ip_to_int("1.2.3"), -1)
    self.assertEqual(self.geo._ip_to_int("1.2.3.4.5"), -1)

  def test_invalid_ip_out_of_range_octet_returns_sentinel(self):
    self.assertEqual(self.geo._ip_to_int("999.1.1.1"), -1)
    self.assertEqual(self.geo._ip_to_int("1.1.1.-5"), -1)

  def test_garbage_input_returns_sentinel_not_zero(self):
    self.assertEqual(self.geo._ip_to_int("not-an-ip"), -1)
    self.assertNotEqual(self.geo._ip_to_int("not-an-ip"), 0)


class TestLookupWithFallback(unittest.TestCase):

  def setUp(self):
    self.geo = GeoEngine()
    self.geo.load_db("/path/that/does/not/exist.csv") 

  def test_known_fallback_ip_resolves(self):
    self.assertEqual(self.geo.lookup("8.8.8.8"), "US")
    self.assertEqual(self.geo.lookup("1.1.1.1"), "AU")

  def test_unknown_ip_returns_unknown(self):
    self.assertEqual(self.geo.lookup("203.0.113.99"), "UNKNOWN")

  def test_invalid_ip_returns_unknown_not_wrong_country(self):
    self.assertEqual(self.geo.lookup("garbage"), "UNKNOWN")

  def test_empty_db_returns_unknown(self):
    empty_geo = GeoEngine()
    self.assertEqual(empty_geo.lookup("8.8.8.8"), "UNKNOWN")


if __name__ == "__main__":
  unittest.main()