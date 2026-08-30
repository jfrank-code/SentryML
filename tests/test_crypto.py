"""Tests for SecurityManager (crypto.py): deterministic hashing with salt."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from crypto import SecurityManager  # noqa: E402


class TestSecurityManager(unittest.TestCase):

  def test_same_salt_same_ip_gives_same_hash(self):
    salt = b"\x00" * 16
    sec_a = SecurityManager(salt=salt)
    sec_b = SecurityManager(salt=salt)
    self.assertEqual(
        sec_a.anonymize_ip("8.8.8.8"), sec_b.anonymize_ip("8.8.8.8")
    )

  def test_different_salt_gives_different_hash(self):
    sec_a = SecurityManager(salt=b"\x00" * 16)
    sec_b = SecurityManager(salt=b"\xff" * 16)
    self.assertNotEqual(
        sec_a.anonymize_ip("8.8.8.8"), sec_b.anonymize_ip("8.8.8.8")
    )

  def test_hash_is_irreversible_by_length(self):
    sec = SecurityManager(salt=b"\x00" * 16)
    result = sec.anonymize_ip("8.8.8.8")
    self.assertEqual(len(result), 16)
    self.assertNotIn("8.8.8.8", result)

  def test_no_salt_provided_generates_random_salt(self):
    sec_a = SecurityManager()
    sec_b = SecurityManager()
    self.assertNotEqual(sec_a.salt, sec_b.salt)


if __name__ == "__main__":
  unittest.main()