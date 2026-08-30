"""Tests for StatsEngine and KMeansNative (engine.py).

Run with: python3 -m unittest discover -s tests
(Uses the standard library's unittest, not pytest—ensuring zero dependencies
for the test suite as well, avoiding the need for dev-only dependency exceptions).
"""
import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from engine import KMeansNative, StatsEngine  # noqa: E402


class TestShannonEntropy(unittest.TestCase):

  def test_empty_list_is_zero(self):
    self.assertEqual(StatsEngine.shannon_entropy([]), 0.0)

  def test_single_repeated_path_is_zero_entropy(self):
    # All the "probability mass" on a single path -> no uncertainty
    self.assertAlmostEqual(
        StatsEngine.shannon_entropy(["/index.html"] * 10), 0.0
    )

  def test_uniform_distribution_is_max_entropy(self):
    # 4 distinct routes, each occurring once -> entropy = log2(4) = 2.0
    paths = ["/a", "/b", "/c", "/d"]
    self.assertAlmostEqual(StatsEngine.shannon_entropy(paths), math.log2(4))

  def test_skewed_distribution_between_bounds(self):
    paths = ["/a"] * 8 + ["/b", "/c"]
    entropy = StatsEngine.shannon_entropy(paths)
    self.assertGreater(entropy, 0.0)
    self.assertLess(entropy, math.log2(3))


class TestCalculateMAD(unittest.TestCase):

  def test_empty_list(self):
    self.assertEqual(StatsEngine.calculate_mad([]), (0.0, 0.0))

  def test_constant_values_zero_mad(self):
    median, mad = StatsEngine.calculate_mad([100.0] * 5)
    self.assertEqual(median, 100.0)
    self.assertEqual(mad, 0.0)

  def test_mad_robust_to_single_outlier(self):
    values = [10.0, 11.0, 9.0, 10.0, 10.0, 5000.0]
    median, mad = StatsEngine.calculate_mad(values)
    self.assertLess(mad, 50.0)


class TestKMeansNative(unittest.TestCase):

  def test_empty_data(self):
    kmeans = KMeansNative(k=3)
    self.assertEqual(kmeans.fit_predict([]), [])

  def test_fewer_points_than_k(self):
    kmeans = KMeansNative(k=3)
    result = kmeans.fit_predict([[1.0, 1.0]])
    self.assertEqual(result, [0])

  def test_predict_point_without_training_defaults_to_zero(self):
    kmeans = KMeansNative(k=3)
    self.assertEqual(kmeans.predict_point([100.0, 100.0]), 0)

  def test_predict_point_is_stable_after_training(self):
    data = (
        [[10.0, 10.0]] * 5
        + [[500.0, 500.0]] * 5
        + [[2000.0, 2000.0]] * 5
    )
    kmeans = KMeansNative(k=3)
    kmeans.fit_predict(data)

    # The same point, when queried multiple times, must ALWAYS fall into the
    # same cluster (unlike retraining with fit_predict each time).
    first = kmeans.predict_point([15.0, 15.0])
    for _ in range(10):
      self.assertEqual(kmeans.predict_point([15.0, 15.0]), first)

    far_point_cluster = kmeans.predict_point([2010.0, 2010.0])
    self.assertNotEqual(first, far_point_cluster)


if __name__ == "__main__":
  unittest.main()