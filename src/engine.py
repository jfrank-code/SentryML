from collections import defaultdict
import math


class StatsEngine:

  @staticmethod
  def shannon_entropy(paths: list[str]) -> float:
    if not paths:
      return 0.0
    total = len(paths)
    counts = defaultdict(int)
    for p in paths:
      counts[p] += 1
    return -sum(
        (cant / total) * math.log2(cant / total) for cant in counts.values()
    )

  @staticmethod
  def calculate_mad(data: list) -> tuple[float, float]:
    if not data:
      return 0.0, 0.0
    sorted_data = sorted(data)
    n = len(sorted_data)
    median = sorted_data[n // 2]
    devs = sorted([abs(x - median) for x in data])
    mad = devs[n // 2]
    return float(median), float(mad)


class KMeansNative:

  def __init__(self, k: int = 3, max_iters: int = 20):
    self.k = k
    self.max_iters = max_iters
    self.centroids = []

  def fit_predict(self, data: list[list[float]]) -> list[int]:
    """Trains centroids (Lloyd's algorithm) and classifies `data` in one call.
    Use only for initial training; for stable classification afterward,
    use predict_point instead."""
    if not data:
      return []
    if len(data) < self.k:
      return [0] * len(data)

    step = len(data) // self.k
    self.centroids = [data[i * step] for i in range(self.k)]
    assignments = [0] * len(data)

    for _ in range(self.max_iters):
      new_assignments = []
      for point in data:
        distances = [
            math.sqrt(sum((p - c) ** 2 for p, c in zip(point, centroid)))
            for centroid in self.centroids
        ]
        new_assignments.append(distances.index(min(distances)))

      if new_assignments == assignments:
        break
      assignments = new_assignments

      for i in range(self.k):
        cluster_points = [
            data[j] for j in range(len(data)) if assignments[j] == i
        ]
        if cluster_points:
          dim = len(data[0])
          self.centroids[i] = [
              sum(p[d] for p in cluster_points) / len(cluster_points)
              for d in range(dim)
          ]
    return assignments

  def predict_point(self, point: list[float]) -> int:
    """Classifies a point against already-learned centroids without
    retraining, so the same input always yields the same cluster."""
    if not self.centroids:
      return 0
    distances = [
        math.sqrt(sum((p - c) ** 2 for p, c in zip(point, centroid)))
        for centroid in self.centroids
    ]
    return distances.index(min(distances))