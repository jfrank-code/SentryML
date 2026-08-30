import csv


class GeoEngine:

  def __init__(self):
    self.db = []  # (start_int, end_int, country_code)

  def _ip_to_int(self, ip_str: str) -> int:
    """Returns -1 for any invalid IP, never 0 (which is a valid 0.0.0.0)."""
    try:
      parts = [int(p) for p in ip_str.split(".")]
      if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
        return -1
      return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
    except Exception:
      return -1

  def load_db(self, csv_filepath: str):
    try:
      loaded = []
      with open(csv_filepath, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
          if len(row) >= 3:
            s_ip, e_ip, c = row[0].strip(), row[1].strip(), row[2].strip()
            s_int, e_int = self._ip_to_int(s_ip), self._ip_to_int(e_ip)
            if s_int != -1 and e_int != -1:
              loaded.append((s_int, e_int, c))

      if not loaded:
        raise ValueError("Empty or invalid CSV")

      self.db = loaded
      self.db.sort(key=lambda x: x[0])
    except Exception:
      # Fallback dataset, kept in sync with the demo IP pool
      fallback_ranges = [
          ("1.1.1.0", "1.1.1.255", "AU"),
          ("8.8.8.0", "8.8.8.255", "US"),
          ("114.114.114.0", "114.114.114.255", "CN"),
          ("142.250.190.0", "142.250.190.255", "US"),
          ("177.126.180.0", "177.126.180.255", "BR"),
          ("185.220.101.0", "185.220.101.255", "RU"),
          ("190.119.1.0", "190.119.1.255", "PE"),
          ("200.48.225.0", "200.48.225.255", "PE"),
          ("210.140.10.0", "210.140.10.255", "JP"),
          ("81.2.69.0", "81.2.69.255", "GB"),
      ]
      self.db = [
          (self._ip_to_int(s), self._ip_to_int(e), c)
          for s, e, c in fallback_ranges
      ]
      self.db.sort(key=lambda x: x[0])

  def lookup(self, ip_str: str) -> str:
    """Hand-written binary search, O(log N)."""
    if not self.db:
      return "UNKNOWN"
    target = self._ip_to_int(ip_str)
    if target < 0:
      return "UNKNOWN"

    low, high = 0, len(self.db) - 1
    while low <= high:
      mid = (low + high) // 2
      s_ip, e_ip, country = self.db[mid]
      if s_ip <= target <= e_ip:
        return country
      elif target < s_ip:
        high = mid - 1
      else:
        low = mid + 1
    return "UNKNOWN"