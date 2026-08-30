"""Real HTTP log ingestion: live tail + parsing + per-IP state."""
import re
import time
from collections import defaultdict, deque

# Combined/Common Log Format:
# 190.119.1.5 - - [29/Aug/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 1024
LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)


def parse_log_line(line: str) -> dict | None:
  match = LOG_PATTERN.match(line.strip())
  if not match:
    return None
  return {
      "ip": match.group("ip"),
      "path": match.group("path"),
      "status": match.group("status"),
  }


def tail_file(filepath: str, poll_interval: float = 0.5):
  """`tail -f` equivalent: yields new lines as they're appended."""
  with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
    f.seek(0, 2)  # jump to end of file
    while True:
      line = f.readline()
      if not line:
        time.sleep(poll_interval)
        continue
      yield line


class PerIPWindow:
  """Recent paths and timestamps per IP, used to compute real entropy
  and RPS from actual log traffic."""

  def __init__(self, maxlen_paths: int = 20, rps_window_seconds: float = 5.0):
    self.maxlen_paths = maxlen_paths
    self.rps_window_seconds = rps_window_seconds
    self.paths_by_ip = defaultdict(lambda: deque(maxlen=maxlen_paths))
    self.timestamps_by_ip = defaultdict(lambda: deque(maxlen=500))

  def record(self, ip: str, path: str):
    now = time.monotonic()
    self.paths_by_ip[ip].append(path)
    self.timestamps_by_ip[ip].append(now)

  def recent_paths(self, ip: str) -> list[str]:
    return list(self.paths_by_ip[ip])

  def requests_per_second(self, ip: str) -> float:
    now = time.monotonic()
    ts = self.timestamps_by_ip[ip]
    while ts and (now - ts[0]) > self.rps_window_seconds:
      ts.popleft()
    if not ts:
      return 0.0
    return len(ts) / self.rps_window_seconds