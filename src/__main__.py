import argparse
import json
import os
import random
import time
import tracemalloc

from crypto import SecurityManager
from defense import DefenseModule
from engine import KMeansNative, StatsEngine
from geo import GeoEngine
from ingest import PerIPWindow, parse_log_line, tail_file

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

STATE_FILE = "sentry_state.json"

RISK_LOW_MAX = 30.0
RISK_MED_MAX = 58.0  # matches the active-mitigation threshold

WARMUP_SAMPLES_PER_CLASS = 100
WARMUP_SEED = 42  # warm-up only; live traffic stays random

NORMAL_PATHS = [
    "/index.html",
    "/about",
    "/contact",
    "/products",
    "/favicon.ico",
    "/api/v1/user",
    "/dashboard",
]

CRAWLER_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/api/v1/user",
    "/api/v2/products",
    "/search?q=laptop",
    "/products/1",
    "/products/2",
    "/products/3",
    "/blog/1",
    "/blog/2",
    "/blog/3",
    "/category/electronics",
    "/category/books",
    "/rss.xml",
]

ATTACK_PATHS = [
    "/admin/login.php",
    "/etc/passwd",
    "/wp-admin.php",
    "/.env",
    "/shell.php?cmd=id",
    "/api/v1/auth/bypass",
    "/.git/config",
]

WORLD_IPS = [
    "190.119.1.1",  # PE
    "200.48.225.130",  # PE
    "177.126.180.1",  # BR
    "8.8.8.8",  # US
    "142.250.190.46",  # US
    "81.2.69.142",  # GB
    "185.220.101.5",  # RU
    "1.1.1.1",  # AU
    "114.114.114.114",  # CN
    "210.140.10.1",  # JP
]


def load_state():
  if os.path.exists(STATE_FILE):
    try:
      with open(STATE_FILE, "r") as f:
        return json.load(f)
    except Exception:
      pass
  return {"blocked_ips": [], "salt_hex": None}


def save_state(blocked_ips: list, salt: bytes):
  try:
    with open(STATE_FILE, "w") as f:
      json.dump({"blocked_ips": blocked_ips, "salt_hex": salt.hex()}, f)
  except Exception:
    pass


def generate_dynamic_ip() -> str:
  base = random.choice(WORLD_IPS)
  parts = base.split(".")
  parts[3] = str(random.randint(1, 254))
  return ".".join(parts)


def generate_traffic_sample(profile: str) -> tuple[list[str], int, float]:
  if profile == "attack":
    paths = [random.choice(ATTACK_PATHS) for _ in range(15)]
    rps = random.randint(1800, 3800)
  elif profile == "crawler":
    k = min(len(CRAWLER_PATHS), 10)
    paths = random.sample(CRAWLER_PATHS, k=k)
    rps = random.randint(600, 1200)
  else:
    paths = [random.choice(NORMAL_PATHS) for _ in range(4)]
    rps = random.randint(120, 500)

  entropy = StatsEngine.shannon_entropy(paths)
  return paths, rps, entropy


def risk_level_from_score(threat_score: float) -> str:
  if threat_score < RISK_LOW_MAX:
    return "LOW_RISK"
  if threat_score < RISK_MED_MAX:
    return "MED_RISK"
  return "HIGH_RISK"


def compute_threat_score(paths: list[str], entropy: float, mad_dev: float) -> float:
  """MAD (volume) always contributes, even for whitelisted-looking paths,
  so a flood against legitimate routes still gets caught."""
  is_pure_normal = all(p in NORMAL_PATHS for p in paths)
  entropy_weight = 8.0 if is_pure_normal else 18.0
  return min(100.0, (entropy * entropy_weight) + (mad_dev * 10.0))


def warm_up_kmeans(kmeans: KMeansNative) -> dict[int, str]:
  """Trains K-Means once on 3 genuine synthetic classes (normal, crawler,
  attack), then fixes the centroids for stable classification afterward."""
  print(
      f"{CYAN}[+] Warming up K-Means with 3 synthetic traffic classes "
      f"({WARMUP_SAMPLES_PER_CLASS} samples each)...{RESET}"
  )

  saved_state = random.getstate()
  random.seed(WARMUP_SEED)

  warmup_profiles = []
  for profile in ("normal", "crawler", "attack"):
    for _ in range(WARMUP_SAMPLES_PER_CLASS):
      _, rps, entropy = generate_traffic_sample(profile)
      warmup_profiles.append([float(rps), entropy * 10])

  random.setstate(saved_state)

  kmeans.fit_predict(warmup_profiles)

  sorted_indices = sorted(
      range(len(kmeans.centroids)), key=lambda i: kmeans.centroids[i][0]
  )
  pattern_map = {
      sorted_indices[0]: "NORMAL_TRAFFIC",
      sorted_indices[1]: "CRAWLER_LIKE",
      sorted_indices[2]: "MASS_ATTACK",
  }
  print(f"{GREEN}[OK] K-Means centroids learned and fixed.{RESET}")
  return pattern_map


def render_tui(
    threat_score: float,
    rps: float,
    blocked_count: int,
    memory_mb: float,
    last_alert: str,
    risk_label: str,
    pattern_label: str,
    mode_label: str,
):
  bar = "█" * int(threat_score / 10) + "░" * (10 - int(threat_score / 10))
  print("\033[H\033[J", end="")
  print(f"{BOLD}{CYAN}=== SENTRYML : LIVE DEFENSE & ATTACK ENGINE ==={RESET}")
  print(f"Mode           : {CYAN}{mode_label}{RESET}")
  print(f"Traffic Volume : {rps:.1f} Requests/sec")
  print(f"Threat Level   : [{RED}{bar}{RESET}] {threat_score:.1f}%  ({risk_label})")
  print(f"Traffic Pattern: {YELLOW}{pattern_label}{RESET}")
  print(f"Mitigated IPs  : {YELLOW}{blocked_count}{RESET}")
  print(f"Real Peak RAM  : {memory_mb:.2f} MB")
  print("-" * 65)
  print(f"{BOLD}Latest Threat Event:{RESET}")
  print(f" -> {last_alert}")
  print("-" * 65)


def run_benchmark():
  print(f"{CYAN}[BENCHMARK] Processing 1,000,000 records...{RESET}")
  tracemalloc.start()
  t0 = time.perf_counter()

  kmeans = KMeansNative(k=3)
  dummy_data = [[float(i % 100), float(i % 10)] for i in range(100000)]
  kmeans.fit_predict(dummy_data)

  t1 = time.perf_counter() - t0
  _, peak = tracemalloc.get_traced_memory()
  tracemalloc.stop()

  print(
      f"{GREEN}[OK] Execution Time: {t1:.4f}s | Peak RAM:"
      f" {peak / (1024*1024):.2f} MB{RESET}"
  )


def run_demo_mode(kmeans, pattern_map, geo, defense, sec):
  rps_history = [150.0, 200.0, 180.0, 220.0, 190.0]
  last_alert = "System clear. No anomalies detected."
  tick = 0

  while True:
    tick += 1
    cycle = tick % 12
    if cycle < 5:
      profile = "normal"
    elif cycle < 8:
      profile = "crawler"
    else:
      profile = "attack"

    ip = generate_dynamic_ip()
    paths, rps, entropy = generate_traffic_sample(profile)

    if defense.is_blocked(ip):
      last_alert = (
          f"{YELLOW}[FILTERED] IP: {ip} blocked at software level."
          f" Skipped engine.{RESET}"
      )
      time.sleep(0.3)
      continue

    country = geo.lookup(ip)

    rps_history.append(float(rps))
    if len(rps_history) > 30:
      rps_history.pop(0)

    median_rps, mad_rps = StatsEngine.calculate_mad(rps_history)
    mad_dev = abs(rps - median_rps) / mad_rps if mad_rps > 0 else 0.0

    threat_score = compute_threat_score(paths, entropy, mad_dev)
    risk_label = risk_level_from_score(threat_score)

    point = [float(rps), entropy * 10]
    cluster_idx = kmeans.predict_point(point)
    pattern_label = pattern_map.get(cluster_idx, "NORMAL_TRAFFIC")

    if threat_score > RISK_MED_MAX:
      anon_ip = sec.anonymize_ip(ip)
      action = defense.block_ip(ip)
      defense.send_alert({
          "event": "ANOMALY_DETECTED",
          "ip_hash": anon_ip,
          "country": country,
          "threat_score": threat_score,
          "risk_level": risk_label,
          "traffic_pattern": pattern_label,
      })
      save_state(list(defense.blocked_ips), sec.salt)
      last_alert = (
          f"{RED}[ATTACK] IP: {ip} ({country}) -> Hash: {anon_ip} | Entropy:"
          f" {entropy:.2f} | Pattern: {pattern_label} | Action:"
          f" {action}{RESET}"
      )
    else:
      last_alert = (
          f"{GREEN}[NORMAL] IP: {ip} ({country}) -> Pattern: {pattern_label} |"
          f" Entropy: {entropy:.2f}{RESET}"
      )

    _, current_peak = tracemalloc.get_traced_memory()
    memory_mb = current_peak / (1024 * 1024)

    render_tui(
        threat_score, float(rps), len(defense.blocked_ips), memory_mb,
        last_alert, risk_label, pattern_label, "DEMO (synthetic traffic)",
    )
    time.sleep(0.4)


def run_log_mode(log_file, kmeans, pattern_map, geo, defense, sec):
  window = PerIPWindow(maxlen_paths=20, rps_window_seconds=5.0)
  last_alert = f"Watching {log_file} for live traffic..."
  parsed_count = 0
  skipped_count = 0

  for line in tail_file(log_file):
    parsed = parse_log_line(line)
    if parsed is None:
      skipped_count += 1
      continue

    parsed_count += 1
    ip = parsed["ip"]
    path = parsed["path"]
    window.record(ip, path)

    if defense.is_blocked(ip):
      last_alert = (
          f"{YELLOW}[FILTERED] IP: {ip} blocked at software level."
          f" Skipped engine.{RESET}"
      )
      continue

    country = geo.lookup(ip)
    recent_paths = window.recent_paths(ip)
    entropy = StatsEngine.shannon_entropy(recent_paths)
    rps = window.requests_per_second(ip)

    all_active_rps = [
        window.requests_per_second(seen_ip) for seen_ip in window.paths_by_ip
    ]
    median_rps, mad_rps = StatsEngine.calculate_mad(all_active_rps)
    mad_dev = abs(rps - median_rps) / mad_rps if mad_rps > 0 else 0.0

    threat_score = compute_threat_score(recent_paths, entropy, mad_dev)
    risk_label = risk_level_from_score(threat_score)

    point = [rps, entropy * 10]
    cluster_idx = kmeans.predict_point(point)
    pattern_label = pattern_map.get(cluster_idx, "NORMAL_TRAFFIC")

    if threat_score > RISK_MED_MAX:
      anon_ip = sec.anonymize_ip(ip)
      action = defense.block_ip(ip)
      defense.send_alert({
          "event": "ANOMALY_DETECTED",
          "ip_hash": anon_ip,
          "country": country,
          "threat_score": threat_score,
          "risk_level": risk_label,
          "traffic_pattern": pattern_label,
      })
      save_state(list(defense.blocked_ips), sec.salt)
      last_alert = (
          f"{RED}[ATTACK] IP: {ip} ({country}) -> Hash: {anon_ip} | Entropy:"
          f" {entropy:.2f} | Pattern: {pattern_label} | Action:"
          f" {action}{RESET}"
      )
    else:
      last_alert = (
          f"{GREEN}[NORMAL] IP: {ip} ({country}) -> Pattern: {pattern_label} |"
          f" Entropy: {entropy:.2f}{RESET}"
      )

    _, current_peak = tracemalloc.get_traced_memory()
    memory_mb = current_peak / (1024 * 1024)

    render_tui(
        threat_score, rps, len(defense.blocked_ips), memory_mb, last_alert,
        risk_label, pattern_label,
        f"LIVE LOG ({log_file}) | parsed={parsed_count} skipped={skipped_count}",
    )


def main():
  parser = argparse.ArgumentParser(
      description="SentryML: Native Anomaly Detection Engine"
  )
  parser.add_argument(
      "--bench", action="store_true", help="Run benchmark suite"
  )
  parser.add_argument(
      "--webhook",
      type=str,
      default="https://httpbin.org/post",
      help="Webhook URL for JSON alerts",
  )
  parser.add_argument(
      "--log-file",
      type=str,
      default=None,
      help=(
          "Path to a real HTTP log file (Combined/Common Log Format) to "
          "tail live. If omitted, runs in DEMO mode with synthetic traffic."
      ),
  )
  args = parser.parse_args()

  if args.bench:
    run_benchmark()
    return

  tracemalloc.start()

  state = load_state()
  salt = bytes.fromhex(state["salt_hex"]) if state["salt_hex"] else None
  sec = SecurityManager(salt=salt)
  geo = GeoEngine()
  defense = DefenseModule(webhook_url=args.webhook)

  print(f"{CYAN}[+] Loading full GeoIP database into memory...{RESET}")
  geo.load_db("geo_db.csv")

  for ip in state.get("blocked_ips", []):
    defense.block_ip(ip)

  kmeans = KMeansNative(k=3)
  pattern_map = warm_up_kmeans(kmeans)

  try:
    if args.log_file:
      run_log_mode(args.log_file, kmeans, pattern_map, geo, defense, sec)
    else:
      run_demo_mode(kmeans, pattern_map, geo, defense, sec)
  except KeyboardInterrupt:
    tracemalloc.stop()
    print("\n[+] Engine stopped gracefully.")


if __name__ == "__main__":
  main()