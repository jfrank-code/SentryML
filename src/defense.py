import json
import subprocess
import urllib.request


class DefenseModule:

  def __init__(self, webhook_url: str = None):
    self.webhook_url = webhook_url
    self.blocked_ips = set()

  def is_blocked(self, ip_str: str) -> bool:
    return ip_str in self.blocked_ips

  def block_ip(self, ip_str: str) -> str:
    if ip_str in self.blocked_ips:
      return "ALREADY_BLOCKED"
    self.blocked_ips.add(ip_str)
    try:
      subprocess.run(
          ["iptables", "-A", "INPUT", "-s", ip_str, "-j", "DROP"],
          check=True,
          stdout=subprocess.DEVNULL,
          stderr=subprocess.DEVNULL,
      )
      return "FIREWALL_BLOCKED"
    except Exception:
      return "SOFTWARE_FILTERED"

  def send_alert(self, payload: dict) -> bool:
    if not self.webhook_url:
      return False
    try:
      data = json.dumps(payload).encode("utf-8")
      req = urllib.request.Request(
          self.webhook_url,
          data=data,
          headers={"Content-Type": "application/json"},
      )
      with urllib.request.urlopen(req, timeout=2):
        return True
    except Exception:
      return False