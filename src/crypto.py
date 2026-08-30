import hashlib
import hmac
import secrets


class SecurityManager:

  def __init__(self, salt: bytes = None):
    self.salt = salt if salt else secrets.token_bytes(16)

  def anonymize_ip(self, ip_str: str) -> str:
    h = hmac.new(self.salt, ip_str.encode("utf-8"), hashlib.sha256)
    return h.hexdigest()[:16]