"""Zero-dependency web dashboard: http.server + Server-Sent Events.

No Flask, no FastAPI, no websockets library. The browser's built-in
EventSource API consumes a text/event-stream response — no JS library
needed on the frontend either. Everything here is Python standard
library: http.server, threading, queue, json, pathlib.
"""
import json
import os
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

STATIC_DIR = Path(__file__).parent / "static"


class EventBroadcaster:
  """Pub-sub fan-out so multiple browser tabs can watch the same live
  stream simultaneously (a plain queue.Queue would starve all but one
  consumer, since get() is destructive)."""

  def __init__(self):
    self._subscribers = []
    self._lock = threading.Lock()

  def subscribe(self) -> queue.Queue:
    q = queue.Queue()
    with self._lock:
      self._subscribers.append(q)
    return q

  def unsubscribe(self, q: queue.Queue):
    with self._lock:
      if q in self._subscribers:
        self._subscribers.remove(q)

  def publish(self, event: dict):
    with self._lock:
      subs = list(self._subscribers)
    for q in subs:
      q.put(event)


def make_handler(broadcaster: EventBroadcaster, defense_ref=None, running_event=None):
  class SentryHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
      pass  # keep stdout clean for the CLI's own output

    def do_GET(self):
      if self.path in ("/", "/index.html"):
        self._serve_static("index.html", "text/html; charset=utf-8")
      elif self.path == "/events":
        self._serve_sse()
      elif self.path == "/status":
        self._serve_status()
      else:
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
      if self.path == "/reset":
        self._handle_reset()
      elif self.path == "/pause":
        self._handle_pause()
      elif self.path == "/resume":
        self._handle_resume()
      else:
        self.send_response(404)
        self.end_headers()

    def _json_response(self, payload: dict):
      body = json.dumps(payload).encode("utf-8")
      self.send_response(200)
      self.send_header("Content-Type", "application/json")
      self.send_header("Access-Control-Allow-Origin", "*")
      self.end_headers()
      self.wfile.write(body)

    def _handle_reset(self):
      if defense_ref is not None:
        defense_ref.reset()
      if os.path.exists("sentry_state.json"):
        try:
          os.remove("sentry_state.json")
        except Exception:
          pass
      self._json_response({"status": "ok", "message": "State reset successfully"})

    def _handle_pause(self):
      if running_event is not None:
        running_event.clear()
      broadcaster.publish({"type": "system", "event": "paused"})
      self._json_response({"status": "ok", "paused": True})

    def _handle_resume(self):
      if running_event is not None:
        running_event.set()
      broadcaster.publish({"type": "system", "event": "resumed"})
      self._json_response({"status": "ok", "paused": False})

    def _serve_status(self):
      paused = running_event is not None and not running_event.is_set()
      self._json_response({"paused": paused})

    def _serve_static(self, name: str, content_type: str):
      filepath = STATIC_DIR / name
      try:
        body = filepath.read_bytes()
      except FileNotFoundError:
        self.send_response(404)
        self.end_headers()
        return
      self.send_response(200)
      self.send_header("Content-Type", content_type)
      self.send_header("Content-Length", str(len(body)))
      self.end_headers()
      self.wfile.write(body)

    def _serve_sse(self):
      self.send_response(200)
      self.send_header("Content-Type", "text/event-stream")
      self.send_header("Cache-Control", "no-cache")
      self.send_header("Connection", "keep-alive")
      self.send_header("Access-Control-Allow-Origin", "*")
      self.end_headers()

      q = broadcaster.subscribe()
      try:
        while True:
          event = q.get()
          payload = json.dumps(event)
          self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
          self.wfile.flush()
      except (BrokenPipeError, ConnectionResetError):
        pass
      finally:
        broadcaster.unsubscribe(q)

  return SentryHandler


def start_web_server(broadcaster: EventBroadcaster, host: str, port: int,
                      defense_ref=None, running_event=None) -> ThreadingHTTPServer:
  """Starts the server in a background thread and returns it (so the
  caller can .shutdown() it later if needed)."""
  handler_cls = make_handler(broadcaster, defense_ref=defense_ref, running_event=running_event)
  server = ThreadingHTTPServer((host, port), handler_cls)
  thread = threading.Thread(target=server.serve_forever, daemon=True)
  thread.start()
  return server