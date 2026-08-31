# SentryML — Native Anomaly Detection & Active Defense Engine

**Track E — Security & Crypto Utilities**
**Zero third-party runtime dependencies.** `requirements.txt` is empty. Verified by [`deps_proof.py`](#dependency-proof).

SentryML is a real-time HTTP threat-detection engine: it parses server logs (or simulates them for demo/benchmarking), scores anomalous behavior per IP using hand-rolled statistics and machine learning, anonymizes sensitive data, and actively mitigates threats — all on the Python 3.14 standard library, with nothing installed from PyPI.

---

## What it actually does

1. **Ingests traffic** — either from a **real HTTP log file** (Combined/Common Log Format, tailed live like `tail -f`) via `--log-file`, or from a **built-in synthetic traffic generator** (3 realistic classes: normal user, crawler/scraper, brute-force attack) for demos and benchmarks when no real log is available.
2. **Scores anomalies natively**:
   - **Shannon entropy** over recently requested paths per IP — flags scanners hitting many distinct/suspicious routes.
   - **Robust Z-score via MAD** (Median Absolute Deviation) over request rate — flags volume spikes, resistant to being thrown off by a single earlier outlier.
   - **K-Means clustering** (Lloyd's algorithm, hand-rolled) — classifies each IP's traffic profile as `NORMAL_TRAFFIC`, `CRAWLER_LIKE`, or `MASS_ATTACK`, trained once at startup on a representative synthetic sample (see [Design notes](#design-notes) for why).
3. **Anonymizes sensitive data** — IPs are never stored or alerted on in plaintext; they're hashed with HMAC-SHA256 and a `secrets`-generated salt before persistence or webhook dispatch.
4. **Resolves geography with zero external calls** — binary search (hand-written, no `bisect`) over a local IP-range→country CSV (RIR/RIPE-style).
5. **Mitigates actively** — blocks offending IPs via `iptables` (Linux), with an automatic software-level fallback (in-process filtering) if `iptables` is unavailable.
6. **Alerts externally** — dispatches structured JSON to a configured webhook (Discord/Slack-compatible) via `urllib.request`.
7. **Persists state** — blocked IPs and the anonymization salt survive restarts (`sentry_state.json`), so hashes stay consistent across sessions.
8. **Serves a live web dashboard** (optional, `--web`) — a zero-dependency alternative to the terminal UI: `http.server` streams detection events over Server-Sent Events to a vanilla HTML/CSS/JS frontend (no Flask, no Socket.IO, no React, no CDN). The dashboard includes **Pause/Resume** and **Reset** controls (`POST /pause`, `/resume`, `/reset`, `GET /status`) — essential for a long-lived deployment, since the engine otherwise never stops generating synthetic traffic. Judges can open one URL and watch the engine detect and mitigate threats live, no terminal access needed.

---

## For judges: from a fresh clone, in under a minute

**A note on commands below:** this project only needs a Python interpreter, no `make` — `make` is a convenience wrapper (pre-installed on macOS/Linux, not on Windows by default). If `make` isn't available, use the direct `python`/`python3` commands shown under each `make` target — same result, zero difference in what actually runs.

**Which Python command to use:** macOS/Linux typically ship both Python 2 and 3, so the command is `python3` to be unambiguous. Windows typically only has Python 3 installed, under the command `python` (or `py`). If one doesn't work, try the other — whichever runs `Python 3.10+` when you check `python --version` / `python3 --version` is the right one for this project.

**The web dashboard (`--web`):** also exposes `POST /pause`, `POST /resume`, `GET /status`, and `POST /reset` — visible as buttons in the UI, useful if you're evaluating a long-running deployment instead of a fresh local run.

```bash
git clone <this-repo-url>
cd sentryml
python3 --version        # or: python --version  (needs 3.10+; built & tested on 3.14)

# 1. Confirm zero third-party imports
make deps-proof                    # or: python3 deps_proof.py   (Windows: python deps_proof.py)

# 2. Confirm the test suite passes (30 tests)
make test                          # or: python3 -m unittest discover -s tests
                                    #     (Windows: python -m unittest discover -s tests)

# 3. Run the live engine (synthetic demo traffic, terminal UI)
make run                           # or: cd src && python3 __main__.py
                                    #     (Windows: cd src; python __main__.py)

# 4. (Optional) Live WEB dashboard instead of the terminal — click and play
make web                           # or: cd src && python3 __main__.py --web
                                    # then open http://localhost:8000

# 5. (Optional) Point it at a real HTTP log file instead of synthetic traffic
make demo LOG=/path/to/access.log  # or: cd src && python3 __main__.py --log-file /path/to/access.log
```

`make run` starts the TUI immediately — no `geo_db.csv` needs to be provided; if it's missing, `GeoEngine` falls back to a small built-in dataset covering the demo's IP pool, so the engine runs out of the box. Press `Ctrl+C` to stop it cleanly. A `sentry_state.json` will appear in `src/` after the first blocked IP — that's expected, runtime state, not part of the repo (see `.gitignore`).

---

## Quick start

```bash
# Demo mode (synthetic traffic, no log file needed)
make run

# Against a real HTTP log file, tailed live
make demo LOG=/var/log/nginx/access.log

# Benchmark suite (1,000,000 synthetic records — time + peak RAM)
make bench

# Run the test suite (unittest, stdlib only)
make test

# Confirm zero third-party imports
make deps-proof
```

Or without `make`:
```bash
cd src
python3 __main__.py                          # demo mode
python3 __main__.py --log-file access.log    # real log mode
python3 __main__.py --bench                  # benchmark
python3 __main__.py --webhook https://your-webhook-url
```

Requires **Python 3.10+** (uses `sys.stdlib_module_names` in `deps_proof.py`; the core engine itself only needs the modules listed below, available since much earlier versions). Built and tested against Python 3.14.

---

## Dependency proof

```bash
$ python3 deps_proof.py
[SentryML] Scanning src for non-stdlib imports (Python 3.14.x)...
[OK] Zero third-party imports detected across all source files.
[OK] 100% Python standard library. dependencies: {}
```

`deps_proof.py` parses every file in `src/` with `ast`, extracts every `import`/`from ... import`, and checks each module name against `sys.stdlib_module_names` and this project's own internal modules. Anything else fails the check with an exit code of 1 and a precise list of offending imports. It is itself zero-dependency (`ast`, `sys`, `pathlib`).

Modules actually imported, project-wide: `argparse`, `json`, `os`, `random`, `time`, `tracemalloc`, `collections`, `math`, `csv`, `re`, `subprocess`, `urllib.request`, `hashlib`, `hmac`, `secrets`. All standard library.

---

## Project layout

```
sentryml/
├── README.md
├── STDLIB.md
├── requirements.txt      # empty — dependencies: {}
├── .zero-dep.toml        # track + one-line pitch
├── Makefile
├── deps_proof.py         # dependency verification script
├── src/
│   ├── __main__.py         # entry point, orchestration, CLI/web/log-mode dispatch
│   ├── engine.py           # StatsEngine (entropy, MAD) + KMeansNative
│   ├── ingest.py           # real log tailing + parsing + per-IP state
│   ├── webserver.py        # zero-dependency web dashboard (http.server + SSE)
│   ├── static/
│   │   └── index.html      # vanilla HTML/CSS/JS dashboard frontend, no CDN
│   ├── geo.py               # zero-API GeoIP via hand-written binary search
│   ├── defense.py          # iptables/software mitigation + webhook alerts
│   └── crypto.py           # HMAC-SHA256 anonymization
└── tests/                 # unittest suite, 30 tests, stdlib only
```

---

## Design notes (honest limitations)

- **K-Means is trained once, not every tick.** Early iterations of this engine re-ran `fit_predict()` on a sliding window every cycle, which made the same traffic volume sometimes classify as `CRAWLER_LIKE` and sometimes as `MASS_ATTACK` between ticks — the centroids were relative to whatever was in the last 30 samples, not a fixed reference. The engine now runs a one-time **warm-up phase** at startup: it trains on 300 synthetic samples (100 each of normal/crawler/attack — three genuinely distinct populations, not two forced into three), fixes the centroids, and classifies every subsequent point with `predict_point()` against that fixed reference. This trades a small amount of adaptability for **stable, reproducible classification** — the right tradeoff for a security tool where a judge (or an operator) needs to trust that the same input always yields the same verdict.
- **Risk level vs. traffic pattern are two separate signals, on purpose.** `Threat Level` (LOW/MED/HIGH) comes from `threat_score`, a formula over fixed thresholds — always reproducible. `Traffic Pattern` comes from K-Means and describes *behavior type*, not severity. They're kept separate because collapsing them into one label produced a system that looked inconsistent for reasons that were actually correct (see above).
- **MAD always contributes to `threat_score`, even for whitelisted-looking paths.** An earlier version zeroed out the MAD (volume) contribution whenever all requested paths were in the "normal" set, to reduce false positives — but that opened a real detection gap: a volumetric flood against legitimate routes (e.g., hammering `/index.html`) would have been invisible. The fix keeps MAD always active; only the entropy weight is reduced for pure-normal-path traffic, so path diversity doesn't overpenalize legitimate crawling while volume spikes are still caught regardless of which paths they hit.
- **`iptables` is Linux-specific.** `defense.py` attempts `iptables -A INPUT -s <ip> -j DROP` and falls back to in-process software filtering (`is_blocked()` checked before any per-IP processing) if the command fails or isn't available — so the engine still degrades gracefully on macOS/Windows or in a restricted container, just without kernel-level blocking.
- **Median uses `n // 2`** (not the average of the two central elements for even-length lists) — a deliberate simplification for a hackathon timeframe, not an oversight. Documented here rather than left for a reviewer to discover.
- **The default `--webhook` points to `https://httpbin.org/post`**, a public echo endpoint — safe for testing without configuring a real Discord/Slack webhook, but should be overridden for actual use.
- **Real log mode (`--log-file`) vs demo mode**: the log-mode path (`ingest.py` + `run_log_mode`) computes entropy/RPS from real per-IP state built from actual log lines. Demo mode (`run_demo_mode` / `run_web_mode`) uses the synthetic generator for environments with no real traffic to point at (development, benchmarking, the demo video). Both feed the exact same scoring, clustering, and mitigation pipeline — nothing about the detection logic changes between the two.
- **The terminal UI and the web dashboard share one detection loop** (`run_demo_loop` in `__main__.py`), driven by an `on_tick` callback — the CLI renders it as colored terminal text, the web mode broadcasts it as JSON over SSE. They can't silently drift apart from each other, because there's only one place the detection math actually runs.
- **The web frontend has zero external requests**: no CDN scripts, no Google Fonts, no analytics — just the browser's built-in `EventSource` API and system fonts. This was a deliberate choice to keep the "zero dependency" story honest end-to-end, not just in the Python backend.
- **The web dashboard can be paused.** A synthetic-traffic demo left running for hours or days (e.g. a permanent deployment for judges to try) never stops generating traffic or growing `defense.blocked_ips` — there's no natural end state. A shared `threading.Event` gates the detection loop: `POST /pause` clears it (the loop idles cheaply without processing new traffic, while the HTTP server keeps serving), `POST /resume` sets it again. `GET /status` lets a freshly loaded page pick up the current state, so a second viewer sees "paused" correctly even if someone else paused it first. This doesn't shrink `blocked_ips` on its own — pausing stops it from growing further; **Reset** is what clears it.

---

## Package Killer highlight

**scikit-learn → hand-rolled K-Means (Lloyd's algorithm) in `engine.py`.**

scikit-learn averages **~57.6M downloads/week** on PyPI ([pypistats.org](https://pypistats.org/packages/scikit-learn)). SentryML's `KMeansNative` implements the full training loop (centroid initialization, iterative assignment, centroid recomputation, convergence check) and inference (`predict_point`, classification against fixed centroids) from the algorithm's mathematical definition — no reference to scikit-learn's source, which is itself mostly Cython/C, not plain Python.

See `STDLIB.md` for the complete substitution matrix.

---

## Security notes

- IP anonymization is **hashing (HMAC-SHA256), not encryption** — irreversible by design. There is no key that recovers the original IP from the hash; that's intentional for this use case (you need to correlate repeat offenders, not decrypt them back).
- The salt is generated with `secrets.token_bytes(16)` (CSPRNG, not `random`) and persisted in `sentry_state.json` so hashes stay consistent across restarts.
- Threat model: this engine assumes it runs on the same host or a trusted network segment as the server it protects. It does not authenticate webhook delivery beyond HTTPS transport, and `sentry_state.json` is not encrypted at rest — treat it as sensitive if the salt's secrecy matters for your deployment.