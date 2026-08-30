# Auto-detects python3 vs python (Windows typically only has "python").
PYTHON := $(shell command -v python3 2>/dev/null || command -v python)

.PHONY: run bench test deps-proof demo

# Runs the engine. DEMO mode (synthetic traffic) by default.
run:
	cd src && $(PYTHON) __main__.py

# Runs the engine against a real log: make demo LOG=/path/to/access.log
demo:
	cd src && $(PYTHON) __main__.py --log-file $(LOG)

# Benchmark suite (1,000,000 records, time + peak RAM)
bench:
	cd src && $(PYTHON) __main__.py --bench

# Runs the full test suite (unittest, stdlib only)
test:
	$(PYTHON) -m unittest discover -s tests -v

# Dependency proof: confirms zero third-party imports
deps-proof:
	$(PYTHON) deps_proof.py