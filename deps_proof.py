"""Dependency proof: scan src/ and confirm zero third-party imports.

Use:
    python3 deps_proof.py

It compares each import against `sys.stdlib_module_names`
(the actual standard library of the running Python version) 
and against the project's own internal modules. If it finds 
something that is neither, it fails with exit code 1 and lists 
exactly which file and module are involved.

100% standard library: ast, sys, pathlib.
"""
import ast
import sys
from pathlib import Path

SRC_DIR = Path(__file__).parent / "src"
INTERNAL_MODULES = {"crypto", "defense", "engine", "geo", "ingest", "__main__"}


def find_third_party_imports(src_dir: Path) -> list[tuple[str, str]]:
  offenders = []
  stdlib = getattr(sys, "stdlib_module_names", frozenset())

  for pyfile in sorted(src_dir.glob("*.py")):
    tree = ast.parse(pyfile.read_text(encoding="utf-8"), filename=str(pyfile))
    for node in ast.walk(tree):
      modules = []
      if isinstance(node, ast.Import):
        modules = [alias.name.split(".")[0] for alias in node.names]
      elif isinstance(node, ast.ImportFrom) and node.module:
        modules = [node.module.split(".")[0]]

      for mod in modules:
        if mod in INTERNAL_MODULES:
          continue
        if mod in stdlib:
          continue
        offenders.append((pyfile.name, mod))

  return offenders


def main() -> int:
  print(f"[SentryML] Scanning {SRC_DIR} for non-stdlib imports "
        f"(Python {sys.version.split()[0]})...")

  offenders = find_third_party_imports(SRC_DIR)

  if offenders:
    print("\n[FAIL] THIRD-PARTY IMPORTS DETECTED:")
    for filename, module in offenders:
      print(f"  {filename}: {module}")
    return 1

  print("[OK] Zero third-party imports detected across all source files.")
  print("[OK] 100% Python standard library. dependencies: {}")
  return 0


if __name__ == "__main__":
  sys.exit(main())