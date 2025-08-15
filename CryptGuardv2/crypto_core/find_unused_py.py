#!/usr/bin/env python3
"""
Descobre módulos .py potencialmente NÃO USADOS construindo um grafo de imports
via AST e marcando os alcançáveis a partir de pontos de entrada.

Uso:
  python scripts/find_unused_py.py --entry main_app.py smoketest*.py crypto_core/__init__.py
  # ou deixe sem --entry: ele assume main_app.py, smoketest*.py, crypto_core/__init__.py se existirem.

Gera: unused_modules.json em project_root/
"""
from __future__ import annotations

import argparse
import ast
import fnmatch
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def discover_py(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*.py"):
        # ignora venvs, builds e o próprio scripts/
        if any(seg in p.parts for seg in (".venv", "venv", "build", "dist", "__pycache__", "site-packages")):
            continue
        out.append(p)
    return out

def module_name(p: Path) -> str:
    rel = p.relative_to(ROOT)
    parts = list(rel.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)

def parse_imports(p: Path) -> set[str]:
    src = p.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(src, filename=str(p))
    except SyntaxError:
        return set()
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                imports.add(n.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    return imports

def build_graph(py_files: list[Path]) -> tuple[dict[str, set[str]], dict[str, Path]]:
    mod2file: dict[str, Path] = {}
    for p in py_files:
        mod2file[module_name(p)] = p
    graph: dict[str, set[str]] = {m: set() for m in mod2file}
    for m, p in mod2file.items():
        imps = parse_imports(p)
        # liga para módulos locais se existir correspondência
        for target in list(mod2file.keys()):
            if target.split(".")[0] in imps:
                graph[m].add(target)
    return graph, mod2file

def resolve_entries(entries: list[str], all_files: list[Path]) -> set[str]:
    mods = set()
    names = [module_name(p) for p in all_files]
    for pat in entries:
        # pode ser caminho, módulo ou pattern
        if pat.endswith(".py") or "/" in pat or "\\" in pat:
            for p in all_files:
                if fnmatch.fnmatch(str(p.relative_to(ROOT)).replace("\\","/"), pat):
                    mods.add(module_name(p))
        else:
            # nome de módulo
            for m in names:
                if fnmatch.fnmatch(m, pat):
                    mods.add(m)
    return mods

def reachable(graph: dict[str, set[str]], starts: set[str]) -> set[str]:
    seen: set[str] = set()
    stack = list(starts)
    while stack:
        m = stack.pop()
        if m in seen: 
            continue
        seen.add(m)
        for n in graph.get(m, ()):
            if n not in seen:
                stack.append(n)
    return seen

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--entry", nargs="*", default=[], help="Módulos/arquivos/patterns de entrada")
    args = ap.parse_args()

    py_files = discover_py(ROOT)
    graph, mod2file = build_graph(py_files)

    default_entries = []
    for cand in ["main_app.py", "smoketest_v21.py", "smoketest.py", "crypto_core/__init__.py"]:
        default_entries.append(cand)
    entries = args.entry or default_entries
    start_mods = resolve_entries(entries, py_files)

    reach = reachable(graph, start_mods)
    all_mods = set(mod2file.keys())
    unused = sorted(all_mods - reach)

    report = {
        "root": str(ROOT),
        "entries": sorted(start_mods),
        "total_modules": len(all_mods),
        "reachable": len(reach),
        "unused": [{"module": m, "path": str(mod2file[m])} for m in unused],
    }
    out = ROOT / "unused_modules.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Relatório salvo em {out}")
    print(f"Inutilizados: {len(unused)} (veja unused_modules.json)")
    if len(unused) > 0:
        print("Top 10 (amostra):")
        for item in report["unused"][:10]:
            print(" -", item["path"])

if __name__ == "__main__":
    main()
