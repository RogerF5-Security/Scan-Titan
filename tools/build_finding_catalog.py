"""Export auditable Finding construction sites; external rule catalogs are dynamic."""
from __future__ import annotations

import ast
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build() -> int:
    rows = []
    files = sorted((ROOT / 'src' / 'scan_titan' / 'modules').glob('*.py'))
    files += [ROOT / 'src' / 'scan_titan' / name for name in ('Main.py', 'ssh_audit.py')]
    legacy = {('auth_session.py', '_session_regeneration_profiles'),
              ('authorization.py', '_auth_profile_matrix'),
              ('advanced_logic.py', '_race_conditions'), ('advanced_logic.py', '_websockets')}
    for path in files:
        tree = ast.parse(path.read_text(encoding='utf-8-sig'))
        functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != 'Finding':
                continue
            args = {item.arg: ast.unparse(item.value) for item in node.keywords if item.arg}
            owners = [item for item in functions if item.lineno <= node.lineno <= item.end_lineno]
            owner = min(owners, key=lambda item: item.end_lineno - item.lineno).name if owners else ''
            rows.append({'archivo': path.relative_to(ROOT).as_posix(), 'linea': node.lineno,
                         'funcion': owner, 'titulo_o_expresion': args.get('title', 'expansion dinamica'),
                         'categoria': args.get('category', ''), 'severidad': args.get('severity', ''),
                         'estado': 'legacy omitido con SessionManager' if (path.name, owner) in legacy
                         else 'condicionado por datos, politica y validacion del modulo'})
    output = ROOT / 'docs' / 'FINDING_CATALOG.csv'
    with output.open('w', encoding='utf-8-sig', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f'Finding construction sites: {len(rows)}; output: {output}')
    return len(rows)


if __name__ == '__main__':
    build()
