"""The worker's functions mustn't re-import a module-level name inside themselves: Python
then treats the name as local to the whole function, and any use before that import, or
on a path that skips it, raises UnboundLocalError. `import time` inside start_analysis did
exactly that, failing every job that didn't first clear an old output directory.

Run: python3 -m unittest tests/unit/test_worker_imports.py
"""

import ast
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2] / "src" / "web" / "backend"


def shadowing_imports(path: Path) -> list:
    """(function, line, name) for each re-import of a module-level name inside a branch of a
    function (if, try, for...) that the function also uses elsewhere: a path that skips the
    branch then finds the name unbound. One at the top of the function body is harmless."""
    tree = ast.parse(path.read_text())
    module_names = {(a.asname or a.name).split(".")[0]
                    for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))
                    for a in node.names}
    found = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            if not isinstance(node, (ast.Import, ast.ImportFrom)) or node in fn.body:
                continue
            for alias in node.names:
                name = (alias.asname or alias.name).split(".")[0]
                if name not in module_names:
                    continue
                used_elsewhere = any(isinstance(n, ast.Name) and n.id == name and n.lineno != node.lineno
                                     for n in ast.walk(fn))
                if used_elsewhere:
                    found.append((fn.name, node.lineno, name))
    return found


class WorkerImportsTest(unittest.TestCase):
    def test_no_function_shadows_a_module_import(self):
        for name in ("tasks_docker.py", "tasks.py", "main.py"):
            with self.subTest(file=name):
                self.assertEqual(shadowing_imports(BACKEND / name), [])


if __name__ == "__main__":
    unittest.main()
