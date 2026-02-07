from __future__ import annotations
import ast
from ..utils import safe_unparse, is_docstring_expr

class StripDocstrings:
    name = "strip_docstrings"

    def apply(self, code: str, ctx) -> str:
        tree = ast.parse(code)

        # Insert a friendly banner string (teaching marker)
        tree.body.insert(0, ast.Expr(value=ast.Constant(":: BlankOBF EDU Toolkit ::")))

        # Remove module docstring
        for i, node in enumerate(list(tree.body)[1:], start=1):
            if is_docstring_expr(node):
                tree.body[i] = ast.Pass()

            # Function/class docstrings
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                body = getattr(node, "body", [])
                for j, inner in enumerate(body):
                    if is_docstring_expr(inner):
                        body[j] = ast.Pass()
                setattr(node, "body", body)

        ast.fix_missing_locations(tree)
        return safe_unparse(tree)
