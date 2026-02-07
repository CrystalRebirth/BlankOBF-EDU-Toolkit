from __future__ import annotations
import ast
from typing import Callable

def safe_unparse(tree: ast.AST) -> str:
    # Python 3.10+ guaranteed; kept as a helper for clarity.
    return ast.unparse(tree)

def is_docstring_expr(node: ast.AST) -> bool:
    return isinstance(node, ast.Expr) and isinstance(getattr(node, "value", None), ast.Constant) and isinstance(node.value.value, str)
