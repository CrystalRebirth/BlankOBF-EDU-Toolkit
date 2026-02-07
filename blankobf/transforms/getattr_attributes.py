from __future__ import annotations
import ast
from ..utils import safe_unparse

class GetattrAttributes:
    name = "getattr_attributes"

    def apply(self, code: str, ctx) -> str:
        tree = ast.parse(code)

        class T(ast.NodeTransformer):
            def visit_Attribute(self, node: ast.Attribute):
                # Convert obj.attr -> getattr(obj, "attr") for teaching purposes.
                new = ast.Call(
                    func=ast.Name(id="getattr", ctx=ast.Load()),
                    args=[self.visit(node.value), ast.Constant(node.attr)],
                    keywords=[],
                )
                return ast.copy_location(new, node)

        T().visit(tree)
        ast.fix_missing_locations(tree)
        return safe_unparse(tree)
