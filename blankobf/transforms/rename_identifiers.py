from __future__ import annotations
import ast, random, string, builtins
from ..utils import safe_unparse

class RenameIdentifiers:
    name = "rename_identifiers"

    def _gen(self) -> str:
        return "_0x" + "".join(random.choices(string.hexdigits[:16], k=random.randint(10, 25)))

    def apply(self, code: str, ctx) -> str:
        tree = ast.parse(code)
        builtins_set = set(dir(builtins))
        imported_names = {name for (_m, name) in getattr(ctx, "imports", set())}

        used = set()

        def alias_for(name: str) -> str:
            if name in ctx.aliases:
                return ctx.aliases[name]
            while True:
                a = self._gen()
                if a not in used and a not in ctx.aliases.values():
                    ctx.aliases[name] = a
                    used.add(a)
                    return a

        class T(ast.NodeTransformer):
            def rename(self, name: str) -> str:
                if name in builtins_set or name in imported_names:
                    return name
                return alias_for(name)

            def visit_FunctionDef(self, node: ast.FunctionDef):
                node.name = self.rename(node.name)
                self.generic_visit(node)
                return node

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
                node.name = self.rename(node.name)
                self.generic_visit(node)
                return node

            def visit_ClassDef(self, node: ast.ClassDef):
                node.name = self.rename(node.name)
                self.generic_visit(node)
                return node

            def visit_arg(self, node: ast.arg):
                node.arg = self.rename(node.arg)
                return node

            def visit_Name(self, node: ast.Name):
                node.id = self.rename(node.id)
                return node

        T().visit(tree)
        ast.fix_missing_locations(tree)
        return safe_unparse(tree)
