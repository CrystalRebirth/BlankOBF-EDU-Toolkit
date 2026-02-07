from __future__ import annotations
import ast, random, sys
from ..utils import safe_unparse

class EncodeConstants:
    name = "encode_constants"

    def apply(self, code: str, ctx) -> str:
        tree = ast.parse(code)

        class T(ast.NodeTransformer):
            def visit_Constant(self, node: ast.Constant):
                # integers: rewrite as equivalent expression
                if isinstance(node.value, int) and not isinstance(node.value, bool):
                    choice = random.randint(1, 2)
                    x = node.value
                    if choice == 1:
                        n = random.randint(2 ** 16, sys.maxsize)
                        # x*n - x*(n-1) == x
                        return ast.BinOp(
                            left=ast.Constant(value=x * n),
                            op=ast.Sub(),
                            right=ast.Constant(value=x * (n - 1)),
                        )
                    else:
                        n = random.randint(2 ** 16, sys.maxsize)
                        m = random.randint(50, 500)
                        # ((n*2) + (x*2*m))//2 - n - x*(m-1) == x
                        return ast.BinOp(
                            left=ast.BinOp(
                                left=ast.BinOp(
                                    left=ast.BinOp(
                                        left=ast.Constant(value=n * 2),
                                        op=ast.Add(),
                                        right=ast.Constant(value=x * 2 * m),
                                    ),
                                    op=ast.FloorDiv(),
                                    right=ast.Constant(value=2),
                                ),
                                op=ast.Sub(),
                                right=ast.Constant(value=n),
                            ),
                            op=ast.Sub(),
                            right=ast.Constant(value=x * (m - 1)),
                        )

                # strings: bytes([...])[::-1].decode()
                if isinstance(node.value, str):
                    b = list(node.value.encode("utf-8"))[::-1]
                    return ast.Call(
                        func=ast.Attribute(
                            value=ast.Call(
                                func=ast.Name(id="bytes", ctx=ast.Load()),
                                args=[
                                    ast.Subscript(
                                        value=ast.List(elts=[ast.Constant(v) for v in b], ctx=ast.Load()),
                                        slice=ast.Slice(lower=None, upper=None, step=ast.Constant(-1)),
                                        ctx=ast.Load(),
                                    )
                                ],
                                keywords=[],
                            ),
                            attr="decode",
                            ctx=ast.Load(),
                        ),
                        args=[],
                        keywords=[],
                    )

                # bytes: bytes([...])[::-1]
                if isinstance(node.value, (bytes, bytearray)):
                    b = list(bytes(node.value))[::-1]
                    return ast.Call(
                        func=ast.Name(id="bytes", ctx=ast.Load()),
                        args=[
                            ast.Subscript(
                                value=ast.List(elts=[ast.Constant(v) for v in b], ctx=ast.Load()),
                                slice=ast.Slice(lower=None, upper=None, step=ast.Constant(-1)),
                                ctx=ast.Load(),
                            )
                        ],
                        keywords=[],
                    )

                return node

        T().visit(tree)
        ast.fix_missing_locations(tree)
        return safe_unparse(tree)
