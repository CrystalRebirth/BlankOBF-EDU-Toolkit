from __future__ import annotations
import zlib, base64, ast
from ..utils import safe_unparse

class IPTable:
    name = "ip_table"
    prefer_not_outermost = True

    def apply(self, code: str, ctx) -> str:
        # Educational: represent bytes as dotted-quads.
        data = base64.b64encode(zlib.compress(code.encode("utf-8")))

        def bytes2ip(b: bytes) -> list[str]:
            out = []
            for i in range(0, len(b), 4):
                chunk = b[i:i+4].ljust(4, b"\x00")
                out.append(".".join(str(x) for x in chunk))
            return out

        ips = bytes2ip(data)

        template = '''
ip_table = []
data = list([int(x) for item in [value.split(".") for value in ip_table] for x in item])
payload = bytes(data).rstrip(b"\x00")
exec(compile(__import__("zlib").decompress(__import__("base64").b64decode(payload)), "<blankobf:ip>", "exec"))
'''
        tree = ast.parse(template)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "ip_table":
                node.value = ast.List(elts=[ast.Constant(v) for v in ips], ctx=ast.Load())
        ast.fix_missing_locations(tree)
        return safe_unparse(tree)
