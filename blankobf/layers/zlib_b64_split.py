from __future__ import annotations
import zlib, base64, random, string, ast
from ..utils import safe_unparse

class ZlibB64Split:
    name = "zlib_b64_split"

    def apply(self, code: str, ctx) -> str:
        # Educational packer: compress+base64, split into 4 parts and exec at runtime.
        # NOTE: This is for learning. Use bundle encryption for real protection of assets.
        encoded = base64.b64encode(zlib.compress(code.encode("utf-8"))).decode("ascii")

        # Split into 4 parts (roughly)
        n = max(1, len(encoded) // 4)
        parts = [encoded[i:i+n] for i in range(0, len(encoded), n)][:4]
        while len(parts) < 4:
            parts.append("")
        parts.reverse()

        template = '''
fire = ""
water = ""
earth = ""
wind = ""

payload = fire + water + earth + wind
exec(__import__("zlib").decompress(__import__("base64").b64decode(payload)))
'''
        tree = ast.parse(template)
        assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
        for a, part in zip(assigns, parts):
            before = "".join(random.choices(string.ascii_letters, k=random.randint(5, 60)))
            after = "".join(random.choices(string.ascii_letters, k=random.randint(5, 60)))
            a.value = ast.Subscript(
                value=ast.Constant(value=before + part + after),
                slice=ast.Slice(lower=ast.Constant(len(before)), upper=ast.Constant(len(before) + len(part)), step=None),
                ctx=ast.Load(),
            )

        ast.fix_missing_locations(tree)
        return safe_unparse(tree)
