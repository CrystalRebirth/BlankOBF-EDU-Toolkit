from __future__ import annotations
import zlib, ast, random
from ..utils import safe_unparse

class XORBruteforceLab:
    name = "xor_bruteforce_lab"

    def apply(self, code: str, ctx) -> str:
        # Educational brute-force XOR layer (slow on purpose).
        key = random.randint(1, 60)
        encrypted = [b ^ key for b in zlib.compress(code.encode("utf-8"))]

        template = '''
encrypted = []
for k in range(1, 61):
    try:
        data = bytes([x ^ k for x in encrypted])
        exec(__import__("zlib").decompress(data))
        break
    except Exception:
        pass
'''
        tree = ast.parse(template)
        for node in ast.walk(tree):
            if isinstance(node, ast.List) and node.elts == []:
                node.elts = [ast.Constant(v) for v in encrypted]
                break
        ast.fix_missing_locations(tree)
        return safe_unparse(tree)
