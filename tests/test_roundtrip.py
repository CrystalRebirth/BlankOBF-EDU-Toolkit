import os, tempfile, subprocess, sys, json, unittest
from blankobf.engine import Context, run_pipeline
from blankobf.transforms import StripDocstrings, RenameIdentifiers, EncodeConstants, GetattrAttributes, InsertDummyComments

class RoundTripTests(unittest.TestCase):
    def test_ast_only_roundtrip(self):
        code = 'def f(x):\n    return x+1\nprint(f(2))\n'
        ctx = Context(seed=123, recursion=1)
        out = run_pipeline(code, ctx, [
            StripDocstrings(), RenameIdentifiers(), EncodeConstants(), GetattrAttributes(), InsertDummyComments()
        ], layers=[])

        with tempfile.TemporaryDirectory() as d:
            a = os.path.join(d, "a.py")
            b = os.path.join(d, "b.py")
            with open(a, "w", encoding="utf-8") as f: f.write(code)
            with open(b, "w", encoding="utf-8") as f: f.write(out)

            ra = subprocess.check_output([sys.executable, a], text=True).strip()
            rb = subprocess.check_output([sys.executable, b], text=True).strip()
            self.assertEqual(ra, rb)

if __name__ == "__main__":
    unittest.main()
