from __future__ import annotations
import random

class InsertDummyComments:
    name = "insert_dummy_comments"

    def apply(self, code: str, ctx) -> str:
        lines = code.splitlines()
        if len(lines) < 3:
            return code
        for idx in range(len(lines) - 1, 0, -1):
            if random.randint(1, 10) > 3:
                indent = len(lines[idx]) - len(lines[idx].lstrip(" "))
                sample = random.choice(lines).strip()
                if not sample:
                    sample = "noise"
                lines.insert(idx, (" " * indent) + "# " + sample[:80])
        return "\n".join(lines)
