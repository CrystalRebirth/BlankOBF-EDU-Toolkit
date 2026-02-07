from __future__ import annotations
import json
from .engine import Context, ctx_to_dict

def write_report(path: str, ctx: Context) -> None:
    payload = ctx_to_dict(ctx)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
