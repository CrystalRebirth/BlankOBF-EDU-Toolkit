from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Protocol, Any
import random
import time
import ast

@dataclass
class Context:
    seed: int | None = None
    include_imports: bool = False
    recursion: int = 1

    # collected state (useful for explain mode)
    aliases: dict[str, str] = field(default_factory=dict)
    imports: set[tuple[str | None, str]] = field(default_factory=set)

    metrics: dict[str, Any] = field(default_factory=dict)
    layer_order: list[str] = field(default_factory=list)
    transform_order: list[str] = field(default_factory=list)

class Transform(Protocol):
    name: str
    def apply(self, code: str, ctx: Context) -> str: ...

class Layer(Protocol):
    name: str
    def apply(self, code: str, ctx: Context) -> str: ...

def collect_imports(code: str, ctx: Context) -> None:
    """Collect simple import statements for reporting/learning. We do NOT rewrite imports by default."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                ctx.imports.add((None, name.name))
        elif isinstance(node, ast.ImportFrom):
            module = node.module
            for name in node.names:
                ctx.imports.add((module, name.name))

def run_pipeline(code: str, ctx: Context, transforms: list[Transform], layers: list[Layer]) -> str:
    if ctx.seed is not None:
        random.seed(ctx.seed)

    collect_imports(code, ctx)

    t0 = time.time()
    ctx.metrics["input_len"] = len(code)

    for tr in transforms:
        before_len = len(code)
        code = tr.apply(code, ctx)
        ctx.transform_order.append(tr.name)
        ctx.metrics[f"transform:{tr.name}:delta_len"] = len(code) - before_len

    expanded_layers = layers * max(1, ctx.recursion)
    random.shuffle(expanded_layers)

    # tiny optimization: avoid the slowest layer being outermost if present
    if expanded_layers and hasattr(expanded_layers[-1], "prefer_not_outermost") and expanded_layers[-1].prefer_not_outermost:
        for i, ly in enumerate(expanded_layers):
            if not getattr(ly, "prefer_not_outermost", False):
                expanded_layers[i], expanded_layers[-1] = expanded_layers[-1], expanded_layers[i]
                break

    for ly in expanded_layers:
        before_len = len(code)
        code = ly.apply(code, ctx)
        ctx.layer_order.append(ly.name)
        ctx.metrics[f"layer:{ly.name}:delta_len"] = len(code) - before_len

    ctx.metrics["final_len"] = len(code)
    ctx.metrics["total_seconds"] = round(time.time() - t0, 6)
    return code

def ctx_to_dict(ctx: Context) -> dict[str, Any]:
    d = asdict(ctx)
    d["imports"] = sorted(list(ctx.imports))
    d["aliases_count"] = len(ctx.aliases)
    d["imports_count"] = len(ctx.imports)
    return d
