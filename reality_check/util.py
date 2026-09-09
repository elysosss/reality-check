"""Мелкие общие утилиты: пути, маскирование секретов, вывод таблиц."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"
TOOLS = ROOT / "tools"
CONFIG_DIR = ROOT / "config"


def ts() -> str:
    """Метка времени для имён файлов: 20260908-142530."""
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def run_dir(*parts: str) -> Path:
    """Каталог внутри runs/, создаётся при обращении."""
    p = RUNS.joinpath(*parts)
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_json(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return path


def read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def mask(secret: str | None, keep: int = 4) -> str:
    """Маскирует секрет для печати: 'abcd…(len=32)'. Никогда не печатаем целиком."""
    if not secret:
        return "<empty>"
    s = str(secret)
    if len(s) <= keep:
        return "*" * len(s)
    return f"{s[:keep]}…(len={len(s)})"


_SECRET_KEYS = re.compile(
    r"(password|passwd|token|secret|privatekey|private_key|api_?key|cookie|authorization)",
    re.I,
)


def scrub(data: Any) -> Any:
    """Рекурсивно маскирует значения секретных ключей — перед записью в runs/ или печатью."""
    if isinstance(data, dict):
        out = {}
        for k, v in data.items():
            if isinstance(k, str) and _SECRET_KEYS.search(k):
                out[k] = mask(v if isinstance(v, str) else str(v))
            else:
                out[k] = scrub(v)
        return out
    if isinstance(data, list):
        return [scrub(v) for v in data]
    return data


def human_bytes(n: int | float | None) -> str:
    if not n:
        return "0"
    n = float(n)
    for unit in ("B", "K", "M", "G", "T", "P"):
        if abs(n) < 1024.0:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}E"


def human_time(ms: int | None) -> str:
    """expiryTime в 3x-ui — миллисекунды epoch; 0 или отрицательное = без срока."""
    if not ms or ms <= 0:
        return "∞"
    try:
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).astimezone().strftime("%Y-%m-%d")
    except (ValueError, OverflowError, OSError):
        return "?"


def table(rows: Sequence[Sequence[Any]], headers: Sequence[str]) -> str:
    """Простая ASCII-таблица без внешних зависимостей."""
    data = [[("" if c is None else str(c)) for c in r] for r in rows]
    widths = [len(h) for h in headers]
    for r in data:
        for i, c in enumerate(r):
            if i < len(widths):
                widths[i] = max(widths[i], len(c))
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths)).rstrip()
    sep = "  ".join("-" * w for w in widths)
    body = "\n".join("  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip() for r in data)
    return f"{line}\n{sep}\n{body}" if data else f"{line}\n{sep}\n(пусто)"


def expand_env(value: Any) -> Any:
    """Поддержка ${ENV:VAR} в yaml-конфиге, чтобы секреты можно было держать в окружении."""
    if isinstance(value, str):
        m = re.fullmatch(r"\$\{ENV:([A-Za-z_][A-Za-z0-9_]*)\}", value.strip())
        if m:
            return os.environ.get(m.group(1), "")
        return value
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    return value


def first(iterable: Iterable[Any], default: Any = None) -> Any:
    for x in iterable:
        return x
    return default
