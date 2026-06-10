"""Global verbose logging for NetCut CLI."""

from __future__ import annotations

from rich.console import Console

_level = 0
_console: Console | None = None


def set_verbose(level: int, console: Console | None = None) -> None:
    global _level, _console
    _level = max(0, level)
    _console = console or Console(stderr=True, highlight=False)


def verbose_level() -> int:
    return _level


def vlog(level: int, message: str, *, style: str = "dim cyan") -> None:
    if _level < level:
        return
    out = _console or Console(stderr=True, highlight=False)
    out.log(f"[bold dim]-v[/bold dim] {message}", style=style)
