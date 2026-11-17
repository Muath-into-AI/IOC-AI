"""Render enrichment results as a table, JSON, CSV, or Markdown."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Sequence
from datetime import datetime, timezone

from rich.console import Console
from rich.table import Table

from ioc_enrich import __version__
from ioc_enrich.scoring import EnrichmentResult
from ioc_enrich.sources.base import Status

LEVEL_STYLES = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "none": "green",
    "unknown": "dim",
}


def _source_cell(res: EnrichmentResult) -> str:
    parts = []
    for r in res.results:
        if r.status is Status.UNSUPPORTED:
            continue
        if r.status is Status.ERROR:
            parts.append(f"{r.source}: error")
        elif r.summary:
            parts.append(f"{r.source}: {r.summary}")
        else:
            parts.append(f"{r.source}: {r.status.value}")
    return "\n".join(parts) or "-"


def render_table(results: Sequence[EnrichmentResult], console: Console | None = None) -> None:
    """Print a coloured table to ``console`` (stdout by default)."""
    console = console or Console()
    table = Table(title="ioc-enrich results", show_lines=True)
    table.add_column("IOC", overflow="fold")
    table.add_column("Type")
    table.add_column("Score", justify="right")
    table.add_column("Level")
    table.add_column("Sources", overflow="fold")
    table.add_column("Reasons", overflow="fold")
    for res in results:
        style = LEVEL_STYLES.get(res.score.level, "")
        table.add_row(
            res.ioc,
            res.ioc_type.value,
            f"[{style}]{res.score.value}[/]",
            f"[{style}]{res.score.level}[/]",
            _source_cell(res),
            "\n".join(f"- {x}" for x in res.score.reasons),
        )
    console.print(table)


def render_json(results: Sequence[EnrichmentResult]) -> str:
    """Return results as pretty JSON."""
    return json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False)


def render_csv(results: Sequence[EnrichmentResult]) -> str:
    """Return results as CSV (one row per IOC)."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["ioc", "original", "type", "score", "level", "reasons", "sources"])
    for r in results:
        writer.writerow(
            [
                r.ioc,
                r.original,
                r.ioc_type.value,
                r.score.value,
                r.score.level,
                "; ".join(r.score.reasons),
                "; ".join(_source_cell(r).splitlines()),
            ]
        )
    return buf.getvalue()


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(results: Sequence[EnrichmentResult]) -> str:
    """Return a Markdown report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# IOC enrichment report",
        "",
        f"Generated {now} by ioc-enrich {__version__}.",
        "",
        "| IOC | Type | Score | Level |",
        "|---|---|---:|---|",
    ]
    for r in results:
        lines.append(
            f"| `{_md_escape(r.ioc)}` | {r.ioc_type.value} | {r.score.value} | {r.score.level} |"
        )
    for r in results:
        lines += ["", f"## `{_md_escape(r.ioc)}`", ""]
        if r.original != r.ioc:
            lines.append(f"- Original input: `{_md_escape(r.original)}`")
        lines.append(f"- Type: {r.ioc_type.value}")
        lines.append(f"- Score: **{r.score.value}** ({r.score.level})")
        lines += ["", "**Reasons**", ""]
        lines += [f"- {_md_escape(x)}" for x in r.score.reasons]
        lines += ["", "**Sources**", ""]
        for s in r.results:
            if s.status is Status.UNSUPPORTED:
                continue
            detail = s.summary or s.error or ""
            lines.append(
                f"- {s.source}: {s.status.value}" + (f" — {_md_escape(detail)}" if detail else "")
            )
    return "\n".join(lines) + "\n"
