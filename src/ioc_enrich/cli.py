"""Command-line interface for ioc-enrich."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

from dotenv import load_dotenv

from ioc_enrich import __version__
from ioc_enrich.cache import DEFAULT_TTL, Cache
from ioc_enrich.enrich import Enricher
from ioc_enrich.output import render_csv, render_json, render_markdown, render_table
from ioc_enrich.sources import ALL_SOURCES, build_sources


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ioc-enrich",
        description="Enrich IOCs from free threat-intel sources (defensive triage only).",
    )
    p.add_argument("ioc", nargs="*", help="IOC(s) to enrich; defanged input is accepted")
    p.add_argument("-f", "--file", type=Path, help="read IOCs from a file, one per line")
    fmt = p.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="output JSON")
    fmt.add_argument("--csv", action="store_true", help="output CSV")
    fmt.add_argument("--md", action="store_true", help="output a Markdown report")
    p.add_argument("-o", "--output", type=Path, help="write output to a file")
    p.add_argument(
        "--sources",
        help="comma-separated subset of sources to use: " + ",".join(s.name for s in ALL_SOURCES),
    )
    p.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout in seconds")
    p.add_argument("--no-cache", action="store_true", help="disable the local SQLite cache")
    p.add_argument("--cache-path", type=Path, help="cache file (default ~/.cache/ioc-enrich/)")
    p.add_argument(
        "--cache-ttl",
        type=int,
        default=int(os.environ.get("IOC_ENRICH_CACHE_TTL", DEFAULT_TTL)),
        help="cache TTL in seconds (default 86400)",
    )
    p.add_argument("--env-file", type=Path, help="load API keys from this .env file")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _clean_lines(lines: Iterable[str]) -> list[str]:
    out = []
    for line in lines:
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


def collect_iocs(args: argparse.Namespace, stdin: Iterable[str] | None = None) -> list[str]:
    """Gather IOCs from positional args, ``--file`` and (if piped) stdin."""
    iocs = list(args.ioc)
    if args.file:
        iocs += _clean_lines(args.file.read_text(encoding="utf-8").splitlines())
    if stdin is not None:
        iocs += _clean_lines(stdin)
    return iocs


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    args = _build_parser().parse_args(argv)
    load_dotenv(args.env_file or None)

    use_stdin = not args.ioc and not args.file and not sys.stdin.isatty()
    iocs = collect_iocs(args, sys.stdin if use_stdin else None)
    if not iocs:
        print("error: no IOCs given (pass as arguments, -f FILE, or via stdin)", file=sys.stderr)
        return 2

    only = {s.strip() for s in args.sources.split(",")} if args.sources else None
    sources, skipped = build_sources(only=only, timeout=args.timeout)
    if not sources:
        print(
            "warning: no API keys configured; every source is skipped. See .env.example.",
            file=sys.stderr,
        )
    cache = None if args.no_cache else Cache(args.cache_path, ttl=args.cache_ttl)
    enricher = Enricher(sources, skipped, cache)
    try:
        results = enricher.enrich_many(iocs)
    finally:
        enricher.close()

    if args.json:
        text = render_json(results)
    elif args.csv:
        text = render_csv(results)
    elif args.md:
        text = render_markdown(results)
    else:
        text = None

    if text is None:
        if args.output:
            from rich.console import Console

            with args.output.open("w", encoding="utf-8") as fh:
                render_table(results, Console(file=fh, width=160))
        else:
            render_table(results)
    elif args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
