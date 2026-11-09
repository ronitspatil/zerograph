"""Command line: zerograph scan <path> [-o out.html] [--json out.json]"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .report import summary, to_html, to_json
from .scan import scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="zerograph", description=__doc__)
    parser.add_argument("--version", action="version", version=f"zerograph {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("scan", help="scan a directory or file")
    p.add_argument("path")
    p.add_argument("-o", "--output", metavar="FILE.html", help="write the interactive graph")
    p.add_argument("--json", metavar="FILE.json", help="write the graph and blast radii as JSON")
    p.add_argument("-q", "--quiet", action="store_true", help="hide warnings")
    args = parser.parse_args(argv)

    if not os.path.exists(args.path):
        print(f"zerograph: {args.path}: no such file or directory", file=sys.stderr)
        return 2
    g = scan(args.path)
    if args.output:
        _write(args.output, to_html(g, title=f"ZeroGraph - {os.path.basename(os.path.abspath(args.path))}"))
    if args.json:
        _write(args.json, to_json(g))
    print(summary(g))
    if g.warnings and not args.quiet:
        print(f"\n{len(g.warnings)} warning(s):", file=sys.stderr)
        for warning in g.warnings:
            print(f"  - {warning}", file=sys.stderr)
    for label, path in (("HTML", args.output), ("JSON", args.json)):
        if path:
            print(f"{label} written to {path}")
    return 0


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
