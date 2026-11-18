"""Command-line interface for tokenid."""

from __future__ import annotations

import argparse
import sys
from typing import Dict, List, Optional, Sequence

from . import __version__
from .analysis.entropy import compute_entropy
from .core import analyze, analyze_batch, compare, decode, inspect
from .reporting import colors, json_report, text_report


def _parse_context(pairs: Optional[Sequence[str]]) -> Dict[str, str]:
    context: Dict[str, str] = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise ValueError("--context expects key=value")
        key, value = pair.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError("--context key must not be empty")
        context[key] = value
    return context


def _read_tokens(path: str) -> List[str]:
    if path == "-":
        lines = sys.stdin.read().splitlines()
    else:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    return [line.strip() for line in lines if line.strip()]


def _emit(text: str, output: Optional[str]) -> None:
    if output:
        with open(output, "w", encoding="utf-8") as handle:
            handle.write(text)
            if not text.endswith("\n"):
                handle.write("\n")
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")


def _shared_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument("-o", "--output", help="write the report to a file")
    parser.add_argument(
        "--context",
        action="append",
        metavar="KEY=VALUE",
        help="context value for hash guessing (repeatable)",
    )
    parser.add_argument(
        "--show-context",
        action="store_true",
        help="include context values in the report (off by default)",
    )
    parser.add_argument(
        "--show-token",
        action="store_true",
        help="include the full token/sample values in the report (off by default)",
    )
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="colorize text output (default: auto, only on a terminal)",
    )
    return parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tokenid",
        description="Offline token/identifier classification and predictability analysis.",
    )
    parser.add_argument("--version", action="version", version="tokenid %s" % __version__)
    common = _shared_parser()
    sub = parser.add_subparsers(dest="command", required=True)

    analyze_parser = sub.add_parser(
        "analyze", parents=[common], help="analyze one token"
    )
    analyze_parser.add_argument("token", help="token to analyze")

    compare_parser = sub.add_parser(
        "compare", parents=[common], help="compare one token per line (file or -)"
    )
    compare_parser.add_argument("file", help="file with one token per line, or - for stdin")

    decode_parser = sub.add_parser(
        "decode", parents=[common], help="recursively decode one token"
    )
    decode_parser.add_argument("token", help="token to decode")
    decode_parser.add_argument(
        "--max-depth", type=int, default=5, help="maximum decoding depth (default: 5)"
    )
    decode_parser.add_argument(
        "--max-bytes",
        type=int,
        default=1024 * 1024,
        help="maximum decoded size in bytes (default: 1048576)",
    )

    inspect_parser = sub.add_parser(
        "inspect", parents=[common], help="verbose structural breakdown of one token"
    )
    inspect_parser.add_argument("token", help="token to inspect")

    entropy_parser = sub.add_parser(
        "entropy", parents=[common], help="entropy and charset statistics only"
    )
    entropy_parser.add_argument("token", help="token to measure")

    sub.add_parser(
        "batch", parents=[common], help="analyze tokens read from stdin (one per line)"
    )

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        context = _parse_context(args.context)
    except ValueError as exc:
        parser.error(str(exc))
        return 2

    include_token = bool(args.show_token)
    include_context = bool(args.show_context)
    if args.color == "always":
        use_color = True
    elif args.color == "never":
        use_color = False
    else:
        use_color = args.output is None and colors.supports_color(sys.stdout)

    def _emit_text(rendered: str) -> None:
        _emit(colors.colorize_text(rendered, use_color), args.output)

    try:
        if args.command == "analyze":
            result = analyze(args.token, context=context)
            if args.format == "json":
                payload = json_report.analysis_to_dict(
                    result,
                    include_token=include_token,
                    include_context=include_context,
                )
                _emit(json_report.dumps(payload), args.output)
            else:
                _emit_text(
                    text_report.render_analysis(
                        result,
                        show_token=include_token,
                        show_context=include_context,
                    )
                )
            return 0

        if args.command == "compare":
            tokens = _read_tokens(args.file)
            if not tokens:
                raise ValueError("no samples found in %r" % args.file)
            result = compare(tokens, context=context)
            if args.format == "json":
                payload = json_report.compare_to_dict(
                    result,
                    include_token=include_token,
                    include_context=include_context,
                )
                _emit(json_report.dumps(payload), args.output)
            else:
                _emit_text(
                    text_report.render_compare(
                        result,
                        show_token=include_token,
                        show_context=include_context,
                    )
                )
            return 0

        if args.command == "decode":
            result = decode(
                args.token, max_depth=args.max_depth, max_bytes=args.max_bytes
            )
            if args.format == "json":
                _emit(
                    json_report.dumps(
                        json_report.decode_to_dict(result, include_token=include_token)
                    ),
                    args.output,
                )
            else:
                _emit_text(
                    text_report.render_decode(
                        result, token=args.token, show_token=include_token
                    )
                )
            return 0

        if args.command == "inspect":
            result = inspect(args.token, context=context)
            if args.format == "json":
                payload = json_report.analysis_to_dict(
                    result,
                    include_token=include_token,
                    include_context=include_context,
                )
                _emit(json_report.dumps(payload), args.output)
            else:
                _emit_text(
                    text_report.render_inspect(
                        result,
                        show_token=include_token,
                        show_context=include_context,
                    )
                )
            return 0

        if args.command == "entropy":
            stats = compute_entropy(args.token.strip())
            if args.format == "json":
                _emit(
                    json_report.dumps(
                        json_report.entropy_to_dict(
                            stats, include_token=include_token
                        )
                    ),
                    args.output,
                )
            else:
                _emit_text(text_report.render_entropy(stats))
            return 0

        if args.command == "batch":
            tokens = _read_tokens("-")
            if args.format == "json":
                payload = [
                    json_report.analysis_to_dict(
                        result,
                        include_token=include_token,
                        include_context=include_context,
                    )
                    for result in analyze_batch(tokens, context=context)
                ]
                _emit(json_report.dumps(payload), args.output)
            else:
                _emit_text(
                    text_report.render_batch(
                        analyze_batch(tokens, context=context),
                        show_token=include_token,
                        show_context=include_context,
                    )
                )
            return 0

        parser.error("unknown command")
        return 2
    except (ValueError, TypeError, OSError) as exc:
        sys.stderr.write("tokenid: error: %s\n" % exc)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
