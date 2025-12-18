import contextlib
import pathlib
import re
import sys
from collections.abc import Iterator
from typing import Annotated, Any, TextIO

import typer

from .core import (
    AnyMatcher,
    HashRedactor,
    IMatcher,
    KeyMatcher,
    MaskRedactor,
    RegexMatcher,
    StreamTraverser,
    run_pipeline,
)


@contextlib.contextmanager
def _get_input_stream(path: pathlib.Path | None) -> Iterator[TextIO]:
    """Yields file object if path exists, otherwise yields stdin."""
    if path:
        with path.open("r", encoding="utf-8") as f:
            yield f
    else:
        yield sys.stdin


def _main(
    input_file: Annotated[
        pathlib.Path | None,
        typer.Argument(
            help="Path to JSON file. Reads from stdin if omitted.",
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ] = None,
    keys: Annotated[
        str | None, typer.Option(help="Comma-separated sensitive keys.")
    ] = None,
    key_file: Annotated[
        pathlib.Path | None,
        typer.Option(
            exists=True, dir_okay=False, readable=True, help="File with sensitive keys."
        ),
    ] = None,
    keys_regex: Annotated[
        list[str] | None,
        typer.Option(help="Regex pattern(s). Can be used multiple times."),
    ] = None,
    hash: Annotated[
        bool,
        typer.Option(
            help="Replace each sensitive value with a deterministic SHA-256 hash of "
            "the original value."
        ),
    ] = False,
) -> None:
    matchers: list[IMatcher] = []

    target_keys: set[str] = set()
    if keys:
        target_keys |= {k.strip() for k in keys.split(",") if k.strip()}
    if key_file:
        target_keys |= {k.strip() for k in key_file.read_text().split(",") if k.strip()}
    if target_keys:
        matchers.append(KeyMatcher(keys=target_keys))

    for pattern in keys_regex or []:
        try:
            matchers.append(RegexMatcher(pattern=pattern))
        except re.error as e:
            typer.echo(f"Error: Invalid regex {pattern!r}: {e}", err=True)
            raise typer.Exit(code=2)

    if not matchers:
        typer.echo(
            "Error: Must specify sensitive keys via `--keys`, `--key-file` or `--keys-regex`.",
            err=True,
        )
        raise typer.Exit(code=2)

    redactor = HashRedactor() if hash else MaskRedactor()

    traverser = StreamTraverser(
        matcher=AnyMatcher(matchers=matchers), redactor=redactor
    )

    try:
        with _get_input_stream(input_file) as source:
            run_pipeline(source, sys.stdout, traverser)
    except Exception as e:
        typer.echo(f"Error processing JSON: {e}", err=True)
        raise typer.Exit(code=1)


def main() -> Any:
    return typer.run(_main)
