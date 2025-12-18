import io
import json

import pytest

from json_redactor.core import (
    HashRedactor,
    IMatcher,
    JsonValue,
    KeyMatcher,
    MaskRedactor,
    StreamTraverser,
    run_pipeline,
)


@pytest.mark.parametrize(
    "raw_json, matcher, expected",
    (
        pytest.param(
            '{"name": "Alice", "SurName": "Smith"}',
            KeyMatcher(keys={"email"}),
            {"name": "Alice", "SurName": "Smith"},
            id="Non-sensitive keys unchanged",
        ),
        pytest.param(
            '{"name": "Alice", "email": "alice@x.com"}',
            KeyMatcher(keys={"email"}),
            {"name": "Alice", "email": "***REDACTED***"},
            id="Masks sensitive keys",
        ),
        pytest.param(
            '{"addresses": [{"house": "1", "tel": "11-22"}, {"house": "2", "tel": "33-44"}]}',
            KeyMatcher(keys={"house"}),
            {
                "addresses": [
                    {"house": "***REDACTED***", "tel": "11-22"},
                    {"house": "***REDACTED***", "tel": "33-44"},
                ]
            },
            id="Masks nested sensitive keys",
        ),
        pytest.param(
            '{"name": "Alice", "email": "alice@x.com"}',
            KeyMatcher(keys={"EMAIL"}),
            {"name": "Alice", "email": "***REDACTED***"},
            id="Matching is case-insensitive #1",
        ),
        pytest.param(
            '{"name": "Alice", "EmAiL": "alice@x.com"}',
            KeyMatcher(keys={"email"}),
            {"name": "Alice", "EmAiL": "***REDACTED***"},
            id="Matching is case-insensitive #2",
        ),
        pytest.param(
            "1",
            KeyMatcher(keys={"email"}),
            1,
            id="Primitive unchanged",
        ),
        pytest.param(
            '["a", {"email":"x"}]',
            KeyMatcher(keys={"email"}),
            ["a", {"email": "***REDACTED***"}],
            id="List is redacted",
        ),
    ),
)
def test_ok(raw_json: str, matcher: IMatcher, expected: JsonValue) -> None:
    traverser = StreamTraverser(matcher=matcher, redactor=MaskRedactor())

    out = io.StringIO()
    run_pipeline(io.StringIO(raw_json), out, traverser)

    assert json.loads(out.getvalue()) == expected


def test_hash_redactor_is_deterministic() -> None:
    traverser = StreamTraverser(
        matcher=KeyMatcher(keys={"security"}), redactor=HashRedactor()
    )

    out_1 = io.StringIO()
    run_pipeline(
        io.StringIO(
            '{"security": {"a": 1, "b": 2, "c": [3, 4], "d": {"e": 10, "f": 11}}}'
        ),
        out_1,
        traverser,
    )

    out_2 = io.StringIO()
    run_pipeline(
        io.StringIO(
            '{"security": {"d": {"f": 11, "e": 10}, "c": [3, 4], "b": 2, "a": 1}}'
        ),
        out_2,
        traverser,
    )

    loaded_out_1 = json.loads(out_1.getvalue())
    loaded_out_2 = json.loads(out_2.getvalue())

    assert (
        loaded_out_1["security"]
        == "66cf71a6d9a3e0274c702ac00363e4283e38c4eb8e7452b81918de835514b4d9"
    )
    assert loaded_out_1 == loaded_out_2


@pytest.mark.parametrize(
    "raw_json, expected",
    (
        pytest.param(
            '{"name": "Alice", "email": "alice@x.com"}',
            '{"name": "Alice", "email": "***REDACTED***"}',
            id="Name first, email second",
        ),
        pytest.param(
            '{"email": "alice@x.com", "name": "Alice"}',
            '{"email": "***REDACTED***", "name": "Alice"}',
            id="Email first, name second",
        ),
    ),
)
def test_preserves_original_key_order(raw_json: str, expected: str) -> None:
    traverser = StreamTraverser(
        matcher=KeyMatcher(keys={"email"}), redactor=MaskRedactor()
    )

    out = io.StringIO()
    run_pipeline(io.StringIO(raw_json), out, traverser)

    assert out.getvalue() == expected
