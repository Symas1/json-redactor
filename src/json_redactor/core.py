import hashlib
import json
import typing
from collections.abc import Iterator, Mapping, Sequence, Set
from dataclasses import dataclass
from typing import Protocol, TypeAlias

import json_stream
import json_stream.base
import json_stream.writer

JsonPrimitive: TypeAlias = str | bool | int | float | None  # noqa: UP040
JsonValue: TypeAlias = JsonPrimitive | Sequence["JsonValue"] | Mapping[str, "JsonValue"]  # noqa: UP040


class IRedactor(Protocol):
    """Protocol for transforming a sensitive value."""

    def __call__(
        self, value: JsonValue | json_stream.base.TransientStreamingJSONObject
    ) -> str: ...


class IMatcher(Protocol):
    """Protocol for identifying sensitive keys."""

    def is_sensitive(self, key: str) -> bool: ...


class MaskRedactor:
    def __call__(
        self, value: JsonValue | json_stream.base.TransientStreamingJSONObject
    ) -> str:
        return "***REDACTED***"


class HashRedactor:
    """Hashes values deterministically using SHA-256.

    Note: JSON Arrays are ordered collections. ["a", "b"] is semantically different
      from ["b", "a"]. That is why arrays are not sorted.
    """

    def __call__(
        self, value: JsonValue | json_stream.base.TransientStreamingJSONObject
    ) -> str:
        if isinstance(value, json_stream.base.TransientStreamingJSONObject):
            # note: may consume a lot of memory if nested object is huge.
            #   Potential space for optimization.
            value = typing.cast(JsonValue, json_stream.to_standard_types(value))

        # Canonicalize the input to a JSON string.
        #   - sort_keys=True: Ensures {"a": 1, "b": 2} hashes the same as
        #     {"b": 2, "a": 1}.
        payload = json.dumps(value, sort_keys=True).encode("utf-8")

        return hashlib.sha256(payload).hexdigest()


class KeyMatcher:
    """Case-insensitive key matcher"""

    def __init__(self, *, keys: Set[str]):
        self.keys = {key.lower() for key in keys}

    def is_sensitive(self, key: str) -> bool:
        return key.lower() in self.keys


@dataclass(frozen=True, kw_only=True, slots=True)
class StreamTraverser:
    """Recursively wraps stream nodes with processing logic."""

    matcher: IMatcher
    redactor: IRedactor

    def __call__(self, value: JsonValue) -> JsonValue:
        if isinstance(value, JsonPrimitive):
            return value

        elif isinstance(value, Sequence):
            return typing.cast(
                JsonValue,
                json_stream.writer.streamable_list(self._process_sequence(value)),
            )

        elif isinstance(value, Mapping):
            return typing.cast(
                JsonValue,
                json_stream.writer.streamable_dict(self._process_mapping(value)),
            )

        else:
            typing.assert_never(value)

    def _process_sequence(self, sequence: Sequence[JsonValue]) -> Iterator[JsonValue]:
        for item in sequence:
            yield self(item)

    def _process_mapping(
        self, mapping: Mapping[str, JsonValue]
    ) -> Iterator[tuple[str, JsonValue]]:
        for key, value in mapping.items():
            if self.matcher.is_sensitive(key):
                yield key, self.redactor(value)

            else:
                yield key, self(value)
