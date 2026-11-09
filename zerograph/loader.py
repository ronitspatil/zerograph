"""Safe YAML/JSON loading that remembers line numbers.

Only yaml.SafeLoader is used, so no tags can construct Python objects.
"""

from __future__ import annotations

import json
import re

import yaml


class LineDict(dict):
    """A dict that knows the line it started on and the line of each key."""

    line: int = 0
    key_lines: dict

    def line_of(self, key) -> int:
        return self.key_lines.get(key, self.line)


class _LineLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    result = LineDict()
    result.line = node.start_mark.line + 1
    result.key_lines = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        try:
            hash(key)
        except TypeError:
            key = str(key)
        result[key] = loader.construct_object(value_node, deep=True)
        result.key_lines[key] = key_node.start_mark.line + 1
    return result


_LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def line_of(obj, key=None) -> int | None:
    if isinstance(obj, LineDict):
        return obj.line_of(key) if key is not None else obj.line
    return None


def load_documents(text: str, is_json: bool = False) -> list:
    """Return every document in the text. Raises ValueError on a parse error."""
    try:
        return [d for d in yaml.load_all(text, Loader=_LineLoader) if d is not None]
    except yaml.YAMLError as exc:
        if not is_json:
            raise ValueError(_short_yaml_error(exc)) from None
    # JSON that PyYAML (YAML 1.1) cannot read, e.g. tabs: fall back without line numbers.
    try:
        return [json.loads(text)]
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc.msg} at line {exc.lineno}") from None


def _short_yaml_error(exc: yaml.YAMLError) -> str:
    mark = getattr(exc, "problem_mark", None)
    problem = getattr(exc, "problem", None) or "parse error"
    where = f" at line {mark.line + 1}" if mark else ""
    return re.sub(r"\s+", " ", f"invalid YAML: {problem}{where}")
