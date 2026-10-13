#!/usr/bin/env python3
"""Generate the bd-smp21.1 host-delegation census artifact.

The census is source-derived and deterministic: it scans ABI Rust sources for
host resolver/delegate primitives, then propagates those through local helper
calls to exported ABI entrypoints.
"""

from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "host_delegation_census.v1"
BEAD_ID = "bd-smp21.1"
DETECTOR_VERSION = 15

PROFILE_INTERPOSE = "interpose-release-linux-x86_64"
PROFILE_STANDALONE = "standalone-release-linux-x86_64"

REQUIRED_ANCHORS = [
    "__libc_start_main",
    "dladdr",
    "dlclose",
    "dl_iterate_phdr",
    "dlopen",
    "dlsym",
    "pthread_create",
    "pthread_detach",
    "pthread_join",
]

THREAD_RAW_SYMBOLS = {
    "cancel": "pthread_cancel",
    "clockjoin_np": "pthread_clockjoin_np",
    "condattr_getclock": "pthread_condattr_getclock",
    "create": "pthread_create",
    "detach": "pthread_detach",
    "equal": "pthread_equal",
    "exit": "pthread_exit",
    "join": "pthread_join",
    "self": "pthread_self",
    "setcancelstate": "pthread_setcancelstate",
    "setcanceltype": "pthread_setcanceltype",
    "testcancel": "pthread_testcancel",
    "timedjoin_np": "pthread_timedjoin_np",
    "tryjoin_np": "pthread_tryjoin_np",
}

FUNCTION_RE = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\b")
CALL_PATH_RE = re.compile(
    r"(?<![\w.])((?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Za-z_][A-Za-z0-9_]*)\s*\("
)
MACRO_INVOCATION_RE = re.compile(
    r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*"
    r"(?:\s*::\s*[A-Za-z_][A-Za-z0-9_]*)*)\s*!\s*([({\[])"
)
AVX2_DISPATCH_DECL_RE = re.compile(
    r"\bunsafe\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)\b"
    r".*?=>\s*([A-Za-z_][A-Za-z0-9_]*)\s*;",
    re.DOTALL,
)
RAW_LITERAL_RE = re.compile(r'resolve_host_symbol_raw\s*\(\s*"([^"]+)"')
RAW_DYNAMIC_RE = re.compile(r"resolve_host_symbol_raw\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)")
CACHED_LITERAL_RE = re.compile(r'resolve_host_symbol_cached\s*\([^,]+,\s*"([^"]+)"')
RESOLVED_THREAD_RE = re.compile(r"\bresolved_thread_([A-Za-z0-9_]+)_raw\s*\(")
PARAM_BINDING_RE = re.compile(
    r"(?:^|[,(])\s*(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:"
)
LOCAL_BINDING_RE = re.compile(
    r"\blet\s+(?:mut\s+)?(?:(?:Some|Ok|Err)\s*\(\s*)?"
    r"([A-Za-z_][A-Za-z0-9_]*)"
)
EXPORT_NAME_RE = re.compile(r'export_name\s*=\s*"([^"]+)"')
BROADER_REFERENCE_RE = re.compile(
    r"resolve_host_symbol_|delegate_to_host_|resolved_thread_|host_pthread_|"
    r"host_dlsym|host_dlvsym|dlvsym_next|host_dl_iterate_phdr_cached|"
    r"host_dladdr_cached|FallbackHost|HostDelegateUnavailable"
)
LIBC_CALL_RE = re.compile(r"\blibc::([a-z_][A-Za-z0-9_]*)\s*\(")
ATTRIBUTE_START_RE = re.compile(r"(?m)^[ \t]*#\s*\[")
MODULE_DECL_RE = re.compile(
    r"(?m)^[ \t]*(?:(?:pub(?:\([^)]*\))?|unsafe)\s+)*mod\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*;"
)
USE_ITEM_RE = re.compile(r"(?m)^(?:(?:pub(?:\([^)]*\))?)\s+)?use\s+([^;]+);")
PATH_ATTRIBUTE_RE = re.compile(r'path\s*=\s*"([^"]+)"')
RAW_STRING_START_RE = re.compile(r'(?:br|r)(?P<hashes>#{0,255})"')


@dataclass(frozen=True)
class CfgExpr:
    kind: str
    name: str
    value: str | None = None
    children: tuple["CfgExpr", ...] = ()

    def render(self) -> str:
        if self.kind == "value":
            return f'{self.name} = "{self.value}"'
        if self.kind == "flag":
            return self.name
        return f"{self.name}({', '.join(child.render() for child in self.children)})"


@dataclass(frozen=True)
class CfgProfile:
    name: str
    features: frozenset[str]
    flags: frozenset[str]
    values: tuple[tuple[str, str], ...]
    target_features: frozenset[str]

    @property
    def value_map(self) -> dict[str, str]:
        return dict(self.values)

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "features": sorted(self.features),
            "flags": sorted(self.flags),
            "target_features": sorted(self.target_features),
            "values": dict(self.values),
        }


@dataclass(frozen=True)
class CfgDiagnostic:
    path: str
    line: int
    predicate: str
    reason: str

    def to_json(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "line": self.line,
            "predicate": self.predicate,
            "reason": self.reason,
        }


CFG_PROFILES = (
    CfgProfile(
        name=PROFILE_INTERPOSE,
        features=frozenset(),
        flags=frozenset({"unix"}),
        target_features=frozenset({"fxsr", "sse", "sse2", "x87"}),
        values=(
            ("target_arch", "x86_64"),
            ("target_endian", "little"),
            ("target_env", "gnu"),
            ("target_family", "unix"),
            ("target_os", "linux"),
            ("target_pointer_width", "64"),
            ("target_vendor", "unknown"),
        ),
    ),
    CfgProfile(
        name=PROFILE_STANDALONE,
        features=frozenset({"standalone"}),
        flags=frozenset({"unix"}),
        target_features=frozenset({"fxsr", "sse", "sse2", "x87"}),
        values=(
            ("target_arch", "x86_64"),
            ("target_endian", "little"),
            ("target_env", "gnu"),
            ("target_family", "unix"),
            ("target_os", "linux"),
            ("target_pointer_width", "64"),
            ("target_vendor", "unknown"),
        ),
    ),
)


class CfgParseError(ValueError):
    pass


class CfgParser:
    """Small parser for Rust's cfg predicate grammar.

    This intentionally accepts only predicates whose truth can be established
    from an explicit build profile. Unsupported syntax is retained
    conservatively and emitted as a blocking diagnostic.
    """

    def __init__(self, text: str):
        self.text = text
        self.pos = 0

    def skip_ws(self) -> None:
        while self.pos < len(self.text) and self.text[self.pos].isspace():
            self.pos += 1

    def parse_ident(self) -> str:
        self.skip_ws()
        match = re.match(r"[A-Za-z_][A-Za-z0-9_]*", self.text[self.pos :])
        if match is None:
            raise CfgParseError(f"expected identifier at column {self.pos + 1}")
        self.pos += len(match.group(0))
        return match.group(0)

    def parse_string(self) -> str:
        self.skip_ws()
        if self.pos >= len(self.text) or self.text[self.pos] != '"':
            raise CfgParseError(f"expected string at column {self.pos + 1}")
        self.pos += 1
        chars: list[str] = []
        while self.pos < len(self.text):
            char = self.text[self.pos]
            self.pos += 1
            if char == '"':
                return "".join(chars)
            if char == "\\":
                if self.pos >= len(self.text):
                    raise CfgParseError("unterminated string escape")
                escaped = self.text[self.pos]
                self.pos += 1
                chars.append(escaped)
            else:
                chars.append(char)
        raise CfgParseError("unterminated string")

    def parse_expr(self) -> CfgExpr:
        name = self.parse_ident()
        self.skip_ws()
        if self.pos < len(self.text) and self.text[self.pos] == "=":
            self.pos += 1
            return CfgExpr(kind="value", name=name, value=self.parse_string())
        if self.pos >= len(self.text) or self.text[self.pos] != "(":
            return CfgExpr(kind="flag", name=name)
        self.pos += 1
        children: list[CfgExpr] = []
        while True:
            self.skip_ws()
            if self.pos < len(self.text) and self.text[self.pos] == ")":
                self.pos += 1
                break
            children.append(self.parse_expr())
            self.skip_ws()
            if self.pos < len(self.text) and self.text[self.pos] == ",":
                self.pos += 1
                continue
            if self.pos < len(self.text) and self.text[self.pos] == ")":
                self.pos += 1
                break
            raise CfgParseError(f"expected ',' or ')' at column {self.pos + 1}")
        return CfgExpr(kind="call", name=name, children=tuple(children))

    def parse_complete(self) -> CfgExpr:
        expr = self.parse_expr()
        self.skip_ws()
        if self.pos != len(self.text):
            raise CfgParseError(f"unexpected trailing input at column {self.pos + 1}")
        return expr


def evaluate_cfg(expr: CfgExpr, profile: CfgProfile) -> bool | None:
    if expr.kind == "value":
        if expr.name == "feature":
            return expr.value in profile.features
        value_map = profile.value_map
        if expr.name in value_map:
            return value_map[expr.name] == expr.value
        if expr.name == "target_feature":
            return expr.value in profile.target_features
        # All other unmodelled key/value predicates are unknown and must
        # survive the source filter with a blocking diagnostic.
        return None
    if expr.kind == "flag":
        if expr.name in profile.flags:
            return True
        if expr.name in {"windows", "debug_assertions", "test"}:
            return False
        return None
    values = [evaluate_cfg(child, profile) for child in expr.children]
    if expr.name == "all":
        if any(value is False for value in values):
            return False
        return None if any(value is None for value in values) else True
    if expr.name == "any":
        if any(value is True for value in values):
            return True
        return None if any(value is None for value in values) else False
    if expr.name == "not" and len(values) == 1:
        return None if values[0] is None else not values[0]
    return None


def blank_preserving_newlines(text: str) -> str:
    return "".join("\n" if char == "\n" else " " for char in text)


def replace_preserving_newlines(original: str, replacement: str) -> str:
    slots = sum(char != "\n" for char in original)
    if len(replacement) > slots:
        raise CfgParseError("cfg_attr expansion does not fit its source attribute")
    pending = iter(replacement)
    exhausted = False
    rendered: list[str] = []
    for char in original:
        if char == "\n":
            rendered.append("\n")
        elif exhausted:
            rendered.append(" ")
        else:
            try:
                rendered.append(next(pending))
            except StopIteration:
                exhausted = True
                rendered.append(" ")
    return "".join(rendered)


def rust_code_mask(text: str) -> str:
    """Blank comments and literals while preserving offsets and newlines."""

    rendered = list(text)
    idx = 0
    block_depth = 0
    while idx < len(text):
        if block_depth:
            if text.startswith("/*", idx):
                rendered[idx] = rendered[idx + 1] = " "
                block_depth += 1
                idx += 2
            elif text.startswith("*/", idx):
                rendered[idx] = rendered[idx + 1] = " "
                block_depth -= 1
                idx += 2
            else:
                if text[idx] != "\n":
                    rendered[idx] = " "
                idx += 1
            continue
        if text.startswith("//", idx):
            end = text.find("\n", idx)
            end = len(text) if end < 0 else end
            for pos in range(idx, end):
                rendered[pos] = " "
            idx = end
            continue
        if text.startswith("/*", idx):
            rendered[idx] = rendered[idx + 1] = " "
            block_depth = 1
            idx += 2
            continue

        raw_match = RAW_STRING_START_RE.match(text, idx)
        if raw_match is not None:
            opening_len = len(raw_match.group(0))
            closing = '"' + raw_match.group("hashes")
            end = text.find(closing, idx + opening_len)
            end = len(text) if end < 0 else end + len(closing)
            for pos in range(idx, end):
                if text[pos] != "\n":
                    rendered[pos] = " "
            idx = end
            continue

        quote_idx = idx + 1 if text.startswith(('b"', 'c"'), idx) else idx
        if quote_idx < len(text) and text[quote_idx] == '"':
            end = quote_idx + 1
            escaped = False
            while end < len(text):
                char = text[end]
                end += 1
                if char == '"' and not escaped:
                    break
                if char == "\\" and not escaped:
                    escaped = True
                else:
                    escaped = False
            for pos in range(idx, end):
                if text[pos] != "\n":
                    rendered[pos] = " "
            idx = end
            continue

        if text[idx] == "'":
            char_end = idx + 1
            if char_end < len(text) and text[char_end] == "\\":
                char_end += 2
            else:
                char_end += 1
            if char_end < len(text) and text[char_end] == "'":
                char_end += 1
                for pos in range(idx, char_end):
                    rendered[pos] = " "
                idx = char_end
                continue
        idx += 1
    return "".join(rendered)


def matching_delimiter(mask: str, opening: int, left: str, right: str) -> int | None:
    depth = 0
    for idx in range(opening, len(mask)):
        char = mask[idx]
        if char == left:
            depth += 1
        elif char == right:
            depth -= 1
            if depth == 0:
                return idx + 1
    return None


def split_top_level_with_offsets(
    text: str, delimiter: str = ","
) -> list[tuple[int, str]]:
    if len(delimiter) != 1:
        raise ValueError("top-level delimiter must be one character")
    mask = rust_code_mask(text)
    pieces: list[tuple[int, str]] = []
    start = 0
    depths = {"(": 0, "[": 0, "{": 0}
    closing = {")": "(", "]": "[", "}": "{"}
    for idx, char in enumerate(mask):
        if char in depths:
            depths[char] += 1
        elif char in closing:
            depths[closing[char]] -= 1
        elif char == delimiter and not any(depths.values()):
            leading = len(text[start:idx]) - len(text[start:idx].lstrip())
            pieces.append((start + leading, text[start:idx].strip()))
            start = idx + 1
    leading = len(text[start:]) - len(text[start:].lstrip())
    pieces.append((start + leading, text[start:].strip()))
    return pieces


def split_top_level(text: str) -> list[str]:
    return [piece for _, piece in split_top_level_with_offsets(text)]


def attribute_spans(text: str, mask: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for match in ATTRIBUTE_START_RE.finditer(mask):
        opening = mask.find("[", match.start(), match.end())
        end = matching_delimiter(mask, opening, "[", "]")
        if end is not None:
            spans.append((match.start(), end))
    return spans


def only_trivia(mask: str, start: int, end: int) -> bool:
    return not mask[start:end].strip()


def skip_trivia(mask: str, start: int) -> int:
    idx = start
    while idx < len(mask) and mask[idx].isspace():
        idx += 1
    return idx


def extend_if_chain(mask: str, end: int) -> int:
    """Include `else` / `else if` tails belonging to one cfg-gated if."""

    cursor = skip_trivia(mask, end)
    while mask.startswith("else", cursor) and (
        cursor + 4 == len(mask) or not (mask[cursor + 4].isalnum() or mask[cursor + 4] == "_")
    ):
        cursor = skip_trivia(mask, cursor + 4)
        if mask.startswith("if", cursor) and (
            cursor + 2 == len(mask)
            or not (mask[cursor + 2].isalnum() or mask[cursor + 2] == "_")
        ):
            cursor += 2
        brace = mask.find("{", cursor)
        if brace < 0:
            return end
        close = matching_delimiter(mask, brace, "{", "}")
        if close is None:
            return end
        end = close
        cursor = skip_trivia(mask, end)
    return end


def cfg_target_end(mask: str, start: int) -> int | None:
    """Find the end of the Rust node governed by an outer cfg attribute."""

    start = skip_trivia(mask, start)
    if start >= len(mask):
        return None
    if mask[start] == "{":
        return matching_delimiter(mask, start, "{", "}")

    target = mask[start:]
    target = re.sub(r"^(?:pub(?:\([^)]*\))?\s+)", "", target, count=1)
    first_match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", target)
    first_word = first_match.group(1) if first_match else ""
    if re.match(r"(?:unsafe\s+)?(?:async\s+)?(?:const\s+)?(?:extern\s+\"C(?:-unwind)?\"\s+)?fn\b", target):
        first_word = "fn"
    semicolon_driven = first_word in {"const", "static", "type", "use", "let"}
    block_driven = first_word in {
        "fn", "struct", "enum", "union", "impl", "trait", "mod", "if", "match",
        "while", "for", "loop", "unsafe",
    }
    paren = bracket = brace = 0
    idx = start
    first_top_brace: int | None = None
    while idx < len(mask):
        char = mask[idx]
        if char == "(":
            paren += 1
        elif char == ")":
            paren -= 1
        elif char == "[":
            bracket += 1
        elif char == "]":
            bracket -= 1
        elif char == "{":
            if paren == 0 and bracket == 0 and brace == 0:
                first_top_brace = idx
                close = matching_delimiter(mask, idx, "{", "}")
                if close is None:
                    return None
                if block_driven or not semicolon_driven:
                    return extend_if_chain(mask, close) if first_word == "if" else close
                idx = close
                continue
            brace += 1
        elif char == "}":
            if brace == 0:
                return idx
            brace -= 1
        elif char == ";" and paren == bracket == brace == 0:
            return idx + 1
        elif char == "," and paren == bracket == brace == 0 and first_top_brace is None:
            return idx + 1
        idx += 1
    return None


def cfg_attribute_parts(attribute: str) -> tuple[str, str] | None:
    inner = attribute[attribute.find("[") + 1 : attribute.rfind("]")].strip()
    match = re.match(r"(cfg|cfg_attr)\s*\((.*)\)\s*$", inner, re.DOTALL)
    if match is None:
        return None
    return match.group(1), match.group(2)


def apply_cfg_profile(
    text: str,
    path: Path,
    root: Path,
    profile: CfgProfile,
) -> tuple[str, list[CfgDiagnostic]]:
    """Apply outer cfg/cfg_attr attributes without moving source lines."""

    mask = rust_code_mask(text)
    spans = attribute_spans(text, mask)
    diagnostics: list[CfgDiagnostic] = []
    replacements: list[tuple[int, int, str]] = []
    consumed: set[int] = set()

    for span_index, (attr_start, attr_end) in enumerate(spans):
        if span_index in consumed:
            continue
        parts = cfg_attribute_parts(text[attr_start:attr_end])
        if parts is None:
            continue

        group_start_index = span_index
        while group_start_index > 0:
            previous = spans[group_start_index - 1]
            if not only_trivia(mask, previous[1], spans[group_start_index][0]):
                break
            group_start_index -= 1
        group_end_index = span_index
        while group_end_index + 1 < len(spans):
            following = spans[group_end_index + 1]
            if not only_trivia(mask, spans[group_end_index][1], following[0]):
                break
            group_end_index += 1

        group_cfg_indices = [
            idx
            for idx in range(group_start_index, group_end_index + 1)
            if cfg_attribute_parts(text[spans[idx][0] : spans[idx][1]]) is not None
        ]
        if any(idx in consumed for idx in group_cfg_indices):
            continue
        consumed.update(group_cfg_indices)

        inactive = False
        group_replacements: list[tuple[int, int, str]] = []
        for cfg_index in group_cfg_indices:
            start, end = spans[cfg_index]
            kind, body = cfg_attribute_parts(text[start:end]) or ("", "")
            predicate_text = body
            expansion = ""
            if kind == "cfg_attr":
                cfg_attr_parts = split_top_level(body)
                if len(cfg_attr_parts) < 2:
                    diagnostics.append(
                        CfgDiagnostic(
                            path=rel(root, path),
                            line=text.count("\n", 0, start) + 1,
                            predicate=body.strip(),
                            reason="cfg_attr_missing_expansion",
                        )
                    )
                    continue
                predicate_text = cfg_attr_parts[0]
                expansion = "\n".join(f"#[{item}]" for item in cfg_attr_parts[1:])
            try:
                predicate = CfgParser(predicate_text).parse_complete()
            except CfgParseError as error:
                diagnostics.append(
                    CfgDiagnostic(
                        path=rel(root, path),
                        line=text.count("\n", 0, start) + 1,
                        predicate=predicate_text.strip(),
                        reason=f"cfg_parse_error: {error}",
                    )
                )
                continue
            value = evaluate_cfg(predicate, profile)
            if value is None:
                diagnostics.append(
                    CfgDiagnostic(
                        path=rel(root, path),
                        line=text.count("\n", 0, start) + 1,
                        predicate=predicate.render(),
                        reason="unsupported_cfg_predicate",
                    )
                )
                continue
            if kind == "cfg" and not value:
                inactive = True
            elif kind == "cfg":
                group_replacements.append((start, end, blank_preserving_newlines(text[start:end])))
            elif value:
                try:
                    replacement = replace_preserving_newlines(text[start:end], expansion)
                except CfgParseError as error:
                    diagnostics.append(
                        CfgDiagnostic(
                            path=rel(root, path),
                            line=text.count("\n", 0, start) + 1,
                            predicate=predicate.render(),
                            reason=f"cfg_attr_expansion_error: {error}",
                        )
                    )
                else:
                    group_replacements.append((start, end, replacement))
            else:
                group_replacements.append((start, end, blank_preserving_newlines(text[start:end])))

        if inactive:
            target_start = spans[group_end_index][1]
            target_end = cfg_target_end(mask, target_start)
            if target_end is None:
                diagnostics.append(
                    CfgDiagnostic(
                        path=rel(root, path),
                        line=text.count("\n", 0, spans[group_start_index][0]) + 1,
                        predicate=" && ".join(
                            (cfg_attribute_parts(text[spans[idx][0] : spans[idx][1]]) or ("", ""))[1].strip()
                            for idx in group_cfg_indices
                        ),
                        reason="cfg_target_extent_unknown",
                    )
                )
                continue
            start = spans[group_start_index][0]
            replacements.append((start, target_end, blank_preserving_newlines(text[start:target_end])))
        else:
            replacements.extend(group_replacements)

    result = text
    for start, end, replacement in sorted(replacements, reverse=True):
        result = result[:start] + replacement + result[end:]
    return result, diagnostics


@dataclass(frozen=True)
class HostCall:
    path: str
    line: int
    function: str
    function_id: str
    delegation_kind: str
    host_symbol: str
    expression: str
    evidence: str


@dataclass(frozen=True)
class FunctionCall:
    caller_id: str
    target_id: str
    path: str
    line: int
    target_expression: str
    expression: str
    evidence: str


@dataclass(frozen=True)
class UnknownCall:
    caller_id: str
    path: str
    line: int
    target_expression: str
    reason: str
    candidate_function_ids: tuple[str, ...]
    expression: str
    evidence: str


@dataclass
class FunctionInfo:
    name: str
    path: Path
    start_line: int
    body_start_line: int
    signature: str
    attr_text: str
    lines: list[tuple[int, str]] = field(default_factory=list)

    @property
    def module(self) -> str:
        return self.path.stem

    @property
    def identity(self) -> str:
        return f"{self.module}::{self.name}@{self.start_line}"

    @property
    def is_call_graph_item(self) -> bool:
        first_line = self.signature.splitlines()[0]
        return first_line == first_line.lstrip()

    @property
    def is_exported_abi(self) -> bool:
        signature = self.signature
        attrs = self.attr_text
        return (
            ('extern "C"' in signature or 'extern "C-unwind"' in signature)
            and ("no_mangle" in attrs or "export_name" in attrs)
        )

    @property
    def exported_symbol(self) -> str:
        match = EXPORT_NAME_RE.search(self.attr_text)
        return match.group(1) if match else self.name


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_tree_sha256(files: list[Path], root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(rel(root, path).encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def parse_module_imports(text: str) -> dict[str, str]:
    """Return simple module-scope function imports as local -> full path."""

    imports: dict[str, str] = {}
    masked = rust_code_mask(text)
    for match in USE_ITEM_RE.finditer(masked):
        expression = " ".join(match.group(1).split())
        normalized = re.sub(r"\s*::\s*", "::", expression)
        normalized = re.sub(r"\{\s*", "{", normalized)
        normalized = re.sub(r"\s*\}", "}", normalized)
        if "::{" in normalized and normalized.endswith("}"):
            base, members = normalized.split("::{", 1)
            members = members[:-1]
            for member in members.split(","):
                if not member or "{" in member or "}" in member or member == "self":
                    continue
                alias_parts = re.split(r"\s+as\s+", member.strip(), maxsplit=1)
                original = re.sub(r"\s+", "", alias_parts[0])
                local_name = alias_parts[1].strip() if len(alias_parts) == 2 else original
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", local_name):
                    imports[local_name] = f"{base}::{original}"
            continue

        alias_parts = re.split(r"\s+as\s+", expression, maxsplit=1)
        original = re.sub(r"\s+", "", alias_parts[0])
        local_name = (
            alias_parts[1].strip()
            if len(alias_parts) == 2
            else original.rsplit("::", 1)[-1]
        )
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", local_name):
            imports[local_name] = original
    return imports


def resolve_import_target(imports: dict[str, str], expression: str) -> str | None:
    """Expand module-local import aliases in one callable path."""

    parts = expression.lstrip(":").split("::")
    visited: set[str] = set()
    while parts and parts[0] in imports:
        head = parts[0]
        if head in visited:
            return None
        visited.add(head)
        replacement = imports[head].lstrip(":").split("::")
        parts = [*replacement, *parts[1:]]
    return "::".join(parts)


def parse_declared_types(text: str) -> set[str]:
    """Return nominal types declared directly in one source module."""

    mask = rust_code_mask(text)
    return set(
        re.findall(
            r"\b(?:struct|enum|union|trait)\s+([A-Za-z_][A-Za-z0-9_]*)\b",
            mask,
        )
    )


def parse_generated_associated_leaves(text: str) -> set[tuple[str, str]]:
    """Return compiler-generated associated functions known to be host-free."""

    mask = rust_code_mask(text)
    spans = attribute_spans(text, mask)
    generated: set[tuple[str, str]] = set()
    declaration_re = re.compile(
        r"(?m)^[ \t]*(?:(?:pub(?:\([^)]*\))?)\s+)?"
        r"(?:struct|enum|union)\s+([A-Za-z_][A-Za-z0-9_]*)\b"
    )
    for declaration in declaration_re.finditer(mask):
        cursor = declaration.start()
        attributes: list[str] = []
        for start, end in reversed(spans):
            if end > cursor:
                continue
            if not only_trivia(mask, end, cursor):
                break
            attributes.append(text[start:end])
            cursor = start
        attribute_text = "\n".join(reversed(attributes))
        for derive in re.findall(r"derive\s*\(([^)]*)\)", attribute_text, re.DOTALL):
            if "Default" in {item.strip().rsplit("::", 1)[-1] for item in derive.split(",")}:
                generated.add((declaration.group(1), "default"))
    return generated


def parse_enum_constructors(text: str) -> set[tuple[str, str]]:
    """Return ``(enum, variant)`` constructors declared in one module."""

    mask = rust_code_mask(text)
    constructors: set[tuple[str, str]] = set()
    for enum_match in re.finditer(r"\benum\s+([A-Za-z_][A-Za-z0-9_]*)\b", mask):
        brace = mask.find("{", enum_match.end())
        semicolon = mask.find(";", enum_match.end())
        if brace < 0 or (semicolon >= 0 and semicolon < brace):
            continue
        close = matching_delimiter(mask, brace, "{", "}")
        if close is None:
            continue
        body = text[brace + 1 : close - 1]
        for variant in split_top_level(body):
            variant_mask = rust_code_mask(variant)
            cursor = 0
            while cursor < len(variant_mask):
                whitespace = re.match(r"\s*", variant_mask[cursor:])
                cursor += len(whitespace.group(0)) if whitespace is not None else 0
                if not variant_mask.startswith("#[", cursor):
                    break
                opening = variant_mask.find("[", cursor)
                end = matching_delimiter(variant_mask, opening, "[", "]")
                if end is None:
                    cursor = len(variant_mask)
                    break
                cursor = end
            name_match = re.match(
                r"([A-Za-z_][A-Za-z0-9_]*)\b", variant_mask[cursor:]
            )
            if name_match is not None:
                constructors.add((enum_match.group(1), name_match.group(1)))
    return constructors


def parse_generated_macro_functions(path: Path, text: str) -> list[FunctionInfo]:
    """Model functions emitted by reviewed declaration macros.

    Unknown macro token trees never create lexical bindings. Reviewed declaration
    macros are represented by synthetic functions with the same exported names
    and call edges as their expansions. This keeps coverage and host-dependency
    propagation source-derived without needing rustc expansion output.
    """

    mask = rust_code_mask(text)
    closing_delimiters = {"(": ")", "[": "]", "{": "}"}
    functions: list[FunctionInfo] = []

    definition_spans: list[tuple[int, int]] = []
    definition_re = re.compile(
        r"\bmacro_rules\s*!\s*[A-Za-z_][A-Za-z0-9_]*\s*([({\[])"
    )
    for definition in definition_re.finditer(mask):
        opening = definition.start(1)
        delimiter = definition.group(1)
        end = matching_delimiter(
            mask, opening, delimiter, closing_delimiters[delimiter]
        )
        if end is not None:
            definition_spans.append((definition.start(), end))

    def inside_definition(position: int) -> bool:
        return any(start <= position < end for start, end in definition_spans)

    def add_function(
        name: str,
        line_no: int,
        body: str,
        *,
        exported: bool,
    ) -> None:
        signature = (
            f'pub unsafe extern "C" fn {name}() {{ {body} }}'
            if exported
            else f"fn {name}() {{ {body} }}"
        )
        functions.append(
            FunctionInfo(
                name=name,
                path=path,
                start_line=line_no,
                body_start_line=line_no,
                signature=signature,
                attr_text="#[unsafe(no_mangle)]" if exported else "",
                lines=[(line_no, signature)],
            )
        )

    def require_match(
        pattern: str, statement: str, macro_name: str, line_no: int
    ) -> re.Match[str]:
        matched = re.fullmatch(pattern, statement, re.DOTALL)
        if matched is None:
            compact = " ".join(statement.split())
            raise ValueError(
                f"unrecognized {macro_name}! declaration at {path}:{line_no}: {compact}"
            )
        return matched

    math_bulk_macros = {
        "unary": r"([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*=\s*\|[^|]*\|\s*(.+)",
        "unary_one": r"([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*=\s*\|[^|]*\|\s*(.+)",
        "binary": r"([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*=\s*\|[^|]*\|\s*(.+)",
        "ternary": r"([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*=\s*\|[^|]*\|\s*(.+)",
        "with_reg": r"([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*=\s*\|[^|]*\|\s*(.+)",
        "to_int": r"([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*->\s*.+?=\s*\|[^|]*\|\s*(.+)",
        "two_to": r"([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*->\s*.+?=\s*\|[^|]*\|\s*(.+)",
        "three_to": r"([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*->\s*.+?=\s*\|[^|]*\|\s*(.+)",
        "fromfp": r"([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*->\s*.+?=\s*([A-Za-z_:][A-Za-z0-9_:]*)",
        "complex_unary": r"([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_:][A-Za-z0-9_:]*)",
    }
    math_helper_macros = {"ptr_in", "ptr_and_ld", "real_shim"}
    math_target_macros = {"ptr_pair"}
    finite_macros = {
        "finite_unary_f64",
        "finite_unary_f32",
        "finite_unary_f128",
        "finite_binary_f64",
        "finite_binary_f32",
        "finite_binary_f128",
    }
    rpc_macros = {"rpc_stub", "xdr_i32_prim", "xdr_narrow_prim", "xdr_i64_prim"}
    unistd_leaf_macros = {
        "xdr_stub",
        "nss_files_end_stub",
        "nss_files_set_void_stub",
        "nss_files_set_stayopen_stub",
        "nss_files_parse_stub",
    }
    unistd_errno_macros = {
        "nss_files_get_ent_stub",
        "nss_files_get_by_str_stub",
        "nss_files_get_by_int_stub",
    }

    for invocation in MACRO_INVOCATION_RE.finditer(mask):
        if inside_definition(invocation.start()):
            continue
        macro_name = re.split(r"\s*::\s*", invocation.group(1))[-1]
        opening = invocation.start(2)
        delimiter = invocation.group(2)
        end = matching_delimiter(
            mask,
            opening,
            delimiter,
            closing_delimiters[delimiter],
        )
        if end is None:
            if macro_name in {
                "avx2_dispatch",
                *math_bulk_macros,
                *math_helper_macros,
                *math_target_macros,
                "canonicalize",
                *finite_macros,
                *rpc_macros,
                *unistd_leaf_macros,
                *unistd_errno_macros,
            }:
                line_no = text.count("\n", 0, invocation.start()) + 1
                raise ValueError(
                    f"unterminated reviewed macro invocation at {path}:{line_no}"
                )
            continue

        body_start = opening + 1
        body = text[body_start : end - 1]
        body_mask = mask[body_start : end - 1]

        if macro_name == "avx2_dispatch":
            declaration = AVX2_DISPATCH_DECL_RE.search(body_mask)
            if declaration is None:
                line_no = text.count("\n", 0, invocation.start()) + 1
                raise ValueError(
                    f"unrecognized avx2_dispatch! declaration at {path}:{line_no}"
                )
            name, target = declaration.groups()
            line_no = text.count("\n", 0, body_start + declaration.start()) + 1
            add_function(name, line_no, f"{target}();", exported=False)
            continue

        if path.name == "math_abi.rs" and macro_name in math_bulk_macros:
            for offset, statement in split_top_level_with_offsets(body, ";"):
                if not statement:
                    continue
                line_no = text.count("\n", 0, body_start + offset) + 1
                matched = require_match(
                    math_bulk_macros[macro_name], statement, macro_name, line_no
                )
                groups = matched.groups()
                if macro_name in {"unary", "complex_unary"}:
                    first, second, helper, target = groups
                    exported_names = (first, second)
                else:
                    first, helper, target = groups
                    exported_names = (first,)
                add_function(helper, line_no, f"{target};", exported=False)
                for exported_name in exported_names:
                    add_function(
                        exported_name, line_no, f"{helper}();", exported=True
                    )
            continue

        if path.name == "math_abi.rs" and macro_name in math_helper_macros:
            for offset, statement in split_top_level_with_offsets(body, ";"):
                if not statement:
                    continue
                line_no = text.count("\n", 0, body_start + offset) + 1
                matched = require_match(
                    r"([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)",
                    statement,
                    macro_name,
                    line_no,
                )
                name, helper = matched.groups()
                add_function(name, line_no, f"{helper}();", exported=True)
            continue

        if path.name == "math_abi.rs" and macro_name in math_target_macros:
            for offset, statement in split_top_level_with_offsets(body, ";"):
                if not statement:
                    continue
                line_no = text.count("\n", 0, body_start + offset) + 1
                matched = require_match(
                    r"([A-Za-z_]\w*)\s*=\s*([A-Za-z_:][A-Za-z0-9_:]*)",
                    statement,
                    macro_name,
                    line_no,
                )
                name, target = matched.groups()
                add_function(name, line_no, f"{target}();", exported=True)
            continue

        if path.name == "math_abi.rs" and macro_name == "canonicalize":
            for offset, statement in split_top_level_with_offsets(body, ";"):
                if not statement:
                    continue
                line_no = text.count("\n", 0, body_start + offset) + 1
                matched = require_match(
                    r"([A-Za-z_]\w*)", statement, macro_name, line_no
                )
                add_function(
                    matched.group(1),
                    line_no,
                    "super::canonicalizef128();",
                    exported=True,
                )
            continue

        if path.name == "math_abi.rs" and macro_name in finite_macros:
            line_no = text.count("\n", 0, body_start) + 1
            parts = split_top_level(body)
            if len(parts) != 2:
                raise ValueError(
                    f"unrecognized {macro_name}! declaration at {path}:{line_no}"
                )
            name_match = require_match(
                r"([A-Za-z_]\w*)", parts[0], macro_name, line_no
            )
            target_match = require_match(
                r"([A-Za-z_:][A-Za-z0-9_:]*)", parts[1], macro_name, line_no
            )
            add_function(
                name_match.group(1),
                line_no,
                f"{target_match.group(1)}();",
                exported=True,
            )
            continue

        if path.name == "rpc_abi.rs" and macro_name in rpc_macros:
            line_no = text.count("\n", 0, body_start) + 1
            name_match = require_match(
                r"\s*([A-Za-z_]\w*)\s*\(.*", body, macro_name, line_no
            )
            calls = "xp32(); xg32();" if macro_name != "rpc_stub" else ""
            add_function(name_match.group(1), line_no, calls, exported=True)
            continue

        if path.name == "unistd_abi.rs" and macro_name in {
            *unistd_leaf_macros,
            *unistd_errno_macros,
        }:
            line_no = text.count("\n", 0, body_start) + 1
            name_match = re.match(r"\s*([A-Za-z_]\w*)\b", body)
            if name_match is None:
                raise ValueError(
                    f"unrecognized {macro_name}! declaration at {path}:{line_no}"
                )
            calls = (
                "nss_set_errnop_enoent();"
                if macro_name in unistd_errno_macros
                else ""
            )
            add_function(name_match.group(1), line_no, calls, exported=True)
    return functions


def parse_functions(path: Path, text: str | None = None) -> list[FunctionInfo]:
    if text is None:
        text = path.read_text(encoding="utf-8")
    rows = text.splitlines()
    mask_rows = rust_code_mask(text).splitlines()
    if len(mask_rows) != len(rows):
        raise ValueError(f"Rust lexical mask changed line count for {path}")
    functions: list[FunctionInfo] = []
    idx = 0
    while idx < len(rows):
        match = FUNCTION_RE.search(mask_rows[idx])
        if not match:
            idx += 1
            continue

        attr_start = idx
        while attr_start > 0:
            prev = rows[attr_start - 1].strip()
            if prev.startswith("#[") or prev.startswith("///") or prev == "":
                attr_start -= 1
                continue
            break
        attrs = "\n".join(rows[attr_start:idx])
        signature_lines: list[str] = []
        brace_balance = 0
        end_idx = idx
        seen_open = False
        declaration_only = False
        parameter_depth = 0
        bracket_depth = 0
        saw_parameter_list = False
        parameters_closed = False
        body_start_line = idx + 1
        while end_idx < len(rows):
            current = rows[end_idx]
            masked_current = mask_rows[end_idx]
            signature_lines.append(current)
            if end_idx == idx:
                # Ignore enclosing syntax before the matched `fn` token. In
                # particular, an inline `extern "C" { fn declaration(); }`
                # must not mistake the extern block's brace for a body.
                masked_current = masked_current[match.start() :]
            body_offset: int | None = None
            for offset, char in enumerate(masked_current):
                if char == "(":
                    parameter_depth += 1
                    saw_parameter_list = True
                    continue
                if char == ")" and parameter_depth > 0:
                    parameter_depth -= 1
                    if saw_parameter_list and parameter_depth == 0:
                        parameters_closed = True
                    continue
                if char == "[":
                    bracket_depth += 1
                    continue
                if char == "]" and bracket_depth > 0:
                    bracket_depth -= 1
                    continue
                if not parameters_closed or parameter_depth != 0 or bracket_depth != 0:
                    continue
                if char == ";":
                    declaration_only = True
                    break
                if char == "{":
                    seen_open = True
                    body_start_line = end_idx + 1
                    body_offset = offset
                    break
            if declaration_only:
                break
            if seen_open and body_offset is not None:
                body_fragment = masked_current[body_offset:]
                brace_balance += body_fragment.count("{") - body_fragment.count("}")
            if seen_open:
                break
            end_idx += 1

        if declaration_only:
            idx = max(end_idx + 1, idx + 1)
            continue

        function = FunctionInfo(
            name=match.group(1),
            path=path,
            start_line=idx + 1,
            body_start_line=body_start_line,
            signature="\n".join(signature_lines),
            attr_text=attrs,
        )
        while end_idx < len(rows):
            current = rows[end_idx]
            masked_current = mask_rows[end_idx]
            if end_idx != body_start_line - 1:
                brace_balance += masked_current.count("{") - masked_current.count("}")
            function.lines.append((end_idx + 1, current))
            if seen_open and brace_balance <= 0:
                break
            end_idx += 1

        functions.append(function)
        idx = max(end_idx + 1, idx + 1)
    functions.extend(parse_generated_macro_functions(path, text))
    return functions


def strip_comments(line: str) -> str:
    return line.split("//", 1)[0]


def function_body_line(function: FunctionInfo, line_no: int, raw_line: str) -> str:
    """Return only executable body text for one parsed function line."""

    if line_no < function.body_start_line:
        return ""
    line = strip_comments(raw_line)
    if line_no == function.body_start_line:
        opening_brace = line.find("{")
        if opening_brace < 0:
            return ""
        return line[opening_brace + 1 :]
    return line


def function_body_lines(function: FunctionInfo) -> list[tuple[int, str, str]]:
    """Return raw evidence plus a comment/literal-free executable view."""

    raw_text = "\n".join(raw_line for _, raw_line in function.lines)
    masked_lines = rust_code_mask(raw_text).split("\n")
    if len(masked_lines) != len(function.lines):
        raise ValueError(f"Rust lexical mask changed line count for {function.identity}")
    return [
        (
            line_no,
            function_body_line(function, line_no, raw_line),
            function_body_line(function, line_no, masked_line),
        )
        for (line_no, raw_line), masked_line in zip(function.lines, masked_lines)
    ]


def scoped_call_paths(function: FunctionInfo) -> dict[int, list[tuple[str, bool]]]:
    """Return call paths and whether a live lexical binding shadows each one.

    Simple ``let`` bindings become visible only after their statement's
    semicolon and disappear at the end of their brace scope.  Constructs this
    lexical scanner cannot prove shadowing for remain conservative: the call is
    not suppressed from host/call-graph analysis.
    """

    body_lines = function_body_lines(function)
    body_text = "\n".join(line for _, _, line in body_lines)
    macro_token_spans: list[tuple[int, int, str]] = []
    closing_delimiters = {"(": ")", "[": "]", "{": "}"}
    for invocation in MACRO_INVOCATION_RE.finditer(body_text):
        macro_name = re.split(r"\s*::\s*", invocation.group(1))[-1]
        opening = invocation.start(2)
        delimiter = invocation.group(2)
        end = matching_delimiter(
            body_text,
            opening,
            delimiter,
            closing_delimiters[delimiter],
        )
        if end is not None:
            macro_token_spans.append((opening, end, macro_name))

    def is_macro_token(position: int) -> bool:
        return any(start <= position < end for start, end, _ in macro_token_spans)

    active_scopes = [set(PARAM_BINDING_RE.findall(function.signature))]
    scope_is_macro = [False]
    pending_bindings = [set()]
    next_scope_bindings: set[str] = set()
    calls_by_line: dict[int, list[tuple[str, bool]]] = {}
    line_offset = 0
    for line_no, _, line in body_lines:
        events: list[tuple[int, int, str, str | None]] = []
        for binding in LOCAL_BINDING_RE.finditer(line):
            if is_macro_token(line_offset + binding.start()):
                continue
            statement_start = max(
                line.rfind(";", 0, binding.start()),
                line.rfind("{", 0, binding.start()),
            )
            prefix = line[statement_start + 1 : binding.start()]
            kind = (
                "next_scope_binding"
                if re.search(r"\b(?:if|while)\b", prefix)
                or "&&" in prefix
                or "||" in prefix
                else "binding"
            )
            events.append((binding.start(), 1, kind, binding.group(1)))
        for closure in re.finditer(r"\|([^|\n]*)\|", line):
            if is_macro_token(line_offset + closure.start()):
                continue
            for parameter in closure.group(1).split(","):
                binding = re.match(
                    r"\s*(?:(?:mut|ref)\s+)?([A-Za-z_][A-Za-z0-9_]*)\b",
                    parameter,
                )
                if binding is not None:
                    events.append(
                        (closure.end(), 1, "next_scope_binding", binding.group(1))
                    )
        for local_function in FUNCTION_RE.finditer(line):
            if is_macro_token(line_offset + local_function.start()):
                continue
            events.append((local_function.start(), 1, "local_function", local_function.group(1)))
        for call in CALL_PATH_RE.finditer(line):
            events.append((call.start(), 2, "call", call.group(1)))
        for position, char in enumerate(line):
            if is_macro_token(line_offset + position):
                continue
            if char == "{":
                events.append((position, 0, "open", None))
            elif char == "}":
                events.append((position, 0, "close", None))
            elif char == ";":
                events.append((position, 0, "semicolon", None))

        for _, _, kind, value in sorted(events):
            if kind == "open":
                active_scopes.append(set(next_scope_bindings))
                next_scope_bindings.clear()
                scope_is_macro.append(False)
                pending_bindings.append(set())
            elif kind == "close":
                if len(active_scopes) > 1:
                    active_scopes.pop()
                    scope_is_macro.pop()
                    pending_bindings.pop()
            elif kind == "semicolon":
                active_scopes[-1].update(pending_bindings[-1])
                pending_bindings[-1].clear()
                next_scope_bindings.clear()
            elif kind == "binding":
                pending_bindings[-1].add(value or "")
            elif kind == "next_scope_binding":
                next_scope_bindings.add(value or "")
            elif kind == "local_function":
                target_scope = len(active_scopes) - 1
                while target_scope > 0 and scope_is_macro[target_scope]:
                    target_scope -= 1
                active_scopes[target_scope].add(value or "")
            else:
                target_expression = value or ""
                target_name = target_expression.rsplit("::", 1)[-1]
                shadowed = "::" not in target_expression and any(
                    target_name in scope for scope in active_scopes
                )
                calls_by_line.setdefault(line_no, []).append(
                    (target_expression, shadowed)
                )
        line_offset += len(line) + 1
    return calls_by_line


def detect_host_calls(
    function: FunctionInfo,
    root: Path,
    *,
    include_libc_calls: bool = False,
    module_imports: dict[str, str] | None = None,
) -> list[HostCall]:
    calls: list[HostCall] = []
    path = rel(root, function.path)
    call_paths = scoped_call_paths(function)
    for line_no, raw_line, line in function_body_lines(function):
        if not line.strip():
            continue
        expression = raw_line.strip()
        for resolver in re.finditer(r"\bresolve_host_symbol_raw\s*\(", line):
            literal = RAW_LITERAL_RE.match(raw_line, resolver.start())
            if literal is not None:
                calls.append(
                    HostCall(
                        path=path,
                        line=line_no,
                        function=function.name,
                        function_id=function.identity,
                        delegation_kind="resolve_host_symbol_raw_literal",
                        host_symbol=literal.group(1),
                        expression=expression,
                        evidence=f"{path}:{line_no}",
                    )
                )
        for resolver in re.finditer(r"\bresolve_host_symbol_cached\s*\(", line):
            literal = CACHED_LITERAL_RE.match(raw_line, resolver.start())
            if literal is not None:
                calls.append(
                    HostCall(
                        path=path,
                        line=line_no,
                        function=function.name,
                        function_id=function.identity,
                        delegation_kind="resolve_host_symbol_cached_literal",
                        host_symbol=literal.group(1),
                        expression=expression,
                        evidence=f"{path}:{line_no}",
                    )
                )
        if RAW_DYNAMIC_RE.search(line):
            calls.append(
                HostCall(
                    path=path,
                    line=line_no,
                    function=function.name,
                    function_id=function.identity,
                    delegation_kind="resolve_host_symbol_raw_dynamic",
                    host_symbol="<dynamic>",
                    expression=expression,
                    evidence=f"{path}:{line_no}",
                )
            )
        for thread_key in RESOLVED_THREAD_RE.findall(line):
            calls.append(
                HostCall(
                    path=path,
                    line=line_no,
                    function=function.name,
                    function_id=function.identity,
                    delegation_kind="resolved_thread_raw_accessor",
                    host_symbol=THREAD_RAW_SYMBOLS.get(thread_key, f"pthread_{thread_key}"),
                    expression=expression,
                    evidence=f"{path}:{line_no}",
                )
            )
        if include_libc_calls:
            for symbol in LIBC_CALL_RE.findall(line):
                if symbol == "syscall":
                    continue
                calls.append(
                    HostCall(
                        path=path,
                        line=line_no,
                        function=function.name,
                        function_id=function.identity,
                        delegation_kind="libc_crate_extern_call",
                        host_symbol=symbol,
                        expression=expression,
                        evidence=f"{path}:{line_no}",
                    )
                )
            for target_expression, shadowed in call_paths.get(line_no, []):
                if shadowed:
                    continue
                imported_expression = resolve_import_target(
                    module_imports or {}, target_expression
                )
                if (
                    imported_expression is None
                    or not imported_expression.startswith("libc::")
                    or target_expression.lstrip(":").startswith("libc::")
                ):
                    continue
                symbol = imported_expression.rsplit("::", 1)[-1]
                calls.append(
                    HostCall(
                        path=path,
                        line=line_no,
                        function=function.name,
                        function_id=function.identity,
                        delegation_kind="libc_crate_imported_extern_call",
                        host_symbol=symbol,
                        expression=expression,
                        evidence=f"{path}:{line_no}",
                    )
                )
        static_needles = [
            ("delegate_to_host_libc_start_main", "__libc_start_main", "startup_host_delegate"),
            ("host_dlsym(", "dlsym", "host_dlsym_helper"),
            ("host_dlvsym(", "dlvsym", "host_dlvsym_helper"),
            ("dlvsym_next(", "dlvsym", "rtld_next_host_dlvsym"),
            ("host_dl_iterate_phdr_cached(", "dl_iterate_phdr", "cached_host_loader_symbol"),
            ("host_dladdr_cached(", "dladdr", "cached_host_loader_symbol"),
            ("host_malloc_raw(", "malloc", "cached_host_allocator_symbol"),
            ("host_calloc_raw(", "calloc", "cached_host_allocator_symbol"),
            ("host_realloc_raw(", "realloc", "cached_host_allocator_symbol"),
            ("host_free_raw(", "free", "cached_host_allocator_symbol"),
            ("host_errno_location_raw(", "__errno_location", "cached_host_errno_symbol"),
        ]
        for needle, host_symbol, kind in static_needles:
            if needle in line:
                calls.append(
                    HostCall(
                        path=path,
                        line=line_no,
                        function=function.name,
                        function_id=function.identity,
                        delegation_kind=kind,
                        host_symbol=host_symbol,
                        expression=expression,
                        evidence=f"{path}:{line_no}",
                    )
                )
    return calls


def function_indices(
    functions: list[FunctionInfo],
) -> tuple[
    dict[str, FunctionInfo],
    dict[tuple[str, str], list[str]],
    dict[str, list[str]],
    dict[tuple[str, str], list[str]],
]:
    function_by_id = {function.identity: function for function in functions}
    functions_by_module_and_name: dict[tuple[str, str], list[str]] = {}
    functions_by_name: dict[str, list[str]] = {}
    call_items_by_module_and_name: dict[tuple[str, str], list[str]] = {}
    for function in functions:
        call_items_by_module_and_name.setdefault(
            (function.module, function.name), []
        ).append(function.identity)
        # Rustfmt keeps module-level functions flush-left. Indented `fn` items
        # are methods, nested functions, or macro bodies; treating those as
        # module namespace entries is what made calls such as `drop(...)`
        # collide with unrelated `Drop::drop` methods.
        if not function.is_call_graph_item:
            continue
        functions_by_module_and_name.setdefault(
            (function.module, function.name), []
        ).append(function.identity)
        functions_by_name.setdefault(function.name, []).append(function.identity)
    for identities in functions_by_module_and_name.values():
        identities.sort()
    for identities in functions_by_name.values():
        identities.sort()
    for identities in call_items_by_module_and_name.values():
        identities.sort()
    return (
        function_by_id,
        functions_by_module_and_name,
        functions_by_name,
        call_items_by_module_and_name,
    )


def qualified_target_module(
    caller_module: str,
    parts: list[str],
    known_modules: set[str],
    module_aliases: dict[str, str | None] | None = None,
) -> tuple[str | None, bool]:
    """Return the exact file module for a source-local qualified call.

    The second result says whether the expression claims to be source-local. A
    local-looking path which cannot be represented by this flat-file scanner is
    evidence of an unknown edge, not permission to fall back to a bare-name
    match.
    """

    if len(parts) < 2:
        return None, False
    prefix = parts[:-1]
    if prefix == ["self"]:
        return caller_module, True
    if prefix == ["super"] or prefix == ["crate"]:
        return "lib", True
    if len(prefix) == 1 and prefix[0] in known_modules:
        return prefix[0], True
    if len(prefix) == 1 and module_aliases is not None and prefix[0] in module_aliases:
        return module_aliases[prefix[0]], True
    if len(prefix) == 2 and prefix[0] in {"crate", "super"}:
        if prefix[1] in known_modules:
            return prefix[1], True
        if module_aliases is not None and prefix[1] in module_aliases:
            return module_aliases[prefix[1]], True
        return None, True
    if len(prefix) >= 2 and prefix[0] == "self":
        return caller_module, True
    if len(prefix) >= 3 and prefix[0] in {"crate", "super"}:
        if prefix[1] in known_modules:
            return prefix[1], True
        if module_aliases is not None and prefix[1] in module_aliases:
            return module_aliases[prefix[1]], True
        return None, True
    if prefix[0] in {"crate", "self", "super"}:
        return None, True
    return None, False


def resolve_function_calls(
    function: FunctionInfo,
    functions_by_module_and_name: dict[tuple[str, str], list[str]],
    functions_by_name: dict[str, list[str]],
    call_items_by_module_and_name: dict[tuple[str, str], list[str]],
    known_modules: set[str],
    root: Path,
    *,
    module_aliases: dict[str, str | None] | None = None,
    module_imports: dict[str, dict[str, str]] | None = None,
    declared_types_by_module: dict[str, set[str]] | None = None,
    enum_constructors: set[tuple[str, str, str]] | None = None,
    generated_associated_leaves: set[tuple[str, str, str]] | None = None,
    conservative_nonlocal_unknown: bool = False,
) -> tuple[list[FunctionCall], list[UnknownCall]]:
    resolved: list[FunctionCall] = []
    unknown: list[UnknownCall] = []
    path = rel(root, function.path)
    seen_resolved: set[tuple[int, str, str]] = set()
    seen_unknown: set[tuple[int, str, str, tuple[str, ...]]] = set()
    call_paths = scoped_call_paths(function)

    def module_item_candidates(
        module: str,
        name: str,
        visited: set[tuple[str, str]] | None = None,
    ) -> list[str]:
        """Resolve one module item, following explicit ``use`` re-exports."""

        key = (module, name)
        visited = set() if visited is None else visited
        if key in visited:
            return []
        visited.add(key)
        candidates = functions_by_module_and_name.get(key, [])
        if candidates:
            return candidates
        imported_expression = (module_imports or {}).get(module, {}).get(name)
        if imported_expression is None:
            return []
        imported_parts = imported_expression.split("::")
        imported_module, claims_local = qualified_target_module(
            module,
            imported_parts,
            known_modules,
            module_aliases,
        )
        if not claims_local or imported_module is None:
            return []
        return module_item_candidates(
            imported_module,
            imported_parts[-1],
            visited,
        )

    for line_no, raw_line, line in function_body_lines(function):
        if not line:
            continue
        expression = raw_line.strip()
        for target_expression, shadowed in call_paths.get(line_no, []):
            parts = target_expression.split("::")
            target_name = parts[-1]
            # The opening signature is part of `function.lines`; preserve the
            # previous detector's recursion exclusion and do not treat the
            # declaration itself as a call edge.
            if len(parts) == 1 and target_name == function.name:
                continue
            # A local value or parameter shadows an item with the same name.
            # Function-pointer calls such as `let host_dlopen = ...; host_dlopen()`
            # must not become edges to an unrelated module-level function.
            if shadowed:
                continue
            candidates: list[str]
            reason: str | None = None

            if len(parts) == 1:
                imported_expression = (module_imports or {}).get(
                    function.module, {}
                ).get(target_name)
                if imported_expression is not None:
                    imported_parts = imported_expression.split("::")
                    imported_name = imported_parts[-1]
                    imported_module, claims_local = qualified_target_module(
                        function.module,
                        imported_parts,
                        known_modules,
                        module_aliases,
                    )
                    candidates = (
                        module_item_candidates(imported_module, imported_name)
                        if imported_module is not None
                        else []
                    )
                    if claims_local and not candidates:
                        reason = "unresolved_imported_target"
                else:
                    candidates = functions_by_module_and_name.get(
                        (function.module, target_name), []
                    )
                if not candidates:
                    # Bare names do not resolve into sibling modules without an
                    # import. This lexical scanner intentionally refuses to
                    # guess at `use` resolution from unrelated same-named items.
                    if reason == "unresolved_imported_target":
                        pass
                    elif not conservative_nonlocal_unknown:
                        continue
                    else:
                        candidates = functions_by_name.get(target_name, [])
                        if not candidates:
                            continue
                        reason = "unresolved_unqualified_nonlocal_target"
                elif len(candidates) > 1:
                    reason = "ambiguous_unqualified_local_target"
            else:
                local_type = parts[-2]
                local_types = (declared_types_by_module or {}).get(
                    function.module, set()
                )
                if len(parts) == 2 and local_type in local_types:
                    target_module, claims_local = function.module, True
                else:
                    target_module, claims_local = qualified_target_module(
                        function.module, parts, known_modules, module_aliases
                    )
                if not claims_local:
                    continue
                candidates = (
                    module_item_candidates(target_module, target_name)
                    if target_module is not None
                    else []
                )
                target_types = (declared_types_by_module or {}).get(
                    target_module or "", set()
                )
                if (
                    not candidates
                    and target_module is not None
                    and local_type in target_types
                ):
                    if (target_module, local_type, target_name) in (
                        enum_constructors or set()
                    ):
                        continue
                    if (target_module, local_type, target_name) in (
                        generated_associated_leaves or set()
                    ):
                        continue
                    candidates = call_items_by_module_and_name.get(
                        (target_module, target_name), []
                    )
                if not candidates:
                    nonlocal_candidates = functions_by_name.get(target_name, [])
                    if conservative_nonlocal_unknown:
                        candidates = nonlocal_candidates
                        reason = "unresolved_qualified_target"
                    elif target_module is not None or len(nonlocal_candidates) <= 1:
                        continue
                    else:
                        candidates = nonlocal_candidates
                        reason = "unresolved_qualified_target"
                elif len(candidates) > 1:
                    reason = "ambiguous_qualified_target"

            if reason is None and len(candidates) == 1:
                target_id = candidates[0]
                if target_id == function.identity:
                    continue
                key = (line_no, target_expression, target_id)
                if key in seen_resolved:
                    continue
                seen_resolved.add(key)
                resolved.append(
                    FunctionCall(
                        caller_id=function.identity,
                        target_id=target_id,
                        path=path,
                        line=line_no,
                        target_expression=target_expression,
                        expression=expression,
                        evidence=f"{path}:{line_no}",
                    )
                )
                continue

            candidate_ids = tuple(sorted(candidates))
            key = (line_no, target_expression, reason or "ambiguous_target", candidate_ids)
            if key in seen_unknown:
                continue
            seen_unknown.add(key)
            unknown.append(
                UnknownCall(
                    caller_id=function.identity,
                    path=path,
                    line=line_no,
                    target_expression=target_expression,
                    reason=reason or "ambiguous_target",
                    candidate_function_ids=candidate_ids,
                    expression=expression,
                    evidence=f"{path}:{line_no}",
                )
            )
    return resolved, unknown


def shortest_reachability_paths(
    start: str,
    call_graph: dict[str, set[str]],
) -> dict[str, tuple[str, ...]]:
    """Return one deterministic shortest call path to every reachable item."""

    paths = {start: (start,)}
    pending = deque([start])
    while pending:
        caller = pending.popleft()
        for target in sorted(call_graph.get(caller, set())):
            if target in paths:
                continue
            paths[target] = (*paths[caller], target)
            pending.append(target)
    return paths


def reaches_host_symbol(
    start: str,
    host_symbol: str,
    call_graph: dict[str, set[str]],
    direct_host_calls: dict[str, list[HostCall]],
) -> bool:
    """Return whether `start` can reach a terminal resolver for `host_symbol`."""

    pending = [start]
    visited: set[str] = set()
    while pending:
        function_id = pending.pop()
        if function_id in visited:
            continue
        visited.add(function_id)
        if any(
            call.host_symbol == host_symbol
            for call in direct_host_calls.get(function_id, [])
        ):
            return True
        pending.extend(call_graph.get(function_id, set()) - visited)
    return False


def reaches_any_host_call(
    start: str,
    call_graph: dict[str, set[str]],
    direct_host_calls: dict[str, list[HostCall]],
) -> bool:
    pending = [start]
    visited: set[str] = set()
    while pending:
        function_id = pending.pop()
        if function_id in visited:
            continue
        visited.add(function_id)
        if direct_host_calls.get(function_id):
            return True
        pending.extend(call_graph.get(function_id, set()) - visited)
    return False


def analyze_host_dependencies(
    functions: list[FunctionInfo],
    root: Path,
    *,
    same_symbol_only: bool,
    include_libc_calls: bool,
    callsite_namespace: str = "",
    module_aliases: dict[str, str | None] | None = None,
    module_imports: dict[str, dict[str, str]] | None = None,
    declared_types_by_module: dict[str, set[str]] | None = None,
    enum_constructors: set[tuple[str, str, str]] | None = None,
    generated_associated_leaves: set[tuple[str, str, str]] | None = None,
    conservative_nonlocal_unknown: bool = False,
) -> dict[str, Any]:
    """Build either the legacy downgrade view or a full dependency view."""

    (
        function_by_id,
        functions_by_module_and_name,
        functions_by_name,
        call_items_by_module_and_name,
    ) = function_indices(functions)
    known_modules = {function.module for function in functions}
    direct_host_calls = {
        function.identity: detect_host_calls(
            function,
            root,
            include_libc_calls=include_libc_calls,
            module_imports=(module_imports or {}).get(function.module),
        )
        for function in functions
    }
    call_edges: dict[str, list[FunctionCall]] = {}
    direct_unknown_calls: dict[str, list[UnknownCall]] = {}
    for function in functions:
        resolved, unknown = resolve_function_calls(
            function,
            functions_by_module_and_name,
            functions_by_name,
            call_items_by_module_and_name,
            known_modules,
            root,
            module_aliases=module_aliases,
            module_imports=module_imports,
            declared_types_by_module=declared_types_by_module,
            enum_constructors=enum_constructors,
            generated_associated_leaves=generated_associated_leaves,
            conservative_nonlocal_unknown=conservative_nonlocal_unknown,
        )
        call_edges[function.identity] = resolved
        direct_unknown_calls[function.identity] = unknown
    call_graph = {
        function_id: {edge.target_id for edge in edges}
        for function_id, edges in call_edges.items()
    }

    exported_functions = [function for function in functions if function.is_exported_abi]
    reachability_paths = {
        function.identity: shortest_reachability_paths(function.identity, call_graph)
        for function in exported_functions
    }
    expanded_calls: dict[str, list[tuple[HostCall, tuple[str, ...]]]] = {}
    for function in exported_functions:
        calls: list[tuple[HostCall, tuple[str, ...]]] = []
        for target, witness_path in sorted(
            reachability_paths[function.identity].items(),
            key=lambda identity: (len(identity[1]), identity[1]),
        ):
            for call in direct_host_calls[target]:
                if same_symbol_only and call.host_symbol != function.exported_symbol:
                    continue
                calls.append((call, witness_path))
        if calls:
            expanded_calls[function.identity] = calls

    symbol_rows: list[dict[str, Any]] = []
    all_calls: list[dict[str, Any]] = []
    for function in sorted(
        exported_functions,
        key=lambda item: (rel(root, item.path), item.start_line),
    ):
        calls = expanded_calls.get(function.identity, [])
        if not calls:
            continue
        exported_symbol = function.exported_symbol
        host_symbols = sorted({call.host_symbol for call, _ in calls})
        kinds = sorted({call.delegation_kind for call, _ in calls})
        callsite_ids = []
        for idx, (call, witness_path) in enumerate(calls, 1):
            callsite_id = (
                f"{callsite_namespace}{function.module}:{exported_symbol}:"
                f"{function.start_line}:{idx:03d}"
            )
            callsite_ids.append(callsite_id)
            all_calls.append(
                {
                    "id": callsite_id,
                    "exported_symbol": exported_symbol,
                    "exported_function_id": function.identity,
                    "module": function.module,
                    "path": call.path,
                    "line": call.line,
                    "helper_function": call.function,
                    "helper_function_id": call.function_id,
                    "delegation_kind": call.delegation_kind,
                    "host_symbol": call.host_symbol,
                    "reachability_path": list(witness_path),
                    "reachability_hops": len(witness_path) - 1,
                    "expression": call.expression,
                    "evidence": call.evidence,
                }
            )
        symbol_rows.append(
            {
                "symbol": exported_symbol,
                "function_id": function.identity,
                "module": function.module,
                "source": f"{rel(root, function.path)}:{function.start_line}",
                "host_symbols": host_symbols,
                "delegation_kinds": kinds,
                "callsite_count": len(calls),
                "callsite_ids": callsite_ids,
            }
        )

    any_host_cache: dict[str, bool] = {}

    def candidate_reaches_host(candidate: str, symbol: str) -> bool:
        if same_symbol_only:
            return reaches_host_symbol(candidate, symbol, call_graph, direct_host_calls)
        if candidate not in any_host_cache:
            any_host_cache[candidate] = reaches_any_host_call(
                candidate, call_graph, direct_host_calls
            )
        return any_host_cache[candidate]

    unknown_call_rows: list[dict[str, Any]] = []
    exported_with_unknown_edges: set[str] = set()
    for caller_id, unknown_calls in direct_unknown_calls.items():
        caller = function_by_id[caller_id]
        for idx, call in enumerate(unknown_calls, 1):
            reachable_exports = []
            for exported in exported_functions:
                if caller_id not in reachability_paths[exported.identity]:
                    continue
                symbol = exported.exported_symbol
                candidate_can_delegate = any(
                    candidate_reaches_host(candidate, symbol)
                    for candidate in call.candidate_function_ids
                )
                unresolved_looks_delegating = (
                    not call.candidate_function_ids
                    and (
                        (not same_symbol_only and call.reason == "unresolved_qualified_target")
                        or
                        (same_symbol_only and symbol in call.target_expression)
                        or any(
                            marker in call.target_expression
                            for marker in ("host", "resolve", "delegate", "resolved")
                        )
                    )
                )
                if candidate_can_delegate or unresolved_looks_delegating:
                    reachable_exports.append(symbol)
            reachable_exports = sorted(set(reachable_exports))
            if not reachable_exports:
                continue
            exported_with_unknown_edges.update(reachable_exports)
            unknown_call_rows.append(
                {
                    "id": (
                        f"{callsite_namespace}{caller.module}:{caller.name}:"
                        f"{caller.start_line}:unknown:{idx:03d}"
                    ),
                    "caller_function": caller.name,
                    "caller_function_id": caller_id,
                    "module": caller.module,
                    "path": call.path,
                    "line": call.line,
                    "target_expression": call.target_expression,
                    "reason": call.reason,
                    "candidate_function_ids": list(call.candidate_function_ids),
                    "caller_is_exported_abi": caller.is_exported_abi,
                    "caller_exported_symbol": (
                        caller.exported_symbol if caller.is_exported_abi else None
                    ),
                    "reachable_from_exported_symbols": reachable_exports,
                    "expression": call.expression,
                    "evidence": call.evidence,
                }
            )

    symbol_rows.sort(key=lambda row: (row["module"], row["symbol"]))
    all_calls.sort(key=lambda row: (row["module"], row["exported_symbol"], row["id"]))
    unknown_call_rows.sort(
        key=lambda row: (row["module"], row["caller_function"], row["line"], row["id"])
    )
    module_counts: dict[str, int] = {}
    for row in symbol_rows:
        module_counts[row["module"]] = module_counts.get(row["module"], 0) + 1
    return {
        "exported_functions": exported_functions,
        "symbol_rows": symbol_rows,
        "calls": all_calls,
        "unknown_calls": unknown_call_rows,
        "exported_with_unknown_edges": exported_with_unknown_edges,
        "module_counts": module_counts,
        "function_count": len(functions),
        "resolved_call_edge_count": sum(len(edges) for edges in call_edges.values()),
    }


def broader_references(source_files: list[Path], root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in source_files:
        for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            text = raw_line.strip()
            if not text or not BROADER_REFERENCE_RE.search(text):
                continue
            rows.append(
                {
                    "path": rel(root, path),
                    "line": line_no,
                    "module": path.stem,
                    "evidence": f"{rel(root, path)}:{line_no}",
                    "text": text,
                }
            )
    return rows


def module_declarations(
    path: Path,
    text: str,
    abi_source_dir: Path,
) -> list[tuple[str, Path]]:
    mask = rust_code_mask(text)
    attrs = attribute_spans(text, mask)
    declarations: list[tuple[str, Path]] = []
    for match in MODULE_DECL_RE.finditer(mask):
        module_name = match.group(1)
        source_name = f"{module_name}.rs"
        preceding = [span for span in attrs if span[1] <= match.start()]
        if preceding and only_trivia(mask, preceding[-1][1], match.start()):
            path_match = PATH_ATTRIBUTE_RE.search(text[preceding[-1][0] : preceding[-1][1]])
            if path_match is not None:
                source_name = path_match.group(1)
        source_path = path.parent / source_name
        if not source_path.is_file():
            source_path = abi_source_dir / source_name
        declarations.append((module_name, source_path))
    return declarations


def profile_source_view(
    root: Path,
    abi_source_dir: Path,
    source_files: list[Path],
    profile: CfgProfile,
) -> tuple[dict[Path, str], dict[str, str | None], list[CfgDiagnostic]]:
    filtered: dict[Path, str] = {}
    diagnostics_by_path: dict[Path, list[CfgDiagnostic]] = {}
    for path in source_files:
        profile_text, path_diagnostics = apply_cfg_profile(
            path.read_text(encoding="utf-8"), path, root, profile
        )
        filtered[path] = profile_text
        diagnostics_by_path[path] = path_diagnostics

    lib_path = abi_source_dir / "lib.rs"
    active_paths: set[Path]
    module_alias_candidates: dict[str, set[str]] = {}
    module_diagnostics: list[CfgDiagnostic] = []
    if lib_path not in filtered:
        active_paths = set(source_files)
    else:
        active_paths = {lib_path}
        pending = deque([lib_path])
        while pending:
            parent = pending.popleft()
            for module_name, source_path in module_declarations(
                parent, filtered[parent], abi_source_dir
            ):
                if source_path not in filtered:
                    module_diagnostics.append(
                        CfgDiagnostic(
                            path=rel(root, parent),
                            line=1,
                            predicate=module_name,
                            reason=f"active_module_source_missing: {source_path}",
                        )
                    )
                    continue
                module_alias_candidates.setdefault(module_name, set()).add(source_path.stem)
                if source_path not in active_paths:
                    active_paths.add(source_path)
                    pending.append(source_path)

    module_aliases = {
        alias: next(iter(targets)) if len(targets) == 1 else None
        for alias, targets in module_alias_candidates.items()
    }
    diagnostics = [
        diagnostic
        for path in active_paths
        for diagnostic in diagnostics_by_path.get(path, [])
    ]
    diagnostics.extend(module_diagnostics)
    return (
        {path: filtered[path] for path in sorted(active_paths)},
        module_aliases,
        sorted(diagnostics, key=lambda item: (item.path, item.line, item.reason)),
    )


def support_matrix_coverage(
    root: Path,
    exported_functions: list[FunctionInfo],
) -> dict[str, Any]:
    matrix_path = root / "support_matrix.json"
    matrix_symbols: list[str] = []
    if matrix_path.is_file():
        matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
        rows = matrix.get("symbols", []) if isinstance(matrix, dict) else []
        matrix_symbols = [
            row["symbol"]
            for row in rows
            if isinstance(row, dict) and isinstance(row.get("symbol"), str)
        ]
    source_symbols = [function.exported_symbol for function in exported_functions]
    source_set = set(source_symbols)
    matrix_set = set(matrix_symbols)
    duplicate_source_symbols = sorted(
        symbol for symbol in source_set if source_symbols.count(symbol) > 1
    )
    duplicate_matrix_symbols = sorted(
        symbol for symbol in matrix_set if matrix_symbols.count(symbol) > 1
    )
    missing_from_source = sorted(matrix_set - source_set)
    missing_from_matrix = sorted(source_set - matrix_set)
    complete = bool(matrix_symbols) and not (
        duplicate_source_symbols
        or duplicate_matrix_symbols
        or missing_from_source
        or missing_from_matrix
    )
    return {
        "support_matrix_path": "support_matrix.json",
        "support_matrix_sha256": (
            file_sha256(matrix_path) if matrix_path.is_file() else None
        ),
        "support_matrix_row_count": len(matrix_symbols),
        "support_matrix_unique_symbol_count": len(matrix_set),
        "source_export_function_count": len(exported_functions),
        "source_unique_export_symbol_count": len(source_set),
        "duplicate_source_symbols": duplicate_source_symbols,
        "duplicate_support_matrix_symbols": duplicate_matrix_symbols,
        "missing_from_source_count": len(missing_from_source),
        "missing_from_source": missing_from_source,
        "missing_from_support_matrix_count": len(missing_from_matrix),
        "missing_from_support_matrix": missing_from_matrix,
        "complete": complete,
    }


def build_profile_census(
    root: Path,
    abi_source_dir: Path,
    source_files: list[Path],
    profile: CfgProfile,
) -> dict[str, Any]:
    filtered, module_aliases, cfg_diagnostics = profile_source_view(
        root, abi_source_dir, source_files, profile
    )
    functions: list[FunctionInfo] = []
    for path, text in filtered.items():
        functions.extend(parse_functions(path, text))
    module_imports = {
        path.stem: parse_module_imports(text) for path, text in filtered.items()
    }
    declared_types_by_module = {
        path.stem: parse_declared_types(text) for path, text in filtered.items()
    }
    enum_constructors = {
        (path.stem, enum_name, variant_name)
        for path, text in filtered.items()
        for enum_name, variant_name in parse_enum_constructors(text)
    }
    generated_associated_leaves = {
        (path.stem, type_name, function_name)
        for path, text in filtered.items()
        for type_name, function_name in parse_generated_associated_leaves(text)
    }
    analysis = analyze_host_dependencies(
        functions,
        root,
        same_symbol_only=False,
        include_libc_calls=True,
        callsite_namespace=f"{profile.name}:",
        module_aliases=module_aliases,
        module_imports=module_imports,
        declared_types_by_module=declared_types_by_module,
        enum_constructors=enum_constructors,
        generated_associated_leaves=generated_associated_leaves,
        conservative_nonlocal_unknown=True,
    )
    coverage = support_matrix_coverage(root, analysis["exported_functions"])
    host_dependencies_by_symbol = {
        row["symbol"]: row["host_symbols"] for row in analysis["symbol_rows"]
    }
    reachable_terminal_counts_by_symbol = {
        row["symbol"]: row["callsite_count"] for row in analysis["symbol_rows"]
    }
    unique_terminal_calls: dict[tuple[Any, ...], dict[str, Any]] = {}
    for call in analysis["calls"]:
        key = (
            call["path"],
            call["line"],
            call["helper_function_id"],
            call["host_symbol"],
            call["delegation_kind"],
        )
        unique_terminal_calls.setdefault(
            key,
            {
                "path": call["path"],
                "line": call["line"],
                "function_id": call["helper_function_id"],
                "host_symbol": call["host_symbol"],
                "delegation_kind": call["delegation_kind"],
                "expression": call["expression"],
                "evidence": call["evidence"],
            },
        )
    unknown_counts_by_reason: dict[str, int] = {}
    for row in analysis["unknown_calls"]:
        reason = row["reason"]
        unknown_counts_by_reason[reason] = unknown_counts_by_reason.get(reason, 0) + 1
    compact_unknown_calls = []
    for row in analysis["unknown_calls"][:100]:
        reachable = row["reachable_from_exported_symbols"]
        compact_unknown_calls.append(
            {
                "id": row["id"],
                "caller_function_id": row["caller_function_id"],
                "evidence": row["evidence"],
                "target_expression": row["target_expression"],
                "reason": row["reason"],
                "candidate_function_ids": row["candidate_function_ids"],
                "reachable_export_count": len(reachable),
                "reachable_export_sample": reachable[:20],
            }
        )
    blockers = []
    if cfg_diagnostics:
        blockers.append(
            {
                "code": "cfg_analysis_incomplete",
                "count": len(cfg_diagnostics),
            }
        )
    if analysis["symbol_rows"]:
        blockers.append(
            {
                "code": "reachable_host_dependencies",
                "count": len(analysis["symbol_rows"]),
            }
        )
    if analysis["unknown_calls"]:
        blockers.append(
            {
                "code": "unknown_reachable_call_edges",
                "count": len(analysis["unknown_calls"]),
            }
        )
    if not coverage["complete"]:
        blockers.append(
            {
                "code": "support_matrix_coverage_incomplete",
                "count": coverage["missing_from_source_count"]
                + coverage["missing_from_support_matrix_count"]
                + len(coverage["duplicate_source_symbols"])
                + len(coverage["duplicate_support_matrix_symbols"]),
            }
        )
    return {
        "profile": profile.to_json(),
        "active_source_file_count": len(filtered),
        "active_source_files": [rel(root, path) for path in filtered],
        "function_count": analysis["function_count"],
        "resolved_call_edge_count": analysis["resolved_call_edge_count"],
        "cfg_diagnostic_count": len(cfg_diagnostics),
        "cfg_diagnostics": [diagnostic.to_json() for diagnostic in cfg_diagnostics],
        "coverage": coverage,
        "summary": {
            "exported_function_count": len(analysis["exported_functions"]),
            "exported_symbol_with_host_dependency_count": len(analysis["symbol_rows"]),
            "host_dependency_callsite_count": len(analysis["calls"]),
            "unique_terminal_host_callsite_count": len(unique_terminal_calls),
            "unknown_reachable_call_edge_count": len(analysis["unknown_calls"]),
            "exported_symbol_with_unknown_call_edge_count": len(
                analysis["exported_with_unknown_edges"]
            ),
            "standalone_admission_ready": not blockers,
        },
        "admission_blockers": blockers,
        "host_dependencies_by_symbol": host_dependencies_by_symbol,
        "reachable_terminal_counts_by_symbol": reachable_terminal_counts_by_symbol,
        "terminal_host_callsites": [
            unique_terminal_calls[key] for key in sorted(unique_terminal_calls)
        ],
        "unknown_reachable_call_edge_counts_by_reason": unknown_counts_by_reason,
        "unknown_reachable_call_edge_samples": compact_unknown_calls,
    }


def build_payload(root: Path, abi_source_dir: Path) -> dict[str, Any]:
    source_files = sorted(abi_source_dir.glob("*.rs"))
    functions: list[FunctionInfo] = []
    for path in source_files:
        functions.extend(parse_functions(path))

    legacy = analyze_host_dependencies(
        functions,
        root,
        same_symbol_only=True,
        include_libc_calls=False,
    )
    symbol_rows = legacy["symbol_rows"]
    all_calls = legacy["calls"]
    unknown_call_rows = legacy["unknown_calls"]
    exported_functions = legacy["exported_functions"]
    exported_with_unknown_edges = legacy["exported_with_unknown_edges"]
    module_counts = legacy["module_counts"]
    required_anchor_rows = [
        {
            "symbol": symbol,
            "present": any(row["symbol"] == symbol for row in symbol_rows),
        }
        for symbol in REQUIRED_ANCHORS
    ]
    source_refs = broader_references(source_files, root)
    profile_census = {
        profile.name: build_profile_census(
            root, abi_source_dir, source_files, profile
        )
        for profile in CFG_PROFILES
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "bead": BEAD_ID,
        "description": "Source-derived census of exported ABI symbols with a call-graph witness to a resolver/delegate primitive for the same host symbol.",
        "detector": {
            "version": DETECTOR_VERSION,
            "abi_source_dir": rel(root, abi_source_dir),
            "source_file_count": len(source_files),
            "source_tree_sha256": source_tree_sha256(source_files, root),
            "function_identity": "<module>::<function>@<one-based-start-line>",
        },
        "policy": {
            "required_anchor_symbols": REQUIRED_ANCHORS,
            "host_delegation_needles": [
                "resolve_host_symbol_raw",
                "resolve_host_symbol_cached",
                "resolved_thread_*_raw",
                "delegate_to_host_libc_start_main",
                "host_dlsym",
                "host_dlvsym",
                "host_dl_iterate_phdr_cached",
                "host_dladdr_cached",
            ],
            "call_resolution": {
                "unqualified": "Resolve only to one function with the same name in the caller's module.",
                "qualified": "Resolve crate/self/super or scanned-module paths only to one exact module-qualified function.",
                "local_bindings": "Function parameters and let-bound values shadow module items and are never treated as call-graph edges.",
                "unknown": "Only ambiguous edges reachable from an exported ABI function and capable of hiding same-symbol host delegation are emitted; bare nonlocal names are never guessed.",
            },
            "status_derivation": "A row is emitted only when the exported symbol reaches terminal host evidence naming that same symbol; unrelated runtime dependencies cannot force WrapsHostLibc.",
            "profile_evidence": "Each release profile applies Rust cfg/cfg_attr predicates before finding every reachable terminal resolver or libc extern call. Admission fails closed on host dependencies, unknown call edges, cfg diagnostics, or incomplete support-matrix coverage.",
        },
        "summary": {
            "exported_symbol_count": sum(1 for function in functions if function.is_exported_abi),
            "host_delegating_symbol_count": len(symbol_rows),
            "host_delegation_callsite_count": len(all_calls),
            "unknown_call_edge_count": len(unknown_call_rows),
            "exported_symbol_with_unknown_call_edge_count": len(exported_with_unknown_edges),
            "broader_source_reference_count": len(source_refs),
            "module_count": len(module_counts),
            "required_anchor_count": len(REQUIRED_ANCHORS),
            "required_anchor_present_count": sum(1 for row in required_anchor_rows if row["present"]),
        },
        "module_census": [
            {"module": module, "host_delegating_symbol_count": count}
            for module, count in sorted(module_counts.items())
        ],
        "required_anchor_symbols": required_anchor_rows,
        "symbol_census": symbol_rows,
        "callsite_census": all_calls,
        "unknown_call_edges": unknown_call_rows,
        "profile_census": profile_census,
        "broader_source_references": source_refs,
        "source_file_hashes": [
            {"path": rel(root, path), "sha256": file_sha256(path)} for path in source_files
        ],
    }


def canonical(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def run_cfg_self_test(root: Path) -> int:
    source = r'''
#[cfg(not(feature = "standalone"))]
fn selected_helper() -> i32 { resolve_host_symbol_raw("selected_helper"); 1 }
#[cfg(feature = "standalone")]
fn selected_helper() -> i32 { 2 }

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn exported() -> i32 {
    #[cfg(not(feature = "standalone"))]
    { resolve_host_symbol_raw("exported"); }
    3
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", not(test)))]
fn linux_release_only() {}

#[cfg(target_feature = "sse2")]
fn baseline_target_feature_is_retained() {}

#[cfg(target_feature = "avx2")]
fn unavailable_target_feature_is_removed() {}

#[cfg(foo(bar))]
fn unknown_predicate_is_retained() {}

#[cfg(custom_host_path)]
fn unknown_flag_is_retained() {}

#[cfg(custom_host_mode = "enabled")]
fn unknown_value_is_retained() {}

#[cfg(not(feature = "standalone")]
fn malformed_predicate_is_retained() {}
'''
    fake_path = root / "scripts/__host_delegation_cfg_self_test.rs"
    profiles = {profile.name: profile for profile in CFG_PROFILES}
    interpose, interpose_diagnostics = apply_cfg_profile(
        source, fake_path, root, profiles[PROFILE_INTERPOSE]
    )
    standalone, standalone_diagnostics = apply_cfg_profile(
        source, fake_path, root, profiles[PROFILE_STANDALONE]
    )
    checks = 0

    def require(condition: bool, message: str) -> None:
        nonlocal checks
        checks += 1
        if not condition:
            raise AssertionError(message)

    require(len(interpose.splitlines()) == len(source.splitlines()), "interpose line count moved")
    require(len(standalone.splitlines()) == len(source.splitlines()), "standalone line count moved")
    require(
        'resolve_host_symbol_raw("selected_helper")' in interpose,
        "interpose profile removed its selected helper",
    )
    require(
        'resolve_host_symbol_raw("selected_helper")' not in standalone,
        "standalone profile retained an inactive host helper",
    )
    require(
        'resolve_host_symbol_raw("exported")' in interpose,
        "interpose profile removed its cfg-gated block",
    )
    require(
        'resolve_host_symbol_raw("exported")' not in standalone,
        "standalone profile retained an inactive cfg-gated block",
    )
    require(
        interpose.count("fn selected_helper") == 1
        and standalone.count("fn selected_helper") == 1,
        "mutually exclusive definitions did not collapse to one function per profile",
    )
    standalone_functions = parse_functions(fake_path, standalone)
    require(
        any(
            function.name == "exported" and function.is_exported_abi
            for function in standalone_functions
        ),
        "true cfg_attr did not materialize no_mangle export evidence",
    )
    require("fn linux_release_only" in standalone, "known release cfg evaluated false")
    require(
        "fn baseline_target_feature_is_retained" in standalone,
        "baseline target feature evaluated false",
    )
    require(
        "fn unavailable_target_feature_is_removed" not in standalone,
        "unavailable target feature evaluated true",
    )
    require(
        "fn unknown_predicate_is_retained" in standalone
        and any(
            diagnostic.reason == "unsupported_cfg_predicate"
            for diagnostic in standalone_diagnostics
        ),
        "unknown cfg predicate did not fail closed",
    )
    require(
        "fn unknown_flag_is_retained" in standalone
        and any(
            diagnostic.predicate == "custom_host_path"
            and diagnostic.reason == "unsupported_cfg_predicate"
            for diagnostic in standalone_diagnostics
        ),
        "unknown cfg flag did not fail closed",
    )
    require(
        "fn unknown_value_is_retained" in standalone
        and any(
            diagnostic.predicate == 'custom_host_mode = "enabled"'
            and diagnostic.reason == "unsupported_cfg_predicate"
            for diagnostic in standalone_diagnostics
        ),
        "unknown cfg value did not fail closed",
    )
    require(
        "fn malformed_predicate_is_retained" in standalone
        and any(
            diagnostic.reason.startswith("cfg_parse_error:")
            for diagnostic in standalone_diagnostics
        ),
        "malformed cfg predicate did not fail closed",
    )
    require(
        len(interpose_diagnostics) == len(standalone_diagnostics) == 4,
        "cfg diagnostics changed unexpectedly across profiles",
    )
    graph_source = r'''
#[unsafe(no_mangle)]
pub extern "C" fn reaches_libc() -> i32 { helper() }
fn helper() -> i32 { unsafe { libc::getuid() as i32 } }
#[unsafe(no_mangle)]
pub extern "C" fn unresolved_local_path() { crate::missing::call(); }

use crate::imported_helper_module::imported_helper;
use libc::getgid as imported_getgid;
use ::libc::getppid as absolute_imported_getppid;
use libc as host_libc;
use host_libc::getuid as transitively_imported_getuid;
use libc::getpid as macro_let_pid;
use libc::getppid as macro_fn_pid;
macro_rules! discard { ($($tokens:tt)*) => {}; }
#[unsafe(no_mangle)]
pub extern "C" fn reaches_imported_libc() -> i32 { imported_helper() }
#[unsafe(no_mangle)]
pub extern "C" fn reaches_imported_external_libc() -> i32 {
    unsafe { imported_getgid() as i32 }
}
#[unsafe(no_mangle)]
pub extern "C" fn reaches_absolute_imported_external_libc() -> i32 {
    unsafe { absolute_imported_getppid() as i32 }
}
#[unsafe(no_mangle)]
pub extern "C" fn reaches_transitively_imported_external_libc() -> i32 {
    unsafe { transitively_imported_getuid() as i32 }
}
#[unsafe(no_mangle)]
pub extern "C" fn reaches_qualified_alias_external_libc() -> i32 {
    unsafe { host_libc::getpid() as i32 }
}
#[unsafe(no_mangle)]
pub extern "C" fn imported_libc_shadow_is_not_a_call() -> i32 {
    let imported_getgid = || 7;
    imported_getgid()
}
#[unsafe(no_mangle)]
pub extern "C" fn imported_libc_initializer_is_a_call() -> i32 {
    let imported_getgid = unsafe { imported_getgid() as i32 };
    imported_getgid
}
#[unsafe(no_mangle)]
pub extern "C" fn imported_libc_after_scope_is_a_call() -> i32 {
    { let imported_getgid = || 7; let _ = imported_getgid(); }
    unsafe { imported_getgid() as i32 }
}
#[unsafe(no_mangle)]
pub extern "C" fn conditional_import_shadow_is_not_a_call() -> i32 {
    if true
        && let Some(imported_getgid) = Some(|| 7)
    {
        return imported_getgid();
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn discarded_macro_let_does_not_shadow() -> i32 {
    discard ! (let macro_let_pid = || 7;);
    unsafe { macro_let_pid() as i32 }
}

#[unsafe(no_mangle)]
pub extern "C" fn discarded_macro_fn_does_not_shadow() -> i32 {
    discard! { fn macro_fn_pid() {} }
    unsafe { macro_fn_pid() as i32 }
}

#[unsafe(no_mangle)]
pub extern "C" fn known_dispatch_macro_emits_local_function() -> i32 {
    avx2_dispatch! { unsafe fn generated_local() -> i32 => helper; }
    generated_local()
}

#[unsafe(no_mangle)]
pub extern "C" fn lexical_noise_is_not_a_call() -> i32 {
    let _literal = "libc::getuid(";
    /* libc::getppid(); */
    9
}

struct LocalGuard;
impl LocalGuard {
    fn process_id() -> i32 { unsafe { libc::getppid() as i32 } }
}
#[unsafe(no_mangle)]
pub extern "C" fn reaches_associated_libc() -> i32 { LocalGuard::process_id() }

enum LocalValue { Wrapped(i32), Empty }
#[unsafe(no_mangle)]
pub extern "C" fn enum_constructor_is_not_a_call() -> i32 {
    let _value = LocalValue::Wrapped(7);
    7
}

#[derive(Default)]
struct DerivedLeaf;
#[unsafe(no_mangle)]
pub extern "C" fn derived_associated_leaf_is_not_a_call() -> i32 {
    let _value = DerivedLeaf::default();
    8
}

#[unsafe(no_mangle)]
pub extern "C" fn reaches_reexported_libc() -> i32 { native::forwarded_helper() }
'''
    graph_functions = parse_functions(fake_path, graph_source)
    imported_path = root / "scripts/imported_helper_module.rs"
    graph_functions.extend(
        parse_functions(
            imported_path,
            "fn imported_helper() -> i32 { unsafe { libc::getpid() as i32 } }\nfn generated_local() -> i32 { unsafe { libc::getuid() as i32 } }\n",
        )
    )
    native_path = root / "scripts/native_module.rs"
    native_source = "pub use crate::imported_helper_module::imported_helper as forwarded_helper;\n"
    graph = analyze_host_dependencies(
        graph_functions,
        root,
        same_symbol_only=False,
        include_libc_calls=True,
        module_aliases={"native": native_path.stem},
        module_imports={
            fake_path.stem: parse_module_imports(graph_source),
            native_path.stem: parse_module_imports(native_source),
        },
        declared_types_by_module={
            fake_path.stem: parse_declared_types(graph_source),
            imported_path.stem: set(),
            native_path.stem: set(),
        },
        enum_constructors={
            (fake_path.stem, enum_name, variant_name)
            for enum_name, variant_name in parse_enum_constructors(graph_source)
        },
        generated_associated_leaves={
            (fake_path.stem, type_name, function_name)
            for type_name, function_name in parse_generated_associated_leaves(
                graph_source
            )
        },
        conservative_nonlocal_unknown=True,
    )
    require(
        any(
            row["symbol"] == "reaches_libc" and row["host_symbols"] == ["getuid"]
            for row in graph["symbol_rows"]
        ),
        "full dependency graph did not propagate a libc extern call",
    )
    require(
        any(
            row["symbol"] == "reaches_imported_libc"
            and row["host_symbols"] == ["getpid"]
            for row in graph["symbol_rows"]
        ),
        "full dependency graph did not resolve a module-scope function import",
    )
    require(
        any(
            row["symbol"] == "reaches_imported_external_libc"
            and row["host_symbols"] == ["getgid"]
            for row in graph["symbol_rows"]
        ),
        "full dependency graph did not detect an imported libc extern call",
    )
    require(
        any(
            row["symbol"] == "reaches_absolute_imported_external_libc"
            and row["host_symbols"] == ["getppid"]
            for row in graph["symbol_rows"]
        ),
        "full dependency graph did not normalize an absolute libc import",
    )
    require(
        any(
            row["symbol"] == "reaches_transitively_imported_external_libc"
            and row["host_symbols"] == ["getuid"]
            for row in graph["symbol_rows"]
        ),
        "full dependency graph did not resolve a transitive libc import alias",
    )
    require(
        any(
            row["symbol"] == "reaches_qualified_alias_external_libc"
            and row["host_symbols"] == ["getpid"]
            for row in graph["symbol_rows"]
        ),
        "full dependency graph did not resolve a qualified libc crate alias",
    )
    require(
        not any(
            row["symbol"] == "imported_libc_shadow_is_not_a_call"
            for row in graph["symbol_rows"]
        ),
        "host scanner ignored a local binding shadowing a libc import",
    )
    require(
        any(
            row["symbol"] == "imported_libc_initializer_is_a_call"
            and row["host_symbols"] == ["getgid"]
            for row in graph["symbol_rows"]
        ),
        "host scanner applied a let binding inside its own initializer",
    )
    require(
        any(
            row["symbol"] == "imported_libc_after_scope_is_a_call"
            and row["host_symbols"] == ["getgid"]
            for row in graph["symbol_rows"]
        ),
        "host scanner retained a local binding after its scope ended",
    )
    require(
        not any(
            row["symbol"] == "conditional_import_shadow_is_not_a_call"
            for row in graph["symbol_rows"]
        ),
        "host scanner ignored a conditional binding in its body scope",
    )
    require(
        any(
            row["symbol"] == "discarded_macro_let_does_not_shadow"
            and row["host_symbols"] == ["getpid"]
            for row in graph["symbol_rows"]
        ),
        "host scanner treated a discarded macro let-token as a live binding",
    )
    require(
        any(
            row["symbol"] == "discarded_macro_fn_does_not_shadow"
            and row["host_symbols"] == ["getppid"]
            for row in graph["symbol_rows"]
        ),
        "host scanner treated a discarded macro fn-token as a live binding",
    )
    require(
        any(
            row["symbol"] == "known_dispatch_macro_emits_local_function"
            and row["host_symbols"] == ["getuid"]
            for row in graph["symbol_rows"]
        ),
        "host scanner did not propagate a known macro-generated function body",
    )
    require(
        not any(
            row["symbol"] == "lexical_noise_is_not_a_call"
            for row in graph["symbol_rows"]
        ),
        "host scanner treated a string or block comment as executable code",
    )
    require(
        any(
            row["symbol"] == "reaches_associated_libc"
            and row["host_symbols"] == ["getppid"]
            for row in graph["symbol_rows"]
        ),
        "full dependency graph did not resolve a local associated function",
    )
    require(
        any(
            row["symbol"] == "reaches_reexported_libc"
            and row["host_symbols"] == ["getpid"]
            for row in graph["symbol_rows"]
        ),
        "full dependency graph did not follow an explicit module re-export",
    )
    require(
        not any(
            row["caller_exported_symbol"]
            in {
                "enum_constructor_is_not_a_call",
                "derived_associated_leaf_is_not_a_call",
            }
            for row in graph["unknown_calls"]
        ),
        "full dependency graph treated a parsed compiler-generated leaf as a call",
    )
    require(
        any(
            row["caller_exported_symbol"] == "unresolved_local_path"
            and row["reason"] == "unresolved_qualified_target"
            for row in graph["unknown_calls"]
        ),
        "full dependency graph did not fail closed on an unresolved local path",
    )
    structural_source = r'''
#[unsafe(no_mangle)]
pub extern "C" fn brace_noise() -> i32 {
    let _literal = "{";
    // A comment containing unmatched braces must not absorb later functions: }}}
    /* Nor may block-comment braces: { }} */
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn after_brace_noise() -> i32 { 2 }

fn generic_helper<R>(value: R, _array: [u8; 2]) -> R { value }

unsafe extern "C" {
    fn bodyless_foreign_declaration() -> i32;
}

#[unsafe(no_mangle)]
pub extern "C" fn after_foreign_declaration() -> i32 { generic_helper(3, [0; 2]) }
'''
    structural_functions = parse_functions(fake_path, structural_source)
    require(
        [
            function.exported_symbol
            for function in structural_functions
            if function.is_exported_abi
        ]
        == ["brace_noise", "after_brace_noise", "after_foreign_declaration"],
        "function parser counted braces inside comments or literals",
    )
    require(
        any(function.name == "generic_helper" for function in structural_functions),
        "generic function declaration was not parsed",
    )
    require(
        not any(
            function.name == "bodyless_foreign_declaration"
            for function in structural_functions
        )
        and any(
            function.exported_symbol == "after_foreign_declaration"
            for function in structural_functions
        ),
        "bodyless foreign declaration absorbed a later function definition",
    )
    print(f"PASS: cfg/profile scanner self-test ({checks} checks)")
    return 0


def main() -> int:
    root = repo_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--abi-source-dir",
        type=Path,
        default=root / "crates/frankenlibc-abi/src",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=root / "tests/conformance/host_delegation_census.v1.json",
    )
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--self-test-cfg", action="store_true")
    args = parser.parse_args()

    if args.self_test_cfg:
        return run_cfg_self_test(root)

    abi_source_dir = args.abi_source_dir
    if not abi_source_dir.is_absolute():
        abi_source_dir = root / abi_source_dir
    output = args.output
    if not output.is_absolute():
        output = root / output

    payload = build_payload(root, abi_source_dir)
    if args.check:
        if not output.exists():
            print(f"FAIL: missing artifact {output}")
            return 1
        existing = json.loads(output.read_text(encoding="utf-8"))
        if canonical(existing) != canonical(payload):
            print(f"FAIL: {output} is stale; regenerate with:")
            print(f"  scripts/generate_host_delegation_census.py --output {output.relative_to(root)}")
            return 1
        print(
            "PASS: host delegation census current "
            f"(symbols={payload['summary']['host_delegating_symbol_count']}, "
            f"callsites={payload['summary']['host_delegation_callsite_count']})"
        )
        return 0

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"Wrote {output.relative_to(root)} "
        f"(symbols={payload['summary']['host_delegating_symbol_count']}, "
        f"callsites={payload['summary']['host_delegation_callsite_count']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
