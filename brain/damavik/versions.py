# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Version comparison for package-vulnerability range matching.

Two comparators, chosen by ecosystem:

* :func:`dpkg_compare` implements the Debian algorithm (epoch, ``~`` sorting
  before everything, alternating non-digit/digit chunks).  Used for
  ``Debian:*`` and ``Ubuntu`` because that is how those ecosystems order
  versions - anything else produces wrong CVE ranges.
* :func:`generic_compare` is a SemVer/PEP440-flavoured comparison used for
  everything else (PyPI, crates.io, Go, npm, Maven).

Only *ordering* is needed here; equality of ranges is never inferred.
"""

from __future__ import annotations

import re

__all__ = ["dpkg_compare", "generic_compare", "compare", "order_key"]

_PRERELEASE = {"dev": 0, "alpha": 1, "pre": 2, "beta": 3, "rc": 4}
_PRERELEASE_SPLIT = re.compile(r"[.\-]")


# ------------------------------------------------------------------- Debian
def _dpkg_chunks(text: str) -> list[object]:
    """Split into alternating non-digit / digit chunks, Debian style.

    A straightforward two-mode scan.  An earlier version flipped a mode
    boolean when a mode made no progress, which spun forever on any string
    containing a separator (``1.2.3``) - hence the explicit index advance.
    """
    chunks: list[object] = []
    index, length = 0, len(text)
    while index < length:
        end = index
        if text[index].isdigit():
            while end < length and text[end].isdigit():
                end += 1
            chunks.append(int(text[index:end]))
        else:
            while end < length and not text[end].isdigit():
                end += 1
            chunks.append(text[index:end])
        index = end
    return chunks


def _char_order(char: str) -> int:
    """Debian character ordering: ``~`` < anything < letters < non-letters."""
    if char == "~":
        return -1
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _cmp_nondigit(left: str, right: str) -> int:
    index = 0
    while index < len(left) or index < len(right):
        a = _char_order(left[index]) if index < len(left) else 0
        b = _char_order(right[index]) if index < len(right) else 0
        if a != b:
            return -1 if a < b else 1
        index += 1
    return 0


def _cmp_chunks(left: list[object], right: list[object]) -> int:
    """Compare two chunk lists position by position, type-aware."""
    for index in range(max(len(left), len(right))):
        a = left[index] if index < len(left) else None
        b = right[index] if index < len(right) else None
        if a is None:
            a = 0 if isinstance(b, int) else ""
        if b is None:
            b = 0 if isinstance(a, int) else ""
        if isinstance(a, int) and isinstance(b, int):
            if a != b:
                return -1 if a < b else 1
            continue
        result = _cmp_nondigit(str(a), str(b))
        if result:
            return result
    return 0


def _split_epoch(version: str) -> tuple[int, str, str]:
    """``epoch:upstream-revision`` -> (epoch, upstream, revision)."""
    epoch = 0
    rest = str(version).strip()
    if ":" in rest:
        head, _, rest = rest.partition(":")
        if head.isdigit():
            epoch = int(head)
    revision = "0"
    if "-" in rest:
        rest, _, revision = rest.rpartition("-")
    return epoch, rest, revision


def dpkg_compare(left: str, right: str) -> int:
    """Return -1, 0 or 1 comparing two Debian-style version strings."""
    if left == right:
        return 0
    epoch_a, up_a, rev_a = _split_epoch(left)
    epoch_b, up_b, rev_b = _split_epoch(right)
    if epoch_a != epoch_b:
        return -1 if epoch_a < epoch_b else 1
    for part_a, part_b in ((up_a, up_b), (rev_a, rev_b)):
        result = _cmp_chunks(_dpkg_chunks(part_a), _dpkg_chunks(part_b))
        if result:
            return result
    return 0


# ------------------------------------------------------- SemVer / PEP 440
def _numbered(parts: list[str]) -> list[tuple[int, object]]:
    """Rank-then-value keys, so ints and strings never compare directly."""
    key: list[tuple[int, object]] = []
    for chunk in parts:
        if not chunk:
            continue
        if chunk.isdigit():
            key.append((1, int(chunk)))
        elif chunk.lower() in _PRERELEASE:
            key.append((0, _PRERELEASE[chunk.lower()]))
        else:
            key.append((0, chunk))
    return key


def _generic_parts(version: str) -> tuple[list[tuple[int, object]], int,
                                          list[tuple[int, object]]]:
    """``(release, has_no_prerelease, prerelease)``.

    The middle element is what makes ``1.0.0-rc1 < 1.0.0``: at equal release
    numbers, a version with no pre-release tag sorts after one that has a tag.
    Build metadata (``+foo``) is ignored, as SemVer requires.
    """
    text = str(version).strip().lstrip("vV")
    text = text.split("+", 1)[0]
    release, sep, prerelease = text.partition("-")
    return (
        _numbered(release.split(".")),
        0 if sep else 1,
        _numbered(_PRERELEASE_SPLIT.split(prerelease)) if sep else [],
    )


def _cmp_ranked(left: list[tuple[int, object]], right: list[tuple[int, object]]) -> int:
    """Compare rank/value pairs.  Equal rank implies equal type, so the value
    comparison below can never mix an int with a str."""
    for index in range(max(len(left), len(right))):
        a = left[index] if index < len(left) else None
        b = right[index] if index < len(right) else None
        if a is None or b is None:
            if a is None and b is None:
                continue
            return -1 if a is None else 1          # the shorter version sorts first
        if a[0] != b[0]:
            return -1 if a[0] < b[0] else 1
        if a[1] != b[1]:
            return -1 if a[1] < b[1] else 1        # type: ignore[operator]
    return 0


def generic_compare(left: str, right: str) -> int:
    key_a, key_b = _generic_parts(left), _generic_parts(right)
    result = _cmp_ranked(key_a[0], key_b[0])
    if result:
        return result
    if key_a[1] != key_b[1]:
        return -1 if key_a[1] < key_b[1] else 1
    return _cmp_ranked(key_a[2], key_b[2])


# ------------------------------------------------------------------- public
def compare(left: str, right: str, ecosystem: str = "") -> int:
    """Ecosystem-aware comparison."""
    name = (ecosystem or "").lower()
    if name.startswith(("debian", "ubuntu")):
        return dpkg_compare(left, right)
    return generic_compare(left, right)


def order_key(version: str, ecosystem: str = ""):
    """``functools.cmp_to_key`` wrapper for sorting a version list."""
    import functools

    return functools.cmp_to_key(lambda x, y: compare(x, y, ecosystem))(version)
