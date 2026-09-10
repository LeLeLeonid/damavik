# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Tests for the hand-written YAML subset loader."""

from __future__ import annotations

import pytest

from damavik.miniyaml import YamlError, loads


def test_flat_mapping():
    assert loads("a: 1\nb: two\n") == {"a": 1, "b": "two"}


def test_nested_mapping_and_sequence():
    text = """
selection:
  Image|endswith:
    - '/sh'
    - '/bash'
  CommandLine|contains: 'curl'
"""
    assert loads(text) == {
        "selection": {
            "Image|endswith": ["/sh", "/bash"],
            "CommandLine|contains": "curl",
        }
    }


def test_sequence_of_compact_mappings():
    text = """
- id: a
  level: high
- id: b
  level: low
"""
    assert loads(text) == [{"id": "a", "level": "high"}, {"id": "b", "level": "low"}]


def test_flow_collections():
    assert loads("ports: [80, 443, 8080]\nmeta: {a: 1, b: two}\n") == {
        "ports": [80, 443, 8080],
        "meta": {"a": 1, "b": "two"},
    }


def test_scalar_types():
    text = """
yes_bool: true
no_bool: false
nulls: null
tilde: ~
empty:
integer: -12
float: 1.5e3
hex: 0x1f
text: plain words
single: 'quoted: value'
double: "tab\\there"
"""
    data = loads(text)
    assert data["yes_bool"] is True
    assert data["no_bool"] is False
    assert data["nulls"] is None and data["tilde"] is None and data["empty"] is None
    assert data["integer"] == -12
    assert data["float"] == 1500.0
    assert data["hex"] == 31
    assert data["text"] == "plain words"
    assert data["single"] == "quoted: value"
    assert data["double"] == "tab\there"


def test_comments_and_document_marker():
    text = """---
# leading comment
title: rule  # trailing comment
keep: 'not # a comment'
"""
    assert loads(text) == {"title": "rule", "keep": "not # a comment"}


def test_block_scalars():
    text = "description: >-\n  folded line one\n  and two\nliteral: |\n  kept\n  as is\n"
    data = loads(text)
    assert data["description"] == "folded line one and two"
    assert data["literal"] == "kept\nas is\n"


def test_deeply_nested_rule_shape():
    text = """
title: Example
id: DMK-T-001
status: stable
level: high
description: >-
  multi line
  description
logsource:
  category: process_creation
selection:
  meta.parent_is_sensitive: true
  proc.exe|endswith:
    - bash
    - sh
filter:
  proc.user: root
condition: selection and not filter
correlate:
  group_by: net.dst
  window_s: 60
  min_count: 5
"""
    data = loads(text)
    assert data["condition"] == "selection and not filter"
    assert data["correlate"] == {"group_by": "net.dst", "window_s": 60, "min_count": 5}
    assert data["selection"]["proc.exe|endswith"] == ["bash", "sh"]


@pytest.mark.parametrize(
    "text",
    [
        "a:\n\tb: 1\n",                      # tab indentation
        "a: \"unterminated\n",               # unterminated double quote
        "a: &anchor value\n",                # anchors unsupported
        "a: [1, 2\n",                        # unclosed flow
        "  a: 1\n",                          # indented document root
        "just a bare scalar line\n",         # not a mapping
    ],
)
def test_rejects_outside_subset(text):
    with pytest.raises(YamlError):
        loads(text)


def test_empty_document_is_none():
    assert loads("") is None
    assert loads("# only a comment\n") is None
