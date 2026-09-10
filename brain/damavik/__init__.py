# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Damavik - local-first threat monitor.

The house guardian spirit watches the house.  Damavik watches your machine:
every process execution, every network flow, every DNS query, every installed
package - scored locally, never phoning home.

This package is the "brain".  It is deliberately dependency-free: the Python
standard library only.  Optional integrations (PyYAML, yara-x) are imported
lazily and degrade gracefully when absent.
"""

from __future__ import annotations

__version__ = "0.1.0"

#: Frozen canonical schema version.  Every event and alert carries it.
SCHEMA_VERSION = "1"

__all__ = ["__version__", "SCHEMA_VERSION"]
