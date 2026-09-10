# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Version ordering, OSV range matching and pkgwatch state."""

from __future__ import annotations

import os

import pytest

from damavik.osv import MANAGER_TO_ECOSYSTEM, OsvMirror, parse_record
from damavik.pkgwatch import PkgWatch, looks_network_capable, parse_dpkg_status, read_dpkg_status
from damavik.versions import compare, dpkg_compare, generic_compare

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
OSV_DIR = os.path.join(FIXTURES, "osv")


# ------------------------------------------------------------- version maths
@pytest.mark.parametrize(
    "left,right,expected",
    [
        ("1.2.3", "1.2.4", -1),
        ("1.2.4", "1.2.4", 0),
        ("1.10.0", "1.9.0", 1),           # numeric, not lexicographic
        ("1.2.3-1", "1.2.3-2", -1),
        ("1:1.0", "2.0", 1),              # epoch dominates
        ("1.0~rc1", "1.0", -1),           # ~ sorts before everything
        ("1.0+dfsg", "1.0", 1),
        ("2.0", "1:0.1", -1),
    ],
)
def test_dpkg_compare(left, right, expected):
    assert dpkg_compare(left, right) == expected


@pytest.mark.parametrize(
    "left,right,expected",
    [
        ("1.0.0", "1.0.1", -1),
        ("1.0.0", "1.0.0", 0),
        ("1.10.0", "1.9.0", 1),
        ("1.0.0-rc1", "1.0.0", -1),
        ("v2.0", "1.9", 1),
        ("0.9.3", "0.9.10", -1),
    ],
)
def test_generic_compare(left, right, expected):
    assert generic_compare(left, right) == expected


def test_compare_picks_the_ecosystem_algorithm():
    assert compare("1:1.0", "2.0", "Debian:12") == 1
    assert compare("1:1.0", "2.0", "PyPI") == -1


# ---------------------------------------------------------------- OSV mirror
@pytest.fixture(scope="module")
def mirror() -> OsvMirror:
    handle = OsvMirror(OSV_DIR)
    assert handle.load_dir() > 0
    return handle


def test_mirror_indexes_the_fixtures(mirror):
    stats = mirror.stats()
    assert stats["advisories"] >= 3
    assert stats["directory"] == OSV_DIR


def test_fixed_version_is_exclusive(mirror):
    assert mirror.match("Debian:12", "libfoo", "1.2.3")
    assert mirror.match("Debian:12", "libfoo", "1.2.4") == []


def test_introduced_zero_means_all_versions(mirror):
    assert mirror.match("Debian:12", "libfoo", "0.0.1")


def test_last_affected_is_inclusive(mirror):
    assert mirror.match("PyPI", "examplelib", "1.4.2")
    assert mirror.match("PyPI", "examplelib", "1.5.0") == []


def test_explicit_version_list_matches(mirror):
    assert mirror.match("PyPI", "examplelib", "1.2.0")


def test_bare_ecosystem_fallback(mirror):
    """Records published as 'Debian:12' must still match a plain 'Debian' query."""
    assert mirror.match_manager("deb", "libfoo", "1.2.3", distro="")
    assert mirror.match_manager("deb", "libfoo", "1.2.4", distro="") == []


def test_semver_range(mirror):
    assert mirror.match("crates.io", "examplecrate", "0.9.2")
    assert mirror.match("crates.io", "examplecrate", "0.9.3") == []


def test_git_ranges_are_ignored(mirror):
    assert mirror.match("crates.io", "gitonly", "1.0.0") == []


def test_record_without_affected_packages(mirror):
    assert mirror.match("Debian:12", "nonexistent", "1.0") == []


def test_severity_is_extracted(mirror):
    advisory = mirror.match("Debian:12", "libfoo", "1.0")[0]
    assert advisory.severity == "high"
    assert advisory.aliases == ["DSA-9999-1"]


def test_moderate_maps_to_medium(mirror):
    advisory = mirror.match("PyPI", "examplelib", "1.2.0")[0]
    assert advisory.severity == "medium"


def test_missing_directory_is_not_an_error(tmp_path):
    handle = OsvMirror(str(tmp_path / "absent"))
    assert handle.load_dir() == 0
    assert handle.match("Debian:12", "libfoo", "1.0") == []


def test_parse_record_needs_an_id():
    assert parse_record({"affected": []}) == []


def test_load_into_store(store, mirror):
    rows = mirror.load_into_store(store)
    assert rows > 0
    assert store.cves_for("Debian:12", "libfoo")[0]["fixed"] == "1.2.4"


def test_zip_loading(tmp_path):
    import zipfile

    archive = tmp_path / "all.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        for name in os.listdir(OSV_DIR):
            handle.write(os.path.join(OSV_DIR, name), name)
    mirror = OsvMirror(str(tmp_path))
    assert mirror.load_dir() > 0


# ------------------------------------------------------------------ pkgwatch
@pytest.fixture()
def watch(store):
    mirror = OsvMirror(OSV_DIR)
    mirror.load_dir()
    return PkgWatch(store=store, mirror=mirror, host="t", distro="")


def test_dpkg_status_parsing():
    packages = read_dpkg_status(os.path.join(FIXTURES, "dpkg_status.txt"))
    names = {pkg["name"]: pkg["version"] for pkg in packages}
    assert names == {"libfoo": "1.2.3", "netcat-openbsd": "1.226-1",
                     "zlib1g": "1:1.2.13.dfsg-1"}   # 'deinstall' rows are excluded
    libfoo = next(p for p in packages if p["name"] == "libfoo")
    assert "long description" in libfoo["description"]   # continuation lines joined
    assert libfoo["manager"] == "deb"


def test_parse_dpkg_status_handles_empty_input():
    assert parse_dpkg_status("") == []


def test_missing_status_file():
    assert read_dpkg_status("/nonexistent/status") == []


def test_new_package_is_flagged_with_its_cves(watch):
    changes = watch.scan([{"manager": "deb", "name": "libfoo", "version": "1.2.3"}])
    assert changes[0].action == "install"
    assert changes[0].cves == ["CVE-2024-0001"]
    assert changes[0].severity == "high"


def test_known_package_is_only_seen(watch):
    snapshot = [{"manager": "deb", "name": "zlib1g", "version": "1:1.2.13.dfsg-1"}]
    assert watch.scan(snapshot)[0].action == "install"
    assert watch.scan(snapshot)[0].action == "seen"


def test_clean_package_has_no_cves(watch):
    change = watch.scan([{"manager": "deb", "name": "zlib1g", "version": "1:1.2.13"}])[0]
    assert change.cves == []


def test_removal_is_detected(watch):
    snapshot = [{"manager": "deb", "name": "libfoo", "version": "1.2.3"}]
    watch.scan(snapshot)
    removed = watch.diff_removed(snapshot)
    assert removed == []
    removed = watch.diff_removed([])
    assert [change.name for change in removed] == ["libfoo"]
    assert removed[0].action == "remove"


def test_vulnerable_listing(watch):
    watch.scan([{"manager": "deb", "name": "libfoo", "version": "1.2.3"}])
    vulnerable = watch.vulnerable()
    assert len(vulnerable) == 1
    assert vulnerable[0]["cves"] == ["CVE-2024-0001"]
    assert vulnerable[0]["ecosystem"] == MANAGER_TO_ECOSYSTEM["deb"]


def test_package_event_shape(watch):
    change = watch.scan([{"manager": "deb", "name": "libfoo", "version": "1.2.3"}])[0]
    event = change.as_event("2026-09-10T10:00:00.000Z", "t")
    assert event["type"] == "pkg.event"
    assert event["pkg"]["cves"] == ["CVE-2024-0001"]
    assert event["meta"]["action"] == "install"

    from damavik.schema import validate_event

    assert validate_event(event) == []


@pytest.mark.parametrize(
    "name,expected",
    [
        ("netcat-openbsd", True),
        ("libcurl4", True),
        ("openssl", True),
        ("libpng16-16", False),
        ("zlib1g", False),
    ],
)
def test_network_capability_hint(name, expected):
    assert looks_network_capable(name) is expected
