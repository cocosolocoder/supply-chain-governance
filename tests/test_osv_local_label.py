"""Business regression tests for OSV matching of PyPI local version labels.

Components may be registered with a PEP 440 local version such as
``1.0+vendor.2``. The label after ``+`` is part of the version identity: it
must never be stripped for matching, and versions must never be ordered as raw
text. These tests guard that through the public catalog behavior — components
are registered, a local OSV source is imported, and the impacts a user would
query are inspected — rather than only checking that version strings parse.

They lock the following rules:

* explicit ``versions`` match by PEP 440 version equality, which ignores the
  local label on the *source* side only when it is absent — a source listing
  just ``1.0`` never reaches ``1.0+vendor.2``, while a source listing
  ``1.0+Vendor_02`` reaches the equivalently written registrations
  ``1.0+vendor.2`` and ``1.0.0+VENDOR.2`` but not ``1.0+vendor.10``;
* two equal-but-differently-spelled registrations stay distinct components:
  impact records and the versions embedded in dependency paths keep the
  registered text, and equivalent vulnerability conditions never merge
  components — the summary's affected-component count counts identities, not
  conditions;
* intervals keep the comparison meaning of the local label: introduced at
  ``1.0+vendor.2`` and fixed at ``1.0+vendor.10`` reaches ``vendor.2`` and
  ``vendor.9`` but not ``vendor.10`` or labelless ``1.0``; a last_affected
  upper bound includes ``vendor.10``; the ``9`` segment compares numerically,
  so it lies between ``2`` and ``10``;
* an explicit version and an interval hitting the same component from the
  same source produce one impact record that keeps both reasons;
* dependency propagation and the risk report explain a hit from the actually
  matched library version — path endpoint and conditions follow the hit
  terminal; an unhit version alone produces no direct impact;
* importing a record whose version is an illegal local version (``1.0+``)
  fails naming the record/entry/field position and leaves the previous source
  content and all query results unchanged.
"""

import unittest

from supply_guard.catalog import Catalog


def osv_record(identifier, package="lib", **affected):
    entry = {"package": {"ecosystem": "PyPI", "name": package}}
    entry.update(affected)
    return {"id": identifier, "affected": [entry]}


def vendor_range(*events):
    return [{"type": "ECOSYSTEM", "events": [dict([event]) for event in events]}]


class LocalLabelExplicitTests(unittest.TestCase):
    """Explicit versions use PEP 440 equality and keep identity verbatim."""

    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def records_by_version(self):
        return {r["component"]["version"]: r for r in self.catalog.impact()}

    def test_source_without_label_does_not_reach_labeled_component(self) -> None:
        # The label is not stripped: 1.0+vendor.2 sorts just above 1.0 and is
        # not equal to it, so a source that lists only 1.0 must not hit it.
        self.catalog.add_component("api", "pypi", "lib", "1.0")
        self.catalog.add_component("api", "pypi", "lib", "1.0+vendor.2")
        self.catalog.import_osv("src", [osv_record("CVE-1", versions=["1.0"])])
        by_version = self.records_by_version()
        self.assertEqual(set(by_version), {"1.0"})
        self.assertEqual(by_version["1.0"]["matched_conditions"], ["==1.0"])

    def test_label_normalization_equivalence_hits_both_spellings(self) -> None:
        # PEP 440 lower-cases/underscore-normalizes and zero-pads release
        # segments, so 1.0+Vendor_02 is the same version as 1.0+vendor.2 and
        # 1.0.0+VENDOR.2; 1.0+vendor.10 is a different version.
        for version in (
            "1.0+vendor.2",
            "1.0.0+VENDOR.2",
            "1.0+vendor.10",
        ):
            self.catalog.add_component("api", "pypi", "lib", version)
        self.catalog.import_osv(
            "src", [osv_record("CVE-1", versions=["1.0+Vendor_02"])]
        )
        by_version = self.records_by_version()
        self.assertEqual(set(by_version), {"1.0+vendor.2", "1.0.0+VENDOR.2"})
        # Both records explain the hit against the normalized condition; the
        # component identity in each record is still the registered text.
        for version in ("1.0+vendor.2", "1.0.0+VENDOR.2"):
            record = by_version[version]
            self.assertTrue(record["direct"])
            self.assertEqual(record["component"]["version"], version)
            self.assertEqual(record["path"], [record["component"]])
            self.assertEqual(record["matched_conditions"], ["==1.0+vendor.2"])

    def test_equivalent_spellings_remain_distinct_component_identities(self) -> None:
        # Equality of the vulnerability condition must never merge the two
        # registrations: directory count, impact records and paths each carry
        # both spellings verbatim.
        self.catalog.add_component("api", "pypi", "lib", "1.0+vendor.2")
        self.catalog.add_component("api", "pypi", "lib", "1.0.0+VENDOR.2")
        self.catalog.import_osv(
            "src", [osv_record("CVE-1", versions=["1.0+Vendor_02"])]
        )
        self.assertEqual(self.catalog.summary().components, 2)
        records = self.records_by_version()
        self.assertEqual(len(records), 2)
        for version in ("1.0+vendor.2", "1.0.0+VENDOR.2"):
            self.assertEqual(records[version]["component"]["version"], version)
            self.assertEqual(
                [node["version"] for node in records[version]["path"]],
                [version],
            )

    def test_labeled_explicit_does_not_reach_labelless_or_higher_label(self) -> None:
        # A labeled explicit condition is narrower than the public release:
        # 1.0 and 1.0+vendor.10 stay out.
        self.catalog.add_component("api", "pypi", "lib", "1.0")
        self.catalog.add_component("api", "pypi", "lib", "1.0+vendor.10")
        self.catalog.import_osv(
            "src", [osv_record("CVE-1", versions=["1.0+vendor.2"])]
        )
        self.assertEqual(self.records_by_version(), {})


class LocalLabelIntervalTests(unittest.TestCase):
    """Intervals preserve the local label's ordering, including numeric runs."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        for version in ("1.0", "1.0+vendor.2", "1.0+vendor.9", "1.0+vendor.10"):
            self.catalog.add_component("api", "pypi", "lib", version)

    def tearDown(self) -> None:
        self.catalog.close()

    def test_fixed_interval_partitions_on_label_and_numeric_segment(self) -> None:
        # introduced 1.0+vendor.2, fixed 1.0+vendor.10: vendor.2 and
        # vendor.9 are in; vendor.10 (the fix) and labelless 1.0 are out.
        # 9 sits between 2 and 10 only under numeric comparison of the
        # segment — a lexical sort would put 9 past 10.
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=vendor_range(
                        ("introduced", "1.0+vendor.2"),
                        ("fixed", "1.0+vendor.10"),
                    ),
                )
            ],
        )
        by_version = {r["component"]["version"]: r for r in self.catalog.impact()}
        self.assertEqual(set(by_version), {"1.0+vendor.2", "1.0+vendor.9"})
        condition = ">=1.0+vendor.2,<1.0+vendor.10"
        for version in ("1.0+vendor.2", "1.0+vendor.9"):
            self.assertEqual(by_version[version]["matched_conditions"], [condition])

    def test_last_affected_upper_bound_includes_the_labeled_endpoint(self) -> None:
        # Same endpoints but last_affected instead of fixed: the vendor.10
        # build itself is still affected.
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=vendor_range(
                        ("introduced", "1.0+vendor.2"),
                        ("last_affected", "1.0+vendor.10"),
                    ),
                )
            ],
        )
        by_version = {r["component"]["version"]: r for r in self.catalog.impact()}
        self.assertEqual(
            set(by_version),
            {"1.0+vendor.2", "1.0+vendor.9", "1.0+vendor.10"},
        )
        condition = ">=1.0+vendor.2,<=1.0+vendor.10"
        for record in by_version.values():
            self.assertEqual(record["matched_conditions"], [condition])

    def test_labelless_version_below_labeled_lower_bound(self) -> None:
        # Labelless 1.0 sorts immediately below every 1.0+label, so it never
        # enters an interval that opens on a labeled introduced version.
        self.catalog.import_osv(
            "src",
            [osv_record(
                "CVE-1",
                ranges=vendor_range(("introduced", "1.0+vendor.2")),
            )],
        )
        by_version = {r["component"]["version"]: r for r in self.catalog.impact()}
        self.assertNotIn("1.0", by_version)
        self.assertIn("1.0+vendor.2", by_version)


class LocalLabelUnionTests(unittest.TestCase):
    """Explicit + interval on one component stay one record with both reasons."""

    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def test_explicit_and_interval_together_yield_one_record(self) -> None:
        self.catalog.add_component("api", "pypi", "lib", "1.0+vendor.2")
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    versions=["1.0+Vendor_02"],
                    ranges=vendor_range(
                        ("introduced", "1.0+vendor.2"),
                        ("fixed", "1.0+vendor.10"),
                    ),
                )
            ],
        )
        records = self.catalog.impact()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["component"]["version"], "1.0+vendor.2")
        self.assertTrue(records[0]["direct"])
        # One record explains both hit bases, in source declaration order.
        self.assertEqual(
            records[0]["matched_conditions"],
            ["==1.0+vendor.2", ">=1.0+vendor.2,<1.0+vendor.10"],
        )


class LocalLabelDependencyTests(unittest.TestCase):
    """Hits participate in dependency analysis with the real library version."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        # The app depends on both equivalent-spelling hit libraries and on
        # the out-of-range 1.0+vendor.10 build of the same package.
        self.catalog.add_component("api", "pypi", "app", "2.0.0")
        self.catalog.add_component("api", "pypi", "lib", "1.0+vendor.2")
        self.catalog.add_component("api", "pypi", "lib", "1.0.0+VENDOR.2")
        self.catalog.add_component("api", "pypi", "lib", "1.0+vendor.10")
        for lib_version in (
            "1.0+vendor.2",
            "1.0.0+VENDOR.2",
            "1.0+vendor.10",
        ):
            self.catalog.add_dependency(
                "api", "pypi", "app", "2.0.0",
                "api", "pypi", "lib", lib_version,
            )

    def tearDown(self) -> None:
        self.catalog.close()

    def import_explicit(self) -> None:
        self.catalog.import_osv(
            "src", [osv_record("CVE-1", versions=["1.0+Vendor_02"])]
        )

    def test_unhit_version_has_no_direct_impact(self) -> None:
        self.import_explicit()
        hit_versions = {r["component"]["version"] for r in self.catalog.impact()}
        self.assertNotIn("1.0+vendor.10", hit_versions)

    def test_indirect_path_ends_at_the_actually_hit_library(self) -> None:
        self.import_explicit()
        records = self.catalog.impact()
        # Two distinct hit libraries (each its own direct record) plus the
        # single app record they propagate to.
        self.assertEqual(len(records), 3)
        direct = [r for r in records if r["direct"]]
        self.assertEqual(
            {r["component"]["version"] for r in direct},
            {"1.0+vendor.2", "1.0.0+VENDOR.2"},
        )
        app = next(r for r in records if r["component"]["name"] == "app")
        self.assertFalse(app["direct"])
        # The path keeps the registered text of the terminal library; it must
        # never be normalized away or rewritten to the other spelling.
        self.assertEqual(
            [(node["name"], node["version"]) for node in app["path"]],
            [("app", "2.0.0"), ("lib", "1.0+vendor.2")],
        )
        # The conditions are the terminal (actually matched) library's.
        self.assertEqual(app["matched_conditions"], ["==1.0+vendor.2"])

    def test_summary_counts_distinct_components_not_conditions(self) -> None:
        self.import_explicit()
        summary = self.catalog.summary()
        # app + two equivalent-spelling hit libraries = 3 affected
        # components; the unhit vendor.10 identity does not count.
        self.assertEqual(summary.components, 4)
        self.assertEqual(summary.affected_components, 3)
        self.assertEqual(summary.vulnerabilities, 1)

    def test_impact_and_risk_report_agree_on_identities_and_bases(self) -> None:
        self.import_explicit()
        impacts = self.catalog.impact()
        report = self.catalog.risk_report(evaluated_at="2026-10-07T00:00:00Z")
        # Same source, matched package, identity and conditions on both sides.
        impact_keys = {
            (
                r["source"],
                r["matched_name"],
                r["component"]["service"],
                r["component"]["ecosystem"],
                r["component"]["name"],
                r["component"]["version"],
                tuple(r["matched_conditions"]),
                tuple((n["name"], n["version"]) for n in r["path"]),
            )
            for r in impacts
        }
        report_keys = {
            (
                e["source"],
                e["matched_name"],
                e["component"]["service"],
                e["component"]["ecosystem"],
                e["component"]["name"],
                e["component"]["version"],
                tuple(e["matched_conditions"]),
                tuple((n["name"], n["version"]) for n in e["path"]),
            )
            for e in report["impacts"]
        }
        self.assertEqual(impact_keys, report_keys)
        self.assertEqual(report["impact_count"], 3)
        # Distinct affected components, not one per version condition.
        self.assertEqual(report["unhandled_component_count"], 3)
        # Every record is attributed to the same OSV source and package.
        self.assertEqual({e["source"] for e in report["impacts"]}, {"src"})
        self.assertEqual({e["matched_name"] for e in report["impacts"]}, {"lib"})


class LocalLabelInvalidImportTests(unittest.TestCase):
    """An illegal local version in a source fails with a precise location."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        self.catalog.import_osv(
            "src", [osv_record("CVE-OK", package="lib", versions=["1.0"])]
        )
        self.catalog.add_component("api", "pypi", "lib", "1.0")
        self.catalog.add_component("api", "pypi", "lib", "1.0+vendor.2")

    def tearDown(self) -> None:
        self.catalog.close()

    def assert_previous_source_still_answers(self) -> None:
        # The last successful import still governs: only labelless 1.0 is hit
        # by CVE-OK; the labeled build and the failed record are absent.
        by_version = {r["component"]["version"]: r for r in self.catalog.impact()}
        self.assertEqual(set(by_version), {"1.0"})
        self.assertEqual(by_version["1.0"]["vulnerability"], "CVE-OK")
        self.assertEqual(self.catalog.summary().vulnerabilities, 1)
        report = self.catalog.risk_report()
        self.assertEqual(
            {e["vulnerability"] for e in report["impacts"]}, {"CVE-OK"}
        )

    def test_illegal_local_in_versions_names_record_and_position(self) -> None:
        with self.assertRaises(ValueError) as context:
            self.catalog.import_osv(
                "src",
                [
                    osv_record(
                        "CVE-BAD", package="lib", versions=["1.0+"]
                    )
                ],
            )
        message = str(context.exception)
        self.assertIn("记录 0", message)
        self.assertIn("affected[0].versions", message)
        self.assertIn("1.0+", message)
        self.assert_previous_source_still_answers()

    def test_illegal_local_in_range_events_names_the_event_field(self) -> None:
        for field in ("introduced", "fixed", "last_affected"):
            with self.subTest(field=field):
                events = (
                    [("introduced", "0"), (field, "1.0+")]
                    if field != "introduced"
                    else [("introduced", "1.0+")]
                )
                with self.assertRaises(ValueError) as context:
                    self.catalog.import_osv(
                        "src",
                        [osv_record("CVE-BAD", ranges=vendor_range(*events))],
                    )
                message = str(context.exception)
                self.assertIn("记录 0", message)
                self.assertIn(f"affected[0].ranges[0].{field}", message)
        self.assert_previous_source_still_answers()

    def test_record_index_reported_for_later_bad_record(self) -> None:
        with self.assertRaises(ValueError) as context:
            self.catalog.import_osv(
                "src",
                [
                    osv_record("CVE-FIRST", package="a", versions=["1.0"]),
                    osv_record("CVE-BAD", package="b", versions=["2.0+"]),
                ],
            )
        message = str(context.exception)
        self.assertIn("记录 1", message)
        self.assertIn("affected[0].versions", message)
        self.assert_previous_source_still_answers()


if __name__ == "__main__":
    unittest.main()
