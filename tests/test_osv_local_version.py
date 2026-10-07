"""Business regression tests for OSV matching of PyPI local version labels.

These tests exercise the public catalog behavior — components are
registered, a local OSV source is imported, and the impacts a user would
query are inspected — rather than only checking that version strings parse.
They guard the PEP 440 local-version rules: the label after ``+`` is part of
the version for both equality and ordering (never stripped, never compared
as one text blob), ``1.0+Vendor_02`` equals ``1.0.0+VENDOR.2`` in conditions
while staying a distinct component identity, numeric label segments order
numerically inside intervals, and a malformed label like ``1.0+`` rejects
the import without touching the previously imported source.
"""

import unittest

from supply_guard.catalog import Catalog


def osv_record(identifier, package="flask", **affected):
    entry = {"package": {"ecosystem": "PyPI", "name": package}}
    entry.update(affected)
    return {"id": identifier, "affected": [entry]}


def local_range(*events):
    return [{"type": "ECOSYSTEM", "events": [dict([event]) for event in events]}]


class LocalExplicitEqualityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def impacted_versions(self):
        return {r["component"]["version"] for r in self.catalog.impact()}

    def test_release_only_condition_does_not_hit_local_version(self) -> None:
        # PEP 440: 1.0 and 1.0+vendor.2 are different versions. A source
        # listing only the bare release must not hit the labeled build —
        # the local label is part of the version, not a suffix to strip.
        self.catalog.add_component("api", "pypi", "flask", "1.0")
        self.catalog.add_component("api", "pypi", "flask", "1.0+vendor.2")
        self.catalog.import_osv("src", [osv_record("CVE-1", versions=["1.0"])])
        self.assertEqual(self.impacted_versions(), {"1.0"})

    def test_local_condition_matches_equivalent_spellings(self) -> None:
        # 1.0+Vendor_02, 1.0+vendor.2 and 1.0.0+VENDOR.2 are equal per
        # PEP 440 (case folded, separators collapsed, zero-padded release
        # segments), so one explicit condition hits both registrations;
        # 1.0+vendor.10 is a different label and stays out.
        self.catalog.add_component("api", "pypi", "flask", "1.0+vendor.2")
        self.catalog.add_component("api", "pypi", "flask", "1.0.0+VENDOR.2")
        self.catalog.add_component("api", "pypi", "flask", "1.0+vendor.10")
        self.catalog.import_osv(
            "src", [osv_record("CVE-1", versions=["1.0+Vendor_02"])]
        )
        records = self.catalog.impact()
        self.assertEqual(
            {r["component"]["version"] for r in records},
            {"1.0+vendor.2", "1.0.0+VENDOR.2"},
        )
        # The hit explanation may use the normalized spelling, but it must
        # name the version condition that actually matched.
        for record in records:
            self.assertEqual(record["matched_conditions"], ["==1.0+vendor.2"])
            self.assertTrue(record["direct"])

    def test_equivalent_spellings_stay_distinct_components(self) -> None:
        # Equality in a version condition never merges component identities:
        # the two registrations remain two components, and every record and
        # path keeps the version text exactly as registered.
        self.catalog.add_component("api", "pypi", "app", "2.0")
        self.catalog.add_component("api", "pypi", "flask", "1.0+vendor.2")
        self.catalog.add_component("api", "pypi", "flask", "1.0.0+VENDOR.2")
        self.catalog.add_dependency(
            "api", "pypi", "app", "2.0",
            "api", "pypi", "flask", "1.0.0+VENDOR.2",
        )
        self.catalog.import_osv(
            "src", [osv_record("CVE-1", versions=["1.0+Vendor_02"])]
        )
        summary = self.catalog.summary()
        self.assertEqual(summary.components, 3)
        # app is indirectly affected plus the two distinct flask builds.
        self.assertEqual(summary.affected_components, 3)

        records = self.catalog.impact()
        flask_records = [
            r for r in records if r["component"]["name"] == "flask"
        ]
        self.assertEqual(len(flask_records), 2)
        for record in flask_records:
            self.assertIn(
                record["component"]["version"],
                {"1.0+vendor.2", "1.0.0+VENDOR.2"},
            )
            # The path of a direct hit is the component itself, spelled as
            # registered — not rewritten to the normalized condition form.
            self.assertEqual(record["path"], [record["component"]])

        indirect = next(r for r in records if r["component"]["name"] == "app")
        self.assertFalse(indirect["direct"])
        self.assertEqual(
            [(n["name"], n["version"]) for n in indirect["path"]],
            [("app", "2.0"), ("flask", "1.0.0+VENDOR.2")],
        )


class LocalIntervalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def impacted_versions(self):
        return {r["component"]["version"] for r in self.catalog.impact()}

    def register_labeled_flasks(self) -> None:
        for version in (
            "1.0",
            "1.0+vendor.2",
            "1.0+vendor.9",
            "1.0+vendor.10",
        ):
            self.catalog.add_component("api", "pypi", "flask", version)

    def test_fixed_interval_keeps_local_label_ordering(self) -> None:
        # Introduced at 1.0+vendor.2, fixed at 1.0+vendor.10: the numeric
        # label segments order numerically, so 9 lies between 2 and 10 (a
        # text comparison would place "10" before "2" and "9"). The bare
        # 1.0 sorts below any labeled build and is excluded, as is the
        # fixed endpoint itself.
        self.register_labeled_flasks()
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=local_range(
                        ("introduced", "1.0+vendor.2"),
                        ("fixed", "1.0+vendor.10"),
                    ),
                )
            ],
        )
        self.assertEqual(
            self.impacted_versions(), {"1.0+vendor.2", "1.0+vendor.9"}
        )

    def test_last_affected_interval_includes_labeled_endpoint(self) -> None:
        # The same upper bound as last_affected includes 1.0+vendor.10;
        # the unlabeled 1.0 still sorts below the introduced bound.
        self.register_labeled_flasks()
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=local_range(
                        ("introduced", "1.0+vendor.2"),
                        ("last_affected", "1.0+vendor.10"),
                    ),
                )
            ],
        )
        self.assertEqual(
            self.impacted_versions(),
            {"1.0+vendor.2", "1.0+vendor.9", "1.0+vendor.10"},
        )

    def test_matched_conditions_keep_the_local_labels(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1.0+vendor.5")
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=local_range(
                        ("introduced", "1.0+vendor.2"),
                        ("fixed", "1.0+vendor.10"),
                    ),
                )
            ],
        )
        records = self.catalog.impact()
        self.assertEqual(len(records), 1)
        # The explanation must quote the labels, not a stripped 1.0.
        self.assertEqual(
            records[0]["matched_conditions"],
            [">=1.0+vendor.2,<1.0+vendor.10"],
        )


class LocalUnionAndDeduplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()
        # 1.0+vendor.5 matches both the explicit version and the range.
        self.catalog.add_component("api", "pypi", "flask", "1.0+vendor.5")
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    versions=["1.0+vendor.5"],
                    ranges=local_range(
                        ("introduced", "1.0+vendor.2"),
                        ("fixed", "1.0+vendor.10"),
                    ),
                )
            ],
        )

    def tearDown(self) -> None:
        self.catalog.close()

    def test_component_matching_both_kinds_yields_one_explained_record(self) -> None:
        # Same source, same vulnerability, same component: the explicit
        # version and the range both match, yet only one impact record is
        # produced and it keeps both hit explanations.
        records = self.catalog.impact()
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["component"]["version"], "1.0+vendor.5")
        self.assertEqual(record["vulnerability"], "CVE-1")
        self.assertEqual(record["source"], "src")
        self.assertEqual(
            record["matched_conditions"],
            ["==1.0+vendor.5", ">=1.0+vendor.2,<1.0+vendor.10"],
        )

    def test_summary_counts_the_component_not_the_conditions(self) -> None:
        # Two matched conditions on one component must not double-count it.
        summary = self.catalog.summary()
        self.assertEqual(summary.components, 1)
        self.assertEqual(summary.affected_components, 1)
        self.assertEqual(summary.vulnerabilities, 1)


class LocalDependencyConsistencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()
        # app depends on the affected flask 1.0+vendor.2; other-app depends
        # only on the fixed flask 1.0+vendor.10 of the same package.
        self.catalog.add_component("api", "pypi", "app", "1.0.0")
        self.catalog.add_component("api", "pypi", "other-app", "1.0.0")
        self.catalog.add_component("api", "pypi", "flask", "1.0+vendor.2")
        self.catalog.add_component("api", "pypi", "flask", "1.0+vendor.10")
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0.0",
            "api", "pypi", "flask", "1.0+vendor.2",
        )
        self.catalog.add_dependency(
            "api", "pypi", "other-app", "1.0.0",
            "api", "pypi", "flask", "1.0+vendor.10",
        )
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=local_range(
                        ("introduced", "1.0+vendor.2"),
                        ("fixed", "1.0+vendor.10"),
                    ),
                )
            ],
        )

    def tearDown(self) -> None:
        self.catalog.close()

    def test_indirect_impact_follows_the_actually_depended_version(self) -> None:
        records = self.catalog.impact()
        by_name = {r["component"]["name"]: r for r in records}
        self.assertEqual(set(by_name), {"app", "flask"})

        direct = by_name["flask"]
        self.assertTrue(direct["direct"])
        self.assertEqual(direct["component"]["version"], "1.0+vendor.2")

        indirect = by_name["app"]
        self.assertFalse(indirect["direct"])
        # The path ends at the version app actually depends on, and the hit
        # conditions are that endpoint's conditions.
        self.assertEqual(
            [(n["name"], n["version"]) for n in indirect["path"]],
            [("app", "1.0.0"), ("flask", "1.0+vendor.2")],
        )
        self.assertEqual(
            indirect["matched_conditions"],
            [">=1.0+vendor.2,<1.0+vendor.10"],
        )

    def test_fixed_dependency_does_not_pull_in_same_named_package(self) -> None:
        records = self.catalog.impact()
        names = {r["component"]["name"] for r in records}
        self.assertNotIn("other-app", names)
        # The fixed 1.0+vendor.10 itself produces no direct record either.
        versions = {
            r["component"]["version"]
            for r in records
            if r["component"]["name"] == "flask"
        }
        self.assertEqual(versions, {"1.0+vendor.2"})

    def test_summary_impact_and_risk_report_answer_the_same_catalog(self) -> None:
        summary = self.catalog.summary()
        self.assertEqual(summary.components, 4)
        self.assertEqual(summary.affected_components, 2)
        self.assertEqual(summary.vulnerabilities, 1)

        impacts = self.catalog.impact()
        self.assertEqual(len(impacts), 2)
        self.assertEqual({r["direct"] for r in impacts}, {True, False})

        report = self.catalog.risk_report(evaluated_at="2026-01-02T03:04:05Z")
        self.assertEqual(report["evaluated_at"], "2026-01-02T03:04:05.000000Z")
        self.assertEqual(report["impact_count"], 2)
        self.assertEqual(report["unhandled_component_count"], 2)
        # Source, component identity and hit explanation agree between the
        # impact query and the risk report.
        report_keys = {
            (
                e["component"]["name"],
                e["component"]["version"],
                e["source"],
                e["direct"],
                tuple(e["matched_conditions"]),
            )
            for e in report["impacts"]
        }
        impact_keys = {
            (
                r["component"]["name"],
                r["component"]["version"],
                r["source"],
                r["direct"],
                tuple(r["matched_conditions"]),
            )
            for r in impacts
        }
        self.assertEqual(report_keys, impact_keys)
        # Component version spellings are kept verbatim everywhere.
        for entry in report["impacts"]:
            if entry["component"]["name"] == "flask":
                self.assertEqual(entry["component"]["version"], "1.0+vendor.2")
                self.assertEqual(
                    entry["matched_conditions"],
                    [">=1.0+vendor.2,<1.0+vendor.10"],
                )


class InvalidLocalVersionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()
        self.catalog.import_osv(
            "src", [osv_record("CVE-OK", versions=["1.0+vendor.2"])]
        )

    def tearDown(self) -> None:
        self.catalog.close()

    def assert_previous_import_retained(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1.0+vendor.2")
        records = self.catalog.impact()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["vulnerability"], "CVE-OK")
        self.assertEqual(records[0]["matched_conditions"], ["==1.0+vendor.2"])

    def test_empty_local_label_in_versions_rejected_and_source_kept(self) -> None:
        # "1.0+" is not a valid PEP 440 version: the local label must not be
        # empty. The import names the record position and fails, leaving the
        # previously imported source and its query results untouched.
        with self.assertRaises(ValueError) as context:
            self.catalog.import_osv(
                "src", [osv_record("CVE-BAD", versions=["1.0+"])]
            )
        message = str(context.exception)
        self.assertIn("记录 0", message)
        self.assertIn("1.0+", message)
        self.assert_previous_import_retained()

    def test_empty_local_label_in_range_rejected_and_source_kept(self) -> None:
        with self.assertRaises(ValueError) as context:
            self.catalog.import_osv(
                "src",
                [
                    osv_record(
                        "CVE-BAD",
                        ranges=local_range(
                            ("introduced", "1.0+"), ("fixed", "2.0")
                        ),
                    )
                ],
            )
        message = str(context.exception)
        self.assertIn("记录 0", message)
        self.assertIn("1.0+", message)
        self.assert_previous_import_retained()

    def test_valid_local_label_accepted(self) -> None:
        count = self.catalog.import_osv(
            "src", [osv_record("CVE-NEW", versions=["1.0+Vendor_02"])]
        )
        self.assertEqual(count, 1)
        self.catalog.add_component("api", "pypi", "flask", "1.0+vendor.2")
        records = self.catalog.impact()
        self.assertEqual(
            {(r["vulnerability"], r["component"]["version"]) for r in records},
            {("CVE-NEW", "1.0+vendor.2")},
        )


if __name__ == "__main__":
    unittest.main()
