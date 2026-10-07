"""Business regression tests for OSV matching of PyPI versions with epochs.

These tests exercise the public catalog behavior — components are
registered, a local OSV source is imported, and the impacts a user would
query are inspected — rather than only checking that version strings parse.
They guard the PEP 440 epoch rules: the epoch before ``!`` dominates
ordering (never string comparison), ``1!2.0`` equals ``1!2.0.0`` in
conditions while staying a distinct component identity, and interval
endpoints keep their introduced/fixed/last_affected inclusion semantics
when epochs and prereleases are involved.
"""

import unittest

from supply_guard.catalog import Catalog


def osv_record(identifier, package="flask", **affected):
    entry = {"package": {"ecosystem": "PyPI", "name": package}}
    entry.update(affected)
    return {"id": identifier, "affected": [entry]}


def epoch_range(*events):
    return [{"type": "ECOSYSTEM", "events": [dict([event]) for event in events]}]


class EpochOrderingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def impacted_versions(self):
        return {r["component"]["version"] for r in self.catalog.impact()}

    def test_epoch_orders_numerically_not_lexically(self) -> None:
        # 1!9.0 < 1!10.0 per PEP 440; a textual comparison would order them
        # the other way and empty the interval.
        for version in ("1!2.0", "1!9.0", "1!10.0"):
            self.catalog.add_component("api", "pypi", "flask", version)
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=epoch_range(("introduced", "1!9.0"), ("fixed", "1!10.0")),
                )
            ],
        )
        self.assertEqual(self.impacted_versions(), {"1!9.0"})

    def test_higher_epoch_beats_any_lower_epoch_release(self) -> None:
        # 2!1.0 > 1!99.0: dropping the epoch would compare 1.0 with 99.0 and
        # pull the old-epoch component into an interval it is far below.
        self.catalog.add_component("api", "pypi", "flask", "1!99.0")
        self.catalog.add_component("api", "pypi", "flask", "2!1.0")
        self.catalog.import_osv(
            "src",
            [osv_record("CVE-1", ranges=epoch_range(("introduced", "2!1.0")))],
        )
        self.assertEqual(self.impacted_versions(), {"2!1.0"})

    def test_lower_epoch_stays_below_upper_bound_of_higher_epoch(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1!99.0")
        self.catalog.add_component("api", "pypi", "flask", "2!1.0")
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=epoch_range(("introduced", "0"), ("fixed", "2!1.0")),
                )
            ],
        )
        self.assertEqual(self.impacted_versions(), {"1!99.0"})

    def test_epoch_equivalent_release_segments_match_explicit_version(self) -> None:
        # 1!2.0 and 1!2.0.0 are equal as PEP 440 versions, so one explicit
        # condition hits both; the catalog still keeps two distinct component
        # identities with their verbatim version spellings.
        self.catalog.add_component("api", "pypi", "flask", "1!2.0")
        self.catalog.add_component("api", "pypi", "flask", "1!2.0.0")
        self.catalog.import_osv("src", [osv_record("CVE-1", versions=["1!2.0.0"])])
        records = self.catalog.impact()
        self.assertEqual(len(records), 2)
        versions = {r["component"]["version"] for r in records}
        self.assertEqual(versions, {"1!2.0", "1!2.0.0"})
        for record in records:
            self.assertEqual(record["matched_conditions"], ["==1!2.0.0"])
            self.assertTrue(record["direct"])
        # Two independent identities remain in the directory.
        self.assertEqual(self.catalog.summary().components, 2)

    def test_epoch_equivalent_release_segments_match_interval_bounds(self) -> None:
        # An interval introduced at 1!2.0.0 also starts at the component
        # registered as 1!2.0, and a fixed 1!3.0.0 excludes 1!3.0.
        self.catalog.add_component("api", "pypi", "flask", "1!2.0")
        self.catalog.add_component("api", "pypi", "flask", "1!3.0")
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=epoch_range(
                        ("introduced", "1!2.0.0"), ("fixed", "1!3.0.0")
                    ),
                )
            ],
        )
        self.assertEqual(self.impacted_versions(), {"1!2.0"})


class EpochBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def impacted_versions(self):
        return {r["component"]["version"] for r in self.catalog.impact()}

    def test_introduced_included_fixed_excluded_with_epoch(self) -> None:
        for version in ("1!1.9", "1!2.0", "1!2.5", "1!3.0"):
            self.catalog.add_component("api", "pypi", "flask", version)
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=epoch_range(("introduced", "1!2.0"), ("fixed", "1!3.0")),
                )
            ],
        )
        self.assertEqual(self.impacted_versions(), {"1!2.0", "1!2.5"})

    def test_last_affected_included_with_epoch(self) -> None:
        for version in ("1!2.0", "1!3.0", "1!3.0.1"):
            self.catalog.add_component("api", "pypi", "flask", version)
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=epoch_range(
                        ("introduced", "1!2.0"), ("last_affected", "1!3.0")
                    ),
                )
            ],
        )
        self.assertEqual(self.impacted_versions(), {"1!2.0", "1!3.0"})

    def test_prerelease_boundary_before_epoch_release(self) -> None:
        # 1!2.0rc1 sorts before 1!2.0: a fix released at 1!2.0 must not drop
        # the still-affected prerelease, and the release itself is excluded.
        self.catalog.add_component("api", "pypi", "flask", "1!2.0rc1")
        self.catalog.add_component("api", "pypi", "flask", "1!2.0")
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=epoch_range(("introduced", "1!1.0"), ("fixed", "1!2.0")),
                )
            ],
        )
        self.assertEqual(self.impacted_versions(), {"1!2.0rc1"})

    def test_prerelease_as_last_affected_endpoint(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1!2.0rc1")
        self.catalog.add_component("api", "pypi", "flask", "1!2.0")
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=epoch_range(
                        ("introduced", "1!1.0"), ("last_affected", "1!2.0rc1")
                    ),
                )
            ],
        )
        self.assertEqual(self.impacted_versions(), {"1!2.0rc1"})

    def test_matched_conditions_keep_the_epoch(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1!2.5")
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=epoch_range(("introduced", "1!2.0"), ("fixed", "1!3.0")),
                )
            ],
        )
        records = self.catalog.impact()
        self.assertEqual(len(records), 1)
        # The explanation must quote the epoch, not a stripped 2.0/3.0.
        self.assertEqual(records[0]["matched_conditions"], [">=1!2.0,<1!3.0"])


class EpochUnionAndDeduplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def test_explicit_versions_and_ranges_form_a_union(self) -> None:
        # 2!1.0 matches only the explicit version, 1!5.5 only the range;
        # 1!6.0 is the excluded fixed endpoint and 2!2.0 lies past both.
        for version in ("1!5.5", "1!6.0", "2!1.0", "2!2.0"):
            self.catalog.add_component("api", "pypi", "flask", version)
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    versions=["2!1.0"],
                    ranges=epoch_range(("introduced", "1!5.0"), ("fixed", "1!6.0")),
                )
            ],
        )
        records = self.catalog.impact()
        by_version = {r["component"]["version"]: r for r in records}
        self.assertEqual(set(by_version), {"1!5.5", "2!1.0"})
        self.assertEqual(by_version["1!5.5"]["matched_conditions"], [">=1!5.0,<1!6.0"])
        self.assertEqual(by_version["2!1.0"]["matched_conditions"], ["==2!1.0"])

    def test_component_matching_both_kinds_yields_one_explained_record(self) -> None:
        # Same source, same vulnerability, same component: the explicit
        # version and the range both match, yet only one impact record is
        # produced and it explains why the component is affected.
        self.catalog.add_component("api", "pypi", "flask", "2!1.0")
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    versions=["2!1.0"],
                    ranges=epoch_range(("introduced", "2!0"), ("fixed", "2!2.0")),
                )
            ],
        )
        records = self.catalog.impact()
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["component"]["version"], "2!1.0")
        self.assertEqual(record["vulnerability"], "CVE-1")
        self.assertEqual(record["source"], "src")
        self.assertEqual(
            record["matched_conditions"], ["==2!1.0", ">=2!0,<2!2.0"]
        )


class EpochDependencyConsistencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()
        # app depends on the affected flask 1!2.0; other-app depends only on
        # the out-of-range flask 1!9.0 of the same package.
        self.catalog.add_component("api", "pypi", "app", "1.0.0")
        self.catalog.add_component("api", "pypi", "other-app", "1.0.0")
        self.catalog.add_component("api", "pypi", "flask", "1!2.0")
        self.catalog.add_component("api", "pypi", "flask", "1!9.0")
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "flask", "1!2.0"
        )
        self.catalog.add_dependency(
            "api", "pypi", "other-app", "1.0.0", "api", "pypi", "flask", "1!9.0"
        )
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=epoch_range(("introduced", "1!2.0"), ("fixed", "1!3.0")),
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
        self.assertEqual(direct["component"]["version"], "1!2.0")

        indirect = by_name["app"]
        self.assertFalse(indirect["direct"])
        # The path ends at the version app actually depends on, and the hit
        # conditions are that endpoint's conditions.
        self.assertEqual(
            [(n["name"], n["version"]) for n in indirect["path"]],
            [("app", "1.0.0"), ("flask", "1!2.0")],
        )
        self.assertEqual(indirect["matched_conditions"], [">=1!2.0,<1!3.0"])

    def test_out_of_range_dependency_does_not_pull_in_same_named_package(self) -> None:
        records = self.catalog.impact()
        names = {r["component"]["name"] for r in records}
        self.assertNotIn("other-app", names)
        # The out-of-range 1!9.0 itself is not reported either.
        versions = {
            r["component"]["version"]
            for r in records
            if r["component"]["name"] == "flask"
        }
        self.assertEqual(versions, {"1!2.0"})

    def test_summary_impact_and_risk_report_answer_the_same_catalog(self) -> None:
        summary = self.catalog.summary()
        self.assertEqual(summary.components, 4)
        self.assertEqual(summary.affected_components, 2)
        self.assertEqual(summary.vulnerabilities, 1)

        impacts = self.catalog.impact()
        self.assertEqual(len(impacts), 2)
        self.assertEqual(
            {r["direct"] for r in impacts}, {True, False}
        )

        report = self.catalog.risk_report(evaluated_at="2026-01-02T03:04:05Z")
        self.assertEqual(report["evaluated_at"], "2026-01-02T03:04:05.000000Z")
        self.assertEqual(report["impact_count"], 2)
        self.assertEqual(report["unhandled_component_count"], 2)
        report_keys = {
            (e["component"]["name"], e["component"]["version"], e["direct"])
            for e in report["impacts"]
        }
        impact_keys = {
            (r["component"]["name"], r["component"]["version"], r["direct"])
            for r in impacts
        }
        self.assertEqual(report_keys, impact_keys)
        # Component version spellings are kept verbatim everywhere.
        for entry in report["impacts"]:
            if entry["component"]["name"] == "flask":
                self.assertEqual(entry["component"]["version"], "1!2.0")
                self.assertEqual(
                    entry["matched_conditions"], [">=1!2.0,<1!3.0"]
                )


class EpochInvertedIntervalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()
        self.catalog.import_osv(
            "src", [osv_record("CVE-OK", versions=["1!2.0"])]
        )

    def tearDown(self) -> None:
        self.catalog.close()

    def assert_previous_import_retained(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1!2.0")
        records = self.catalog.impact()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["vulnerability"], "CVE-OK")

    def test_epoch_inverted_fixed_interval_rejected_and_source_kept(self) -> None:
        # 2!1.0 > 1!99.0 by epoch; only an epoch-aware comparison sees the
        # inversion — dropping the epoch would accept 1.0 < 99.0.
        with self.assertRaises(ValueError) as context:
            self.catalog.import_osv(
                "src",
                [
                    osv_record(
                        "CVE-BAD",
                        ranges=epoch_range(
                            ("introduced", "2!1.0"), ("fixed", "1!99.0")
                        ),
                    )
                ],
            )
        message = str(context.exception)
        self.assertIn("记录 0", message)
        self.assertIn("区间倒置", message)
        self.assertIn("2!1.0", message)
        self.assertIn("1!99.0", message)
        self.assert_previous_import_retained()

    def test_epoch_inverted_last_affected_interval_rejected(self) -> None:
        with self.assertRaises(ValueError) as context:
            self.catalog.import_osv(
                "src",
                [
                    osv_record(
                        "CVE-BAD",
                        ranges=epoch_range(
                            ("introduced", "2!1.0"), ("last_affected", "1!99.0")
                        ),
                    )
                ],
            )
        self.assertIn("区间倒置", str(context.exception))
        self.assert_previous_import_retained()

    def test_epoch_ordered_interval_accepted_despite_textual_inversion(self) -> None:
        # Textually "1!10.0" < "1!9.0", but PEP 440 orders 1!9.0 < 1!10.0:
        # the interval is valid and must import.
        count = self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-NEW",
                    ranges=epoch_range(("introduced", "1!9.0"), ("fixed", "1!10.0")),
                )
            ],
        )
        self.assertEqual(count, 1)
        self.catalog.add_component("api", "pypi", "flask", "1!9.5")
        records = self.catalog.impact()
        self.assertEqual(
            {(r["vulnerability"], r["component"]["version"]) for r in records},
            {("CVE-NEW", "1!9.5")},
        )


if __name__ == "__main__":
    unittest.main()
