"""Business regression tests for OSV matching of PyPI development releases.

These tests exercise the public catalog behavior — components are
registered, a local OSV source is imported, and the impacts a user would
query are inspected — rather than only checking that version strings parse.
They guard the PEP 440 dev-release rules: a dev release sorts before every
prerelease and final release of the same release segment (never grouped
with them), the numeric dev suffix compares by value (``1.0.dev9`` precedes
``1.0.dev10``, not the reverse), interval introduced/fixed/last_affected
endpoints keep their inclusion semantics around dev versions, and
``1.0.dev2`` equals ``1.0.0.dev2`` in conditions while staying two distinct
component identities with their verbatim version spellings.
"""

import unittest

from supply_guard.catalog import Catalog


def osv_record(identifier, package="lib", **affected):
    entry = {"package": {"ecosystem": "PyPI", "name": package}}
    entry.update(affected)
    return {"id": identifier, "affected": [entry]}


def ecosystem_range(*events):
    return [{"type": "ECOSYSTEM", "events": [dict([event]) for event in events]}]


class DevIntervalEndpointTests(unittest.TestCase):
    """Dev versions as introduced/fixed/last_affected interval endpoints."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        for version in (
            "1.0.dev1",
            "1.0.dev2",
            "1.0.dev9",
            "1.0.dev10",
            "1.0",
        ):
            self.catalog.add_component("api", "pypi", "lib", version)

    def tearDown(self) -> None:
        self.catalog.close()

    def impacted_versions(self):
        return {r["component"]["version"] for r in self.catalog.impact()}

    def test_dev_suffix_compares_numerically_between_dev_endpoints(self) -> None:
        # introduced 1.0.dev2, fixed 1.0.dev10: dev2 and dev9 hit; dev1,
        # dev10 and the final 1.0 do not. A lexical suffix comparison would
        # invert dev9/dev10 and misjudge the fixed endpoint.
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=ecosystem_range(
                        ("introduced", "1.0.dev2"), ("fixed", "1.0.dev10")
                    ),
                )
            ],
        )
        self.assertEqual(self.impacted_versions(), {"1.0.dev2", "1.0.dev9"})

    def test_matched_conditions_quote_the_dev_endpoints(self) -> None:
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=ecosystem_range(
                        ("introduced", "1.0.dev2"), ("fixed", "1.0.dev10")
                    ),
                )
            ],
        )
        records = self.catalog.impact()
        self.assertEqual(len(records), 2)
        for record in records:
            self.assertEqual(
                record["matched_conditions"], [">=1.0.dev2,<1.0.dev10"]
            )

    def test_last_affected_dev_endpoint_is_included(self) -> None:
        # last_affected 1.0.dev10 includes that endpoint; the final 1.0 of
        # the same release segment is still out of range.
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=ecosystem_range(
                        ("introduced", "1.0.dev2"), ("last_affected", "1.0.dev10")
                    ),
                )
            ],
        )
        self.assertEqual(
            self.impacted_versions(),
            {"1.0.dev2", "1.0.dev9", "1.0.dev10"},
        )

    def test_dev_introduced_with_prerelease_fixed_boundary(self) -> None:
        # A dev release precedes every prerelease and final of the same
        # release segment: introduced 1.0.dev2 / fixed 1.0a1 still covers
        # dev2..devN while excluding 1.0a1 and 1.0. They must not be swept
        # in merely because they share the 1.0 release segment.
        self.catalog.add_component("api", "pypi", "lib", "1.0a1")
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=ecosystem_range(
                        ("introduced", "1.0.dev2"), ("fixed", "1.0a1")
                    ),
                )
            ],
        )
        self.assertEqual(
            self.impacted_versions(),
            {"1.0.dev2", "1.0.dev9", "1.0.dev10"},
        )

    def test_dev_versions_order_before_the_release_they_precede(self) -> None:
        # A range that only opens at 1.0a1 catches neither dev versions nor
        # the final 1.0 (the final is excluded by the fixed endpoint); dev
        # releases never get treated as >= a prerelease of the same segment.
        self.catalog.add_component("api", "pypi", "lib", "1.0a1")
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=ecosystem_range(
                        ("introduced", "1.0a1"), ("fixed", "1.0")
                    ),
                )
            ],
        )
        self.assertEqual(self.impacted_versions(), {"1.0a1"})


class DevExplicitEquivalenceTests(unittest.TestCase):
    """Explicit conditions compare by PEP 440 equivalence, not by text."""

    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def test_equivalent_spellings_both_match_one_explicit_condition(self) -> None:
        # 1.0.dev2 and 1.0.0.dev2 are the same PEP 440 version: one explicit
        # condition hits both, while dev3 and the final 1.0 do not.
        for version in ("1.0.dev2", "1.0.0.dev2", "1.0.dev3", "1.0"):
            self.catalog.add_component("api", "pypi", "lib", version)
        self.catalog.import_osv(
            "src", [osv_record("CVE-1", versions=["1.0.dev2"])]
        )
        records = self.catalog.impact()
        self.assertEqual(len(records), 2)
        versions = {r["component"]["version"] for r in records}
        self.assertEqual(versions, {"1.0.dev2", "1.0.0.dev2"})
        for record in records:
            self.assertEqual(record["matched_conditions"], ["==1.0.dev2"])
            self.assertTrue(record["direct"])

    def test_equivalent_spellings_remain_distinct_component_identities(self) -> None:
        # Matching by equivalence must never merge directory records: the two
        # registrations stay two components, each keeping its own verbatim
        # version spelling in impact records and in the path.
        self.catalog.add_component("api", "pypi", "lib", "1.0.dev2")
        self.catalog.add_component("api", "pypi", "lib", "1.0.0.dev2")
        self.catalog.import_osv(
            "src", [osv_record("CVE-1", versions=["1.0.dev2"])]
        )
        records = self.catalog.impact()
        self.assertEqual(len(records), 2)
        for record in records:
            spelling = record["component"]["version"]
            self.assertIn(spelling, ("1.0.dev2", "1.0.0.dev2"))
            # The path ends at the actual registered version of that record.
            self.assertEqual(
                [node["version"] for node in record["path"]], [spelling]
            )
        self.assertEqual(self.catalog.summary().components, 2)
        self.assertEqual(self.catalog.summary().affected_components, 2)

    def test_interval_equivalence_covers_equivalent_introduced_spelling(self) -> None:
        # An interval introduced at the equivalent 1.0.0.dev2 likewise starts
        # at a component registered as 1.0.dev2; a fixed 1.0.dev3 excludes
        # dev3 and beyond (numerical dev suffix, not textual).
        for version in ("1.0.dev1", "1.0.dev2", "1.0.dev3", "1.0.0.dev2"):
            self.catalog.add_component("api", "pypi", "lib", version)
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=ecosystem_range(
                        ("introduced", "1.0.0.dev2"), ("fixed", "1.0.dev3")
                    ),
                )
            ],
        )
        self.assertEqual(
            {r["component"]["version"] for r in self.catalog.impact()},
            {"1.0.dev2", "1.0.0.dev2"},
        )


class DevDependencyConsistencyTests(unittest.TestCase):
    """Direct dev hits propagate through dependencies; missers don't."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        self.catalog.add_component("api", "pypi", "lib", "1.0.dev1")
        self.catalog.add_component("api", "pypi", "lib", "1.0.dev9")
        self.catalog.add_component("api", "pypi", "lib", "1.0")
        self.catalog.add_component("api", "pypi", "app-hit", "2.0.0")
        self.catalog.add_component("api", "pypi", "app-miss", "3.0.0")
        self.catalog.add_dependency(
            "api", "pypi", "app-hit", "2.0.0", "api", "pypi", "lib", "1.0.dev9"
        )
        self.catalog.add_dependency(
            "api", "pypi", "app-miss", "3.0.0", "api", "pypi", "lib", "1.0"
        )
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=ecosystem_range(
                        ("introduced", "1.0.dev2"), ("fixed", "1.0.dev10")
                    ),
                )
            ],
        )

    def tearDown(self) -> None:
        self.catalog.close()

    def test_indirect_impact_follows_the_actually_depended_dev_version(self) -> None:
        records = self.catalog.impact()
        by_name = {r["component"]["name"]: r for r in records}
        self.assertEqual(set(by_name), {"app-hit", "lib"})

        direct = by_name["lib"]
        self.assertTrue(direct["direct"])
        self.assertEqual(direct["component"]["version"], "1.0.dev9")

        indirect = by_name["app-hit"]
        self.assertFalse(indirect["direct"])
        # The path ends at the actually hit dev version, and the hit
        # conditions are the conditions of that endpoint.
        self.assertEqual(
            [(n["name"], n["version"]) for n in indirect["path"]],
            [("app-hit", "2.0.0"), ("lib", "1.0.dev9")],
        )
        self.assertEqual(indirect["matched_conditions"], [">=1.0.dev2,<1.0.dev10"])

    def test_out_of_range_dev_and_final_dependencies_are_not_affected(self) -> None:
        names = {r["component"]["name"] for r in self.catalog.impact()}
        self.assertNotIn("app-miss", names)
        versions = {
            r["component"]["version"]
            for r in self.catalog.impact()
            if r["component"]["name"] == "lib"
        }
        self.assertEqual(versions, {"1.0.dev9"})

    def test_summary_impact_and_risk_report_answer_the_same_catalog(self) -> None:
        summary = self.catalog.summary()
        self.assertEqual(summary.components, 5)
        self.assertEqual(summary.affected_components, 2)
        self.assertEqual(summary.vulnerabilities, 1)
        self.assertEqual(summary.highest_severity, "medium")

        impacts = self.catalog.impact()
        self.assertEqual(len(impacts), 2)
        self.assertEqual({r["direct"] for r in impacts}, {True, False})

        # Without an exemption the dev-version impacts are unhandled risk, and
        # the risk report preserves source, version conditions and paths.
        report = self.catalog.risk_report(evaluated_at="2026-01-02T03:04:05Z")
        self.assertEqual(report["evaluated_at"], "2026-01-02T03:04:05.000000Z")
        self.assertEqual(report["impact_count"], 2)
        self.assertEqual(report["unhandled_component_count"], 2)
        self.assertEqual(report["highest_severity"], "medium")
        report_keys = {
            (e["component"]["name"], e["component"]["version"], e["direct"])
            for e in report["impacts"]
        }
        impact_keys = {
            (r["component"]["name"], r["component"]["version"], r["direct"])
            for r in impacts
        }
        self.assertEqual(report_keys, impact_keys)
        for entry in report["impacts"]:
            self.assertEqual(entry["source"], "src")
            self.assertEqual(entry["vulnerability"], "CVE-1")
            self.assertEqual(entry["matched_name"], "lib")
            self.assertFalse(entry["exempted"])
            if entry["component"]["name"] == "lib":
                self.assertEqual(entry["component"]["version"], "1.0.dev9")
                self.assertEqual(
                    entry["matched_conditions"], [">=1.0.dev2,<1.0.dev10"]
                )
                self.assertEqual(
                    [n["version"] for n in entry["path"]], ["1.0.dev9"]
                )
            else:
                self.assertEqual(
                    [(n["name"], n["version"]) for n in entry["path"]],
                    [("app-hit", "2.0.0"), ("lib", "1.0.dev9")],
                )


if __name__ == "__main__":
    unittest.main()
