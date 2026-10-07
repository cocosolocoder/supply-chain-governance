"""Business regression tests for OSV matching of PyPI development releases.

Users register several development builds of one package (``1.0.dev9``,
``1.0.dev10`` and so on); a local OSV source then decides which builds and
their dependents are affected. These tests lock how those dev builds take
part in version comparison and impact reporting through the public catalog
behavior — components are registered, a local OSV source is imported, and the
impacts a user would query are inspected — rather than only checking that
version strings parse.

They pin the following rules:

* dev releases sort by PEP 440 before both the prereleases (``1.0a1``) and
  the final release (``1.0``) of the same release, and the ``devN`` suffix
  compares numerically (``dev9 < dev10``), never lexically;
* a ``fixed`` interval partitions on the dev number: introduced
  ``1.0.dev2`` / fixed ``1.0.dev10`` reaches ``dev2`` and ``dev9`` but not
  ``dev1``, ``dev10`` or final ``1.0``; a ``last_affected`` upper bound
  includes its dev endpoint while final releases stay outside;
* a fix at the first prerelease must not lump same-release dev builds
  together with it: introduced ``1.0.dev2`` / fixed ``1.0a1`` still reaches
  the dev builds from ``dev2`` up while ``1.0a1`` and ``1.0`` stay out;
* explicit ``versions`` match by PEP 440 equality: a source listing
  ``1.0.dev2`` also reaches a component registered as ``1.0.0.dev2``, but
  not ``dev3`` or the final release — and equivalence never merges the two
  spellings in the directory: impact records, the component count and the
  versions embedded in dependency paths each keep their registered text;
* dependency propagation, summary counts and the risk report follow the
  actually hit dev build — an upper component depending on a hit dev build
  is indirectly affected on a path ending at that build with that endpoint's
  conditions, while depending only on an unhit dev build gives no impact;
* a dev interval that is inverted under PEP 440 (e.g. introduced
  ``1.0.dev10`` fixed ``1.0.dev2``) rejects the import and leaves the
  previous source content in place.
"""

import unittest

from supply_guard.catalog import Catalog


def osv_record(identifier, package="lib", **affected):
    entry = {"package": {"ecosystem": "PyPI", "name": package}}
    entry.update(affected)
    return {"id": identifier, "affected": [entry]}


def dev_range(*events):
    return [{"type": "ECOSYSTEM", "events": [dict([event]) for event in events]}]


DEV_BUILDS = ("1.0.dev1", "1.0.dev2", "1.0.dev9", "1.0.dev10")


class DevIntervalEndpointTests(unittest.TestCase):
    """Dev builds as introduced / fixed / last_affected interval endpoints."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        for version in (*DEV_BUILDS, "1.0a1", "1.0"):
            self.catalog.add_component("api", "pypi", "lib", version)

    def tearDown(self) -> None:
        self.catalog.close()

    def records_by_version(self):
        return {r["component"]["version"]: r for r in self.catalog.impact()}

    def test_fixed_interval_partitions_on_dev_number(self) -> None:
        # introduced 1.0.dev2, fixed 1.0.dev10: dev2 and dev9 are in (9 is
        # compared as a number — a lexical sort would place it past 10);
        # dev1 lies below the lower bound, dev10 is the excluded fix and
        # final 1.0 sorts above every dev build and stays out.
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=dev_range(
                        ("introduced", "1.0.dev2"), ("fixed", "1.0.dev10")
                    ),
                )
            ],
        )
        by_version = self.records_by_version()
        self.assertEqual(set(by_version), {"1.0.dev2", "1.0.dev9"})
        condition = ">=1.0.dev2,<1.0.dev10"
        for version in ("1.0.dev2", "1.0.dev9"):
            record = by_version[version]
            self.assertTrue(record["direct"])
            self.assertEqual(record["matched_conditions"], [condition])
            self.assertEqual(record["path"], [record["component"]])
        for version in ("1.0.dev1", "1.0.dev10", "1.0"):
            self.assertNotIn(version, by_version)

    def test_last_affected_includes_dev_endpoint_but_not_release(self) -> None:
        # Same endpoints with last_affected: the dev10 build itself is still
        # affected; final 1.0 remains above the bound and out of the report.
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=dev_range(
                        ("introduced", "1.0.dev2"),
                        ("last_affected", "1.0.dev10"),
                    ),
                )
            ],
        )
        by_version = self.records_by_version()
        self.assertEqual(
            set(by_version), {"1.0.dev2", "1.0.dev9", "1.0.dev10"}
        )
        condition = ">=1.0.dev2,<=1.0.dev10"
        for record in by_version.values():
            self.assertEqual(record["matched_conditions"], [condition])
        self.assertNotIn("1.0", by_version)

    def test_dev_builds_below_prerelease_fix_remain_affected(self) -> None:
        # Dev builds sort before every prerelease of the same release: with
        # the fix released as 1.0a1, dev2..dev10 are still affected while
        # 1.0a1 itself and final 1.0 are not. Same-release membership must
        # never pull the prerelease/release into the dev interval.
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=dev_range(
                        ("introduced", "1.0.dev2"), ("fixed", "1.0a1")
                    ),
                )
            ],
        )
        by_version = self.records_by_version()
        self.assertEqual(
            set(by_version), {"1.0.dev2", "1.0.dev9", "1.0.dev10"}
        )
        for record in by_version.values():
            self.assertEqual(
                record["matched_conditions"], [">=1.0.dev2,<1.0a1"]
            )
        self.assertNotIn("1.0a1", by_version)
        self.assertNotIn("1.0", by_version)

    def test_open_ended_dev_introduced_includes_dev1_as_below_bound(self) -> None:
        # An open range starting at dev9 has no upper bound: later dev
        # builds, the prerelease and the final release are all reached;
        # only builds strictly below dev9 (dev1, dev2) stay out.
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=dev_range(("introduced", "1.0.dev9")),
                )
            ],
        )
        by_version = self.records_by_version()
        self.assertEqual(
            set(by_version), {"1.0.dev9", "1.0.dev10", "1.0a1", "1.0"}
        )
        self.assertNotIn("1.0.dev1", by_version)
        self.assertNotIn("1.0.dev2", by_version)


class DevExplicitEquivalenceTests(unittest.TestCase):
    """Explicit conditions use PEP 440 equality and keep identity verbatim."""

    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def records_by_version(self):
        return {r["component"]["version"]: r for r in self.catalog.impact()}

    def test_zero_padded_release_segment_hits_equivalent_spelling(self) -> None:
        # A zero release segment is implicit: 1.0.dev2 == 1.0.0.dev2 under
        # PEP 440, so one explicit condition reaches the 1.0.0.dev2
        # registration as well; dev3 and final 1.0 stay out.
        for version in ("1.0.dev2", "1.0.0.dev2", "1.0.dev3", "1.0"):
            self.catalog.add_component("api", "pypi", "lib", version)
        self.catalog.import_osv(
            "src", [osv_record("CVE-1", versions=["1.0.dev2"])]
        )
        by_version = self.records_by_version()
        self.assertEqual(set(by_version), {"1.0.dev2", "1.0.0.dev2"})
        for version, record in by_version.items():
            self.assertTrue(record["direct"])
            self.assertEqual(record["component"]["version"], version)
            self.assertEqual(record["path"], [record["component"]])
            # The condition is rendered in the source-side normalized form;
            # the component identity still carries the registered spelling.
            self.assertEqual(record["matched_conditions"], ["==1.0.dev2"])

    def test_equivalent_spellings_remain_two_components(self) -> None:
        # Equality of the matching condition never merges directory rows:
        # two registrations stay two components with two impact records, and
        # every path keeps the version text each component was registered
        # with.
        self.catalog.add_component("api", "pypi", "lib", "1.0.dev2")
        self.catalog.add_component("api", "pypi", "lib", "1.0.0.dev2")
        self.catalog.import_osv(
            "src", [osv_record("CVE-1", versions=["1.0.dev2"])]
        )
        self.assertEqual(self.catalog.summary().components, 2)
        records = self.records_by_version()
        self.assertEqual(len(records), 2)
        for version in ("1.0.dev2", "1.0.0.dev2"):
            self.assertEqual(records[version]["component"]["version"], version)
            self.assertEqual(
                [node["version"] for node in records[version]["path"]],
                [version],
            )

    def test_source_side_zero_padded_spelling_matches_the_same_pair(self) -> None:
        # The equivalence works in both source spellings: listing
        # 1.0.0.dev2 reaches 1.0.dev2 just as well and still hits neither
        # dev3 nor the release.
        for version in ("1.0.dev2", "1.0.0.dev2", "1.0.dev3", "1.0"):
            self.catalog.add_component("api", "pypi", "lib", version)
        self.catalog.import_osv(
            "src", [osv_record("CVE-1", versions=["1.0.0.dev2"])]
        )
        self.assertEqual(
            set(self.records_by_version()), {"1.0.dev2", "1.0.0.dev2"}
        )


class DevDependencyTests(unittest.TestCase):
    """A hit dev build drives indirect impact with its real endpoint."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        # app depends on the hit dev9; clean-app depends only on the
        # out-of-range dev10 build of the same package.
        self.catalog.add_component("api", "pypi", "app", "2.0.0")
        self.catalog.add_component("api", "pypi", "clean-app", "4.0.0")
        self.catalog.add_component("api", "pypi", "lib", "1.0.dev2")
        self.catalog.add_component("api", "pypi", "lib", "1.0.dev9")
        self.catalog.add_component("api", "pypi", "lib", "1.0.dev10")
        self.catalog.add_dependency(
            "api", "pypi", "app", "2.0.0", "api", "pypi", "lib", "1.0.dev9"
        )
        self.catalog.add_dependency(
            "api", "pypi", "clean-app", "4.0.0",
            "api", "pypi", "lib", "1.0.dev10",
        )
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=dev_range(
                        ("introduced", "1.0.dev2"), ("fixed", "1.0.dev10")
                    ),
                )
            ],
        )

    def tearDown(self) -> None:
        self.catalog.close()

    def test_direct_hits_are_the_in_range_dev_builds(self) -> None:
        direct = {
            r["component"]["version"]
            for r in self.catalog.impact()
            if r["direct"]
        }
        self.assertEqual(direct, {"1.0.dev2", "1.0.dev9"})

    def test_indirect_path_ends_at_the_depended_hit_dev_build(self) -> None:
        records = self.catalog.impact()
        app = next(
            r for r in records
            if r["component"]["name"] == "app"
        )
        self.assertFalse(app["direct"])
        # Path and explanation come from the version app actually depends
        # on: dev9, never normalized to another spelling or build.
        self.assertEqual(
            [(node["name"], node["version"]) for node in app["path"]],
            [("app", "2.0.0"), ("lib", "1.0.dev9")],
        )
        self.assertEqual(
            app["matched_conditions"], [">=1.0.dev2,<1.0.dev10"]
        )

    def test_dependent_of_unhit_dev_build_gets_no_impact(self) -> None:
        names = {r["component"]["name"] for r in self.catalog.impact()}
        self.assertNotIn("clean-app", names)
        # The unhit dev10 build is not directly affected either.
        self.assertNotIn("1.0.dev10", {
            r["component"]["version"] for r in self.catalog.impact()
        })

    def test_summary_counts_direct_and_indirect_components(self) -> None:
        summary = self.catalog.summary()
        # Two in-range dev builds + the app that depends on dev9 = 3
        # affected components; dev10 and clean-app do not count.
        self.assertEqual(summary.components, 5)
        self.assertEqual(summary.affected_components, 3)
        self.assertEqual(summary.vulnerabilities, 1)
        self.assertEqual(summary.highest_severity, "medium")

    def test_risk_report_keeps_source_conditions_path_and_unhandled(self) -> None:
        report = self.catalog.risk_report(evaluated_at="2026-10-07T00:00:00Z")
        impacts = self.catalog.impact()
        # The report answers with exactly the current impact records — same
        # source, matched package, identities, conditions and paths.
        self.assertEqual(report["impact_count"], 3)
        self.assertEqual(report["unhandled_component_count"], 3)
        self.assertEqual(report["highest_severity"], "medium")
        self.assertEqual({e["source"] for e in report["impacts"]}, {"src"})
        self.assertEqual(
            {e["matched_name"] for e in report["impacts"]}, {"lib"}
        )
        for entry in report["impacts"]:
            self.assertFalse(entry["exempted"])
            self.assertIsNone(entry["exemption_request"])
        app = next(
            e for e in report["impacts"] if e["component"]["name"] == "app"
        )
        self.assertFalse(app["direct"])
        self.assertEqual(
            app["matched_conditions"], [">=1.0.dev2,<1.0.dev10"]
        )
        self.assertEqual(
            [(n["name"], n["version"]) for n in app["path"]],
            [("app", "2.0.0"), ("lib", "1.0.dev9")],
        )
        # Record-for-record agreement with impact, ordered or not: the set of
        # (component, vulnerability, source, conditions, path) is identical.
        impact_keys = {
            (
                r["source"], r["vulnerability"],
                r["component"]["service"], r["component"]["ecosystem"],
                r["component"]["name"], r["component"]["version"],
                tuple(r["matched_conditions"]),
                tuple((n["name"], n["version"]) for n in r["path"]),
            )
            for r in impacts
        }
        report_keys = {
            (
                e["source"], e["vulnerability"],
                e["component"]["service"], e["component"]["ecosystem"],
                e["component"]["name"], e["component"]["version"],
                tuple(e["matched_conditions"]),
                tuple((n["name"], n["version"]) for n in e["path"]),
            )
            for e in report["impacts"]
        }
        self.assertEqual(impact_keys, report_keys)


class DevEquivalentSpellingsDependencyTests(unittest.TestCase):
    """Two equivalent-spelling hit dev builds stay two path endpoints."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        self.catalog.add_component("api", "pypi", "app", "2.0.0")
        self.catalog.add_component("api", "pypi", "lib", "1.0.dev2")
        self.catalog.add_component("api", "pypi", "lib", "1.0.0.dev2")
        for lib_version in ("1.0.dev2", "1.0.0.dev2"):
            self.catalog.add_dependency(
                "api", "pypi", "app", "2.0.0",
                "api", "pypi", "lib", lib_version,
            )
        self.catalog.import_osv(
            "src", [osv_record("CVE-1", versions=["1.0.dev2"])]
        )

    def tearDown(self) -> None:
        self.catalog.close()

    def test_two_spellings_keep_two_records_and_verbatim_paths(self) -> None:
        records = self.catalog.impact()
        # Two direct library records plus the one indirect app record;
        # equivalence never collapses the two registrations.
        self.assertEqual(len(records), 3)
        direct_versions = {
            r["component"]["version"] for r in records if r["direct"]
        }
        self.assertEqual(direct_versions, {"1.0.dev2", "1.0.0.dev2"})
        app = next(r for r in records if r["component"]["name"] == "app")
        # The shortest-path tie-break (ecosystem, name, version) selects one
        # terminal deterministically; the path still ends at a genuinely hit
        # dev build registered verbatim.
        self.assertEqual(len(app["path"]), 2)
        self.assertEqual(app["path"][-1]["name"], "lib")
        self.assertIn(app["path"][-1]["version"], direct_versions)
        self.assertEqual(app["matched_conditions"], ["==1.0.dev2"])

    def test_summary_and_report_count_two_identities(self) -> None:
        summary = self.catalog.summary()
        self.assertEqual(summary.components, 3)
        self.assertEqual(summary.affected_components, 3)
        report = self.catalog.risk_report(evaluated_at="2026-10-07T00:00:00Z")
        self.assertEqual(report["impact_count"], 3)
        self.assertEqual(report["unhandled_component_count"], 3)


class DevInvertedIntervalTests(unittest.TestCase):
    """A PEP 440-inverted dev interval rejects the import atomically."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        self.catalog.import_osv(
            "src", [osv_record("CVE-OK", versions=["1.0.dev2"])]
        )

    def tearDown(self) -> None:
        self.catalog.close()

    def assert_previous_source_still_answers(self) -> None:
        self.catalog.add_component("api", "pypi", "lib", "1.0.dev2")
        records = self.catalog.impact()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["vulnerability"], "CVE-OK")
        self.assertEqual(records[0]["matched_conditions"], ["==1.0.dev2"])

    def test_higher_dev_introduced_before_lower_dev_fixed_rejected(self) -> None:
        # dev10 > dev2 numerically; an interval opening at dev10 with a fix
        # at dev2 is inverted and must not import.
        with self.assertRaises(ValueError) as context:
            self.catalog.import_osv(
                "src",
                [
                    osv_record(
                        "CVE-BAD",
                        ranges=dev_range(
                            ("introduced", "1.0.dev10"),
                            ("fixed", "1.0.dev2"),
                        ),
                    )
                ],
            )
        message = str(context.exception)
        self.assertIn("记录 0", message)
        self.assertIn("区间倒置", message)
        self.assertIn("1.0.dev10", message)
        self.assertIn("1.0.dev2", message)
        self.assert_previous_source_still_answers()

    def test_release_introduced_with_dev_last_affected_rejected(self) -> None:
        # Final 1.0 sorts above every dev build, so introduced 1.0 with
        # last_affected 1.0.dev10 is inverted as well.
        with self.assertRaises(ValueError) as context:
            self.catalog.import_osv(
                "src",
                [
                    osv_record(
                        "CVE-BAD",
                        ranges=dev_range(
                            ("introduced", "1.0"),
                            ("last_affected", "1.0.dev10"),
                        ),
                    )
                ],
            )
        self.assertIn("区间倒置", str(context.exception))
        self.assert_previous_source_still_answers()


if __name__ == "__main__":
    unittest.main()
