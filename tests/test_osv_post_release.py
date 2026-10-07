"""Business regression tests for OSV matching of PyPI post-releases.

Users register the final release and several ``.postN`` rebuilds of one
package (``1.0``, ``1.0.post1``, ``1.0.post2``, ``1.0.post10`` and the
development build of a post-release); a local OSV source then decides which
post-releases and their dependents are affected. These tests lock how those
post-releases take part in version comparison and impact reporting through
the public catalog behavior — components are registered, a local OSV source
is imported, and the impacts a user would query are inspected — rather than
only checking that version strings parse.

They pin the following rules:

* post-releases sort immediately above the final release they rebuild and
  their ``postN`` suffix compares numerically (``post2 < post10``), never
  lexically;
* a ``fixed`` interval: introduced ``1.0.post1`` / fixed ``1.0.post2``
  reaches ``1.0.post1`` itself but not final ``1.0`` (which sorts below the
  lower bound), not the excluded fix ``1.0.post2``, and not later posts; the
  development build of the fix ``1.0.post2.dev1`` sorts between post1 and
  post2 and is still in range; introduced itself is affected while fixed
  itself is not;
* a ``last_affected`` upper bound includes its post endpoint (the named
  version is still affected), while later ``.post`` versions stay out;
* explicit ``versions`` match by PEP 440 equality: a source listing
  ``1.0.post1`` also reaches a component registered as ``1.0-1`` (the
  ``N.M-1`` post-release shorthand normalizes to ``N.M.post1``), but not
  ``1.0`` or ``1.0.post2`` — and equivalence never merges the two spellings
  in the directory: impact records, the component count and the versions
  embedded in dependency paths each keep their registered text;
* when one component satisfies both an explicit version and an interval from
  the same vulnerability, source and matched package, one impact record is
  produced that explains the affected basis (both conditions);
* dependency propagation, summary counts and the risk report follow the
  actually hit post-release — an upper component depending on a hit
  post-release is indirectly affected on a path ending at that release with
  that endpoint's conditions, while depending only on the fixed/unhit
  post-release is not reported merely because another build of the same
  package is affected;
* a post-release interval that is inverted under PEP 440 (introduced
  ``1.0.post10`` fixed ``1.0.post2``) rejects the import with a message
  naming the record and the range, and leaves the previous source content
  and its impacts exactly as the last successful import established them.
"""

import unittest

from supply_guard.catalog import Catalog


def osv_record(identifier, package="lib", **affected):
    entry = {"package": {"ecosystem": "PyPI", "name": package}}
    entry.update(affected)
    return {"id": identifier, "affected": [entry]}


def post_range(*events):
    return [{"type": "ECOSYSTEM", "events": [dict([event]) for event in events]}]


POST_VERSIONS = (
    "1.0",
    "1.0.post1",
    "1.0.post2.dev1",
    "1.0.post2",
    "1.0.post9",
    "1.0.post10",
)


class PostIntervalEndpointTests(unittest.TestCase):
    """Post-releases as introduced / fixed / last_affected interval endpoints."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        for version in POST_VERSIONS:
            self.catalog.add_component("api", "pypi", "lib", version)

    def tearDown(self) -> None:
        self.catalog.close()

    def records_by_version(self):
        return {r["component"]["version"]: r for r in self.catalog.impact()}

    def test_fixed_interval_introduced_in_fixed_out_and_numeric_post(self) -> None:
        # introduced 1.0.post1, fixed 1.0.post2: post1 (the introduced
        # version itself) is affected; final 1.0 sorts immediately below the
        # first post-release and stays out; post2 is the excluded fix. The
        # dev build of the fix (post2.dev1) sorts between post1 and post2 and
        # is still in range. Registered post9/post10 also verify ordering:
        # post2 sorts before post10 only under numeric comparison.
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=post_range(
                        ("introduced", "1.0.post1"), ("fixed", "1.0.post2")
                    ),
                )
            ],
        )
        by_version = self.records_by_version()
        self.assertEqual(set(by_version), {"1.0.post1", "1.0.post2.dev1"})
        condition = ">=1.0.post1,<1.0.post2"
        for version in ("1.0.post1", "1.0.post2.dev1"):
            record = by_version[version]
            self.assertTrue(record["direct"])
            self.assertEqual(record["matched_conditions"], [condition])
            self.assertEqual(record["path"], [record["component"]])
        for version in ("1.0", "1.0.post2", "1.0.post9", "1.0.post10"):
            self.assertNotIn(version, by_version)

    def test_last_affected_includes_endpoint_but_not_later_posts(self) -> None:
        # With last_affected at 1.0.post2 the named version itself is still
        # affected, and the dev build below it stays in; later post-releases
        # (post9/post10) sort above the bound and remain out of the report.
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=post_range(
                        ("introduced", "1.0.post1"),
                        ("last_affected", "1.0.post2"),
                    ),
                )
            ],
        )
        by_version = self.records_by_version()
        self.assertEqual(
            set(by_version),
            {"1.0.post1", "1.0.post2.dev1", "1.0.post2"},
        )
        condition = ">=1.0.post1,<=1.0.post2"
        for record in by_version.values():
            self.assertEqual(record["matched_conditions"], [condition])
        for version in ("1.0", "1.0.post9", "1.0.post10"):
            self.assertNotIn(version, by_version)

    def test_numeric_post_order_puts_post9_between_post2_and_post10(self) -> None:
        # postN compares numerically, so post9 sits between post2 and
        # post10 — a lexical sort would place "post10" before "post2" and
        # empty the interval. The introduced post2 itself is affected;
        # post2.dev1 sorts just below post2 and stays out, as does the
        # excluded fix post10.
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=post_range(
                        ("introduced", "1.0.post2"), ("fixed", "1.0.post10")
                    ),
                )
            ],
        )
        by_version = self.records_by_version()
        self.assertEqual(set(by_version), {"1.0.post2", "1.0.post9"})
        condition = ">=1.0.post2,<1.0.post10"
        for record in by_version.values():
            self.assertEqual(record["matched_conditions"], [condition])
        for version in ("1.0", "1.0.post1", "1.0.post2.dev1", "1.0.post10"):
            self.assertNotIn(version, by_version)

    def test_open_ended_post_introduced_leaves_final_release_below_bound(self) -> None:
        # An open range starting at post1 reaches every post-release and the
        # post fix's dev build, but final 1.0 sorts below the first
        # post-release and never enters.
        self.catalog.import_osv(
            "src",
            [osv_record("CVE-1", ranges=post_range(("introduced", "1.0.post1")))]
        )
        by_version = self.records_by_version()
        self.assertEqual(
            set(by_version),
            {"1.0.post1", "1.0.post2.dev1", "1.0.post2",
             "1.0.post9", "1.0.post10"},
        )
        self.assertNotIn("1.0", by_version)

    def test_fixed_at_first_post_excludes_final_release(self) -> None:
        # A range open since "0" closed by fixed 1.0.post1: final 1.0 is
        # below the fix and still affected, while post1 itself is the excluded
        # fix and every later post-release stays out.
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=post_range(
                        ("introduced", "0"), ("fixed", "1.0.post1")
                    ),
                )
            ],
        )
        by_version = self.records_by_version()
        self.assertEqual(set(by_version), {"1.0"})
        self.assertEqual(
            by_version["1.0"]["matched_conditions"], ["<1.0.post1"]
        )


class PostExplicitEquivalenceTests(unittest.TestCase):
    """Explicit conditions use PEP 440 equality and keep identity verbatim."""

    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def records_by_version(self):
        return {r["component"]["version"]: r for r in self.catalog.impact()}

    def test_dash_shorthand_hits_equivalent_dot_post_spelling(self) -> None:
        # PEP 440's 1.0-1 post-release shorthand denotes the same version as
        # 1.0.post1: a source listing 1.0.post1 reaches the 1.0-1
        # registration, and the condition renders in the source-side
        # normalized form; the component identity keeps 1.0-1 verbatim.
        for version in ("1.0-1", "1.0", "1.0.post2"):
            self.catalog.add_component("api", "pypi", "lib", version)
        self.catalog.import_osv(
            "src", [osv_record("CVE-1", versions=["1.0.post1"])]
        )
        by_version = self.records_by_version()
        self.assertEqual(set(by_version), {"1.0-1"})
        record = by_version["1.0-1"]
        self.assertTrue(record["direct"])
        self.assertEqual(record["component"]["version"], "1.0-1")
        self.assertEqual(record["path"], [record["component"]])
        self.assertEqual(record["matched_conditions"], ["==1.0.post1"])

    def test_dash_shorthand_source_side_matches_too(self) -> None:
        # The equivalence works from either spelling: a source that lists
        # 1.0-1 reaches a component registered 1.0.post1 just as well, and
        # still hits neither final 1.0 nor post2.
        for version in ("1.0.post1", "1.0", "1.0.post2"):
            self.catalog.add_component("api", "pypi", "lib", version)
        self.catalog.import_osv(
            "src", [osv_record("CVE-1", versions=["1.0-1"])]
        )
        by_version = self.records_by_version()
        self.assertEqual(set(by_version), {"1.0.post1"})
        self.assertEqual(
            by_version["1.0.post1"]["matched_conditions"], ["==1.0.post1"]
        )

    def test_equivalent_spellings_remain_two_components(self) -> None:
        # Equality of the matching condition never merges directory rows:
        # registrations 1.0-1 and 1.0.post1 stay two components with two
        # impact records, and every path keeps the version text each
        # component was registered with.
        self.catalog.add_component("api", "pypi", "lib", "1.0-1")
        self.catalog.add_component("api", "pypi", "lib", "1.0.post1")
        self.catalog.import_osv(
            "src", [osv_record("CVE-1", versions=["1.0.post1"])]
        )
        self.assertEqual(self.catalog.summary().components, 2)
        records = self.records_by_version()
        self.assertEqual(len(records), 2)
        for version in ("1.0-1", "1.0.post1"):
            self.assertEqual(records[version]["component"]["version"], version)
            self.assertEqual(
                [node["version"] for node in records[version]["path"]],
                [version],
            )

    def test_final_release_and_next_post_are_not_equal(self) -> None:
        # 1.0 is the release the post-releases rebuild, not an equal version;
        # post2 is the next post-release. Neither is hit by ==post1.
        for version in ("1.0", "1.0.post2"):
            self.catalog.add_component("api", "pypi", "lib", version)
        self.catalog.import_osv(
            "src", [osv_record("CVE-1", versions=["1.0.post1"])]
        )
        self.assertEqual(self.records_by_version(), {})


class PostExplicitAndIntervalTests(unittest.TestCase):
    """One component matching explicit + interval keeps one explained record."""

    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def test_explicit_and_interval_together_yield_one_record(self) -> None:
        # post1 satisfies both the explicit versions list and the interval;
        # same vulnerability, source and matched package must still produce
        # exactly one impact record, explaining both bases in declaration
        # order.
        self.catalog.add_component("api", "pypi", "lib", "1.0.post1")
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    versions=["1.0.post1"],
                    ranges=post_range(
                        ("introduced", "1.0.post1"), ("fixed", "1.0.post2")
                    ),
                )
            ],
        )
        records = self.catalog.impact()
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["component"]["version"], "1.0.post1")
        self.assertTrue(record["direct"])
        self.assertEqual(record["vulnerability"], "CVE-1")
        self.assertEqual(record["source"], "src")
        self.assertEqual(
            record["matched_conditions"],
            ["==1.0.post1", ">=1.0.post1,<1.0.post2"],
        )


class PostDependencyTests(unittest.TestCase):
    """A hit post-release drives indirect impact with its real endpoint."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        # app depends on the hit post1; clean-app depends only on the
        # out-of-range/fixed post2 build of the same package.
        self.catalog.add_component("api", "pypi", "app", "2.0.0")
        self.catalog.add_component("api", "pypi", "clean-app", "4.0.0")
        self.catalog.add_component("api", "pypi", "lib", "1.0")
        self.catalog.add_component("api", "pypi", "lib", "1.0.post1")
        self.catalog.add_component("api", "pypi", "lib", "1.0.post2")
        self.catalog.add_dependency(
            "api", "pypi", "app", "2.0.0", "api", "pypi", "lib", "1.0.post1"
        )
        self.catalog.add_dependency(
            "api", "pypi", "clean-app", "4.0.0",
            "api", "pypi", "lib", "1.0.post2",
        )
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=post_range(
                        ("introduced", "1.0.post1"), ("fixed", "1.0.post2")
                    ),
                )
            ],
        )

    def tearDown(self) -> None:
        self.catalog.close()

    def records(self):
        return self.catalog.impact()

    def test_direct_hits_are_only_the_in_range_post(self) -> None:
        direct = {
            r["component"]["version"]
            for r in self.records()
            if r["direct"]
        }
        self.assertEqual(direct, {"1.0.post1"})

    def test_indirect_path_ends_at_the_depended_hit_post(self) -> None:
        app = next(r for r in self.records() if r["component"]["name"] == "app")
        self.assertFalse(app["direct"])
        # Path and explanation come from the version app actually depends
        # on: post1, never the fixed post2 or another same-name build.
        self.assertEqual(
            [(node["name"], node["version"]) for node in app["path"]],
            [("app", "2.0.0"), ("lib", "1.0.post1")],
        )
        self.assertEqual(
            app["matched_conditions"], [">=1.0.post1,<1.0.post2"]
        )

    def test_dependent_of_fixed_version_gets_no_impact(self) -> None:
        # clean-app must not be flagged just because the same package name
        # has an affected post1 build: the dependency is on post2, which is
        # already fixed and is not directly affected either.
        names = {r["component"]["name"] for r in self.records()}
        self.assertNotIn("clean-app", names)
        self.assertEqual(
            {r["component"]["version"] for r in self.records()
             if r["component"]["name"] == "lib"},
            {"1.0.post1"},
        )

    def test_summary_counts_direct_and_indirect_components(self) -> None:
        summary = self.catalog.summary()
        # The in-range post1 plus the app that depends on it = 2 affected
        # components; final 1.0, fixed post2 and clean-app do not count.
        self.assertEqual(summary.components, 5)
        self.assertEqual(summary.affected_components, 2)
        self.assertEqual(summary.vulnerabilities, 1)
        self.assertEqual(summary.highest_severity, "medium")

    def test_impact_and_risk_report_agree(self) -> None:
        impacts = self.records()
        report = self.catalog.risk_report(evaluated_at="2026-10-07T00:00:00Z")
        self.assertEqual(report["impact_count"], 2)
        self.assertEqual(report["unhandled_component_count"], 2)
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
            app["matched_conditions"], [">=1.0.post1,<1.0.post2"]
        )
        self.assertEqual(
            [(n["name"], n["version"]) for n in app["path"]],
            [("app", "2.0.0"), ("lib", "1.0.post1")],
        )
        # Record-for-record agreement: same (source, vuln, identity,
        # direct flag, conditions, path) on both sides.
        impact_keys = {
            (
                r["source"], r["vulnerability"],
                r["component"]["service"], r["component"]["ecosystem"],
                r["component"]["name"], r["component"]["version"],
                r["direct"],
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
                e["direct"],
                tuple(e["matched_conditions"]),
                tuple((n["name"], n["version"]) for n in e["path"]),
            )
            for e in report["impacts"]
        }
        self.assertEqual(impact_keys, report_keys)


class PostEquivalentSpellingsCountsTests(unittest.TestCase):
    """Counts are by component identity; equivalent spellings count apart."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        self.catalog.add_component("api", "pypi", "app", "2.0.0")
        # Two equal-but-differently-spelled post1 registrations, each with
        # both an explicit and an interval reason (two conditions each),
        # plus one unhit post2.
        self.catalog.add_component("api", "pypi", "lib", "1.0-1")
        self.catalog.add_component("api", "pypi", "lib", "1.0.post1")
        self.catalog.add_component("api", "pypi", "lib", "1.0.post2")
        for lib_version in ("1.0-1", "1.0.post1"):
            self.catalog.add_dependency(
                "api", "pypi", "app", "2.0.0",
                "api", "pypi", "lib", lib_version,
            )
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    versions=["1.0.post1"],
                    ranges=post_range(
                        ("introduced", "1.0.post1"), ("fixed", "1.0.post2")
                    ),
                )
            ],
        )

    def tearDown(self) -> None:
        self.catalog.close()

    def test_two_spellings_keep_two_direct_records_with_two_reasons(self) -> None:
        records = self.catalog.impact()
        # Two direct library records (one per spelling, each carrying both
        # hit conditions) plus the one indirect app record.
        direct = [r for r in records if r["direct"]]
        self.assertEqual(
            {r["component"]["version"] for r in direct},
            {"1.0-1", "1.0.post1"},
        )
        for record in direct:
            self.assertEqual(
                record["matched_conditions"],
                ["==1.0.post1", ">=1.0.post1,<1.0.post2"],
            )
            self.assertEqual(record["path"], [record["component"]])
        self.assertEqual(len(records), 3)
        app = next(r for r in records if r["component"]["name"] == "app")
        self.assertFalse(app["direct"])
        self.assertEqual(len(app["path"]), 2)
        self.assertEqual(app["path"][-1]["name"], "lib")
        self.assertIn(app["path"][-1]["version"], {"1.0-1", "1.0.post1"})

    def test_summary_and_report_count_identities_not_conditions(self) -> None:
        # No exemptions: the summary affected count and the risk report's
        # unhandled count both count distinct components — app plus the two
        # equivalent-spelling post1 identities = 3, even though every direct
        # record carries two matched conditions.
        summary = self.catalog.summary()
        self.assertEqual(summary.components, 4)
        self.assertEqual(summary.affected_components, 3)
        report = self.catalog.risk_report(evaluated_at="2026-10-07T00:00:00Z")
        self.assertEqual(report["impact_count"], 3)
        self.assertEqual(report["unhandled_component_count"], 3)
        # The two spellings survive verbatim in the report as well.
        report_versions = {
            (e["component"]["name"], e["component"]["version"])
            for e in report["impacts"]
        }
        self.assertIn(("lib", "1.0-1"), report_versions)
        self.assertIn(("lib", "1.0.post1"), report_versions)


class PostInvertedIntervalTests(unittest.TestCase):
    """A PEP 440-inverted post interval rejects the import atomically."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        # A source that already successfully provides a post1 vulnerability.
        self.catalog.import_osv(
            "src", [osv_record("CVE-OK", versions=["1.0.post1"])]
        )
        self.catalog.add_component("api", "pypi", "lib", "1.0.post1")

    def tearDown(self) -> None:
        self.catalog.close()

    def assert_previous_source_still_answers(self) -> None:
        # The last successful import still governs: CVE-OK hits post1, and
        # neither the rejected CVE-BAD nor any extra condition appears.
        records = self.catalog.impact()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["vulnerability"], "CVE-OK")
        self.assertEqual(records[0]["matched_conditions"], ["==1.0.post1"])
        self.assertEqual(self.catalog.summary().vulnerabilities, 1)
        report = self.catalog.risk_report(evaluated_at="2026-10-07T00:00:00Z")
        self.assertEqual(
            [e["vulnerability"] for e in report["impacts"]], ["CVE-OK"]
        )

    def test_higher_post_introduced_before_lower_post_fixed_rejected(self) -> None:
        # post10 > post2 numerically (a lexical sort would invert them); an
        # interval opening at post10 with a fix at post2 is inverted and must
        # not import. The error names the record and the offending range.
        with self.assertRaises(ValueError) as context:
            self.catalog.import_osv(
                "src",
                [
                    osv_record(
                        "CVE-BAD",
                        ranges=post_range(
                            ("introduced", "1.0.post10"),
                            ("fixed", "1.0.post2"),
                        ),
                    )
                ],
            )
        message = str(context.exception)
        self.assertIn("记录 0", message)
        self.assertIn("affected[0].ranges[0]", message)
        self.assertIn("区间倒置", message)
        self.assertIn("1.0.post10", message)
        self.assertIn("1.0.post2", message)
        self.assert_previous_source_still_answers()

    def test_post_introduced_with_final_release_last_affected_rejected(self) -> None:
        # Final 1.0 sorts below every post-release, so introduced 1.0.post1
        # with last_affected 1.0 is inverted as well; the prior source
        # content is retained.
        with self.assertRaises(ValueError) as context:
            self.catalog.import_osv(
                "src",
                [
                    osv_record(
                        "CVE-BAD",
                        ranges=post_range(
                            ("introduced", "1.0.post1"),
                            ("last_affected", "1.0"),
                        ),
                    )
                ],
            )
        self.assertIn("区间倒置", str(context.exception))
        self.assert_previous_source_still_answers()


if __name__ == "__main__":
    unittest.main()
