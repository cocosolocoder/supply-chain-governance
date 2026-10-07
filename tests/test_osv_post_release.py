"""Business regression tests for OSV matching of PyPI post-releases.

After a final release ships, projects may publish post-releases such as
``1.0.post1`` (PEP 440 also spells that ``1.0-1``), ``1.0.post2`` and
``1.0.post10``. A local OSV source then decides which of those posts and
their dependents are affected. These tests lock how post-releases take part
in version comparison and impact reporting through the public catalog
behavior — components are registered, a local OSV source is imported, and the
impacts a user would query are inspected — rather than only checking that
version strings parse.

They pin the following rules:

* post-releases sort immediately after the final release of the same release
  (``1.0 < 1.0.post1``), the ``postN`` suffix compares numerically
  (``post2 < post9 < post10``), never lexically, and a development build of a
  post (``1.0.post2.dev1``) sorts just below that post itself;
* a ``fixed`` interval keeps its endpoint meanings for posts: introduced
  ``1.0.post1`` is affected, fixed ``1.0.post2`` is not, the final release
  ``1.0`` stays below the range and ``1.0.post2.dev1`` is still in range; a
  ``last_affected`` upper bound includes its post endpoint while later posts
  stay outside;
* explicit ``versions`` match by PEP 440 equality: a source listing
  ``1.0.post1`` also reaches a component registered as ``1.0-1``, but never
  ``1.0`` or ``1.0.post2`` — and equivalence never merges the two spellings
  in the directory: impact records, the component count and the versions
  embedded in dependency paths each keep their registered text;
* an explicit version and an interval hitting the same component from the
  same source produce one impact record that keeps both reasons, and summary
  and risk-report counts count component identities, not hit conditions;
* dependency propagation, summary counts and the risk report follow the
  actually hit post-release — an upper component depending on a hit post is
  indirectly affected on a path ending at that post with that endpoint's
  conditions, while depending only on the fixed post gives no impact even
  though an earlier post of the same package is affected;
* a post interval that is inverted under PEP 440 (e.g. introduced
  ``1.0.post10`` fixed ``1.0.post2``) rejects the import and leaves the
  previous source content in place.
"""

import unittest

from supply_guard.catalog import Catalog


def osv_record(identifier, package="lib", **affected):
    entry = {"package": {"ecosystem": "PyPI", "name": package}}
    entry.update(affected)
    return {"id": identifier, "affected": [entry]}


def post_range(*events):
    return [{"type": "ECOSYSTEM", "events": [dict([event]) for event in events]}]


# 1.0.post9 only lands where the numeric post ordering says it must: a lexical
# sort would wrongly place it past post10.
POST_VERSIONS = (
    "1.0",
    "1.0.post1",
    "1.0.post2",
    "1.0.post2.dev1",
    "1.0.post9",
    "1.0.post10",
)


class PostIntervalEndpointTests(unittest.TestCase):
    """Post-releases as introduced / fixed / last_affected interval ends."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        for version in POST_VERSIONS:
            self.catalog.add_component("api", "pypi", "lib", version)

    def tearDown(self) -> None:
        self.catalog.close()

    def records_by_version(self):
        return {r["component"]["version"]: r for r in self.catalog.impact()}

    def test_fixed_interval_introduced_in_fixed_out(self) -> None:
        # introduced 1.0.post1, fixed 1.0.post2: post1 itself is affected and
        # post2 (the fix) is not. Final 1.0 sorts below every post and stays
        # out; 1.0.post2.dev1 is a development build of post2 and therefore
        # sorts just below post2, so it is still inside the range.
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

    def test_fixed_interval_partitions_post_number_numerically(self) -> None:
        # post2..post10 with the fix at post10: post2 and post9 are in while
        # post10 is out. 9 is compared as a number — a lexical sort would
        # place it past 10. The dev build of post2 sorts below post2 and so
        # stays below the introduced bound.
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

    def test_last_affected_includes_post_endpoint_but_not_later_posts(self) -> None:
        # Same opening with last_affected: the post2 build itself is still
        # affected, and so is its own dev build; later posts (post9, post10)
        # and final 1.0 remain out.
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


class PostExplicitEquivalenceTests(unittest.TestCase):
    """Explicit conditions use PEP 440 equality and keep identity verbatim."""

    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def records_by_version(self):
        return {r["component"]["version"]: r for r in self.catalog.impact()}

    def test_post_explicit_matches_dash_spelling_but_not_release_or_next_post(
        self,
    ) -> None:
        # 1.0-1 is PEP 440's dash spelling of post-release 1: it equals
        # 1.0.post1 and differs from the final 1.0 and from 1.0.post2.
        for version in ("1.0", "1.0-1", "1.0.post1", "1.0.post2"):
            self.catalog.add_component("api", "pypi", "lib", version)
        self.catalog.import_osv(
            "src", [osv_record("CVE-1", versions=["1.0.post1"])]
        )
        by_version = self.records_by_version()
        self.assertEqual(set(by_version), {"1.0-1", "1.0.post1"})
        for version, record in by_version.items():
            self.assertTrue(record["direct"])
            self.assertEqual(record["component"]["version"], version)
            self.assertEqual(record["path"], [record["component"]])
            # The condition is rendered in the source-side normalized form;
            # the component identity still carries the registered spelling.
            self.assertEqual(record["matched_conditions"], ["==1.0.post1"])

    def test_dash_spelling_on_source_side_matches_dot_post_component(self) -> None:
        # Equivalence works in both source spellings: listing 1.0-1 reaches
        # a component registered as 1.0.post1 and still hits neither 1.0 nor
        # 1.0.post2.
        for version in ("1.0", "1.0-1", "1.0.post1", "1.0.post2"):
            self.catalog.add_component("api", "pypi", "lib", version)
        self.catalog.import_osv(
            "src", [osv_record("CVE-1", versions=["1.0-1"])]
        )
        self.assertEqual(set(self.records_by_version()), {"1.0-1", "1.0.post1"})

    def test_equivalent_spellings_remain_two_components(self) -> None:
        # Equality of the matching condition never merges directory rows:
        # two registrations stay two components with two impact records, and
        # every path keeps the version text each component was registered
        # with.
        self.catalog.add_component("api", "pypi", "lib", "1.0.post1")
        self.catalog.add_component("api", "pypi", "lib", "1.0-1")
        self.catalog.import_osv(
            "src", [osv_record("CVE-1", versions=["1.0.post1"])]
        )
        self.assertEqual(self.catalog.summary().components, 2)
        records = self.records_by_version()
        self.assertEqual(len(records), 2)
        for version in ("1.0.post1", "1.0-1"):
            self.assertEqual(records[version]["component"]["version"], version)
            self.assertEqual(
                [node["version"] for node in records[version]["path"]],
                [version],
            )

    def test_explicit_and_interval_together_yield_one_record_with_both_bases(
        self,
    ) -> None:
        # One component that is both explicitly listed and inside the range
        # answers with a single impact record for the one
        # vulnerability/source/package; the matched conditions explain both
        # bases instead of duplicating the component.
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
        self.assertTrue(records[0]["direct"])
        self.assertEqual(records[0]["component"]["version"], "1.0.post1")
        # One record explains both hit bases, in source declaration order.
        self.assertEqual(
            records[0]["matched_conditions"],
            ["==1.0.post1", ">=1.0.post1,<1.0.post2"],
        )
        # Two reasons for one identity never inflate the counts: one affected
        # component in the summary and one unhandled component in the report.
        self.assertEqual(self.catalog.summary().affected_components, 1)
        report = self.catalog.risk_report(evaluated_at="2026-10-07T00:00:00Z")
        self.assertEqual(report["impact_count"], 1)
        self.assertEqual(report["unhandled_component_count"], 1)


class PostDependencyTests(unittest.TestCase):
    """A hit post drives indirect impact with its real endpoint and conditions."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        # app depends on the in-range post1; clean-app depends only on the
        # fixed post2 build of the same package.
        self.catalog.add_component("api", "pypi", "app", "2.0.0")
        self.catalog.add_component("api", "pypi", "clean-app", "4.0.0")
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

    def test_only_the_in_range_post_is_directly_hit(self) -> None:
        direct = {
            (r["component"]["name"], r["component"]["version"])
            for r in self.catalog.impact()
            if r["direct"]
        }
        self.assertEqual(direct, {("lib", "1.0.post1")})

    def test_indirect_path_ends_at_the_depended_hit_post(self) -> None:
        records = self.catalog.impact()
        app = next(r for r in records if r["component"]["name"] == "app")
        self.assertFalse(app["direct"])
        # Path and explanation come from the version app actually depends
        # on: post1, never rewritten to the fixed post2.
        self.assertEqual(
            [(node["name"], node["version"]) for node in app["path"]],
            [("app", "2.0.0"), ("lib", "1.0.post1")],
        )
        self.assertEqual(
            app["matched_conditions"], [">=1.0.post1,<1.0.post2"]
        )

    def test_dependent_of_fixed_post_gets_no_impact(self) -> None:
        # Depending on the fixed build must not raise an indirect impact just
        # because an earlier post of the same package name is affected.
        names = {r["component"]["name"] for r in self.catalog.impact()}
        self.assertNotIn("clean-app", names)
        self.assertNotIn(
            ("lib", "1.0.post2"),
            {
                (r["component"]["name"], r["component"]["version"])
                for r in self.catalog.impact()
            },
        )

    def test_summary_counts_direct_and_indirect_components(self) -> None:
        summary = self.catalog.summary()
        # The in-range post1 plus the app that depends on it = 2 affected
        # components; fixed post2 and clean-app do not count.
        self.assertEqual(summary.components, 4)
        self.assertEqual(summary.affected_components, 2)
        self.assertEqual(summary.vulnerabilities, 1)
        self.assertEqual(summary.highest_severity, "medium")

    def test_risk_report_agrees_with_impact_on_flag_path_and_conditions(
        self,
    ) -> None:
        report = self.catalog.risk_report(evaluated_at="2026-10-07T00:00:00Z")
        impacts = self.catalog.impact()
        # With no exemptions every impact record is unhandled, so the report
        # covers both affected components and keeps the directory-wide
        # medium severity.
        self.assertEqual(report["impact_count"], 2)
        self.assertEqual(report["unhandled_component_count"], 2)
        self.assertEqual(report["highest_severity"], "medium")
        self.assertEqual({e["source"] for e in report["impacts"]}, {"src"})
        self.assertEqual({e["matched_name"] for e in report["impacts"]}, {"lib"})
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
        # Record-for-record agreement with impact, ordered or not: the set of
        # (component, vulnerability, source, direct flag, conditions, path) is
        # identical.
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


class PostEquivalentSpellingsDependencyTests(unittest.TestCase):
    """Two equivalent-spelling hit posts stay two path endpoints and identities."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        self.catalog.add_component("api", "pypi", "app", "2.0.0")
        self.catalog.add_component("api", "pypi", "lib", "1.0.post1")
        self.catalog.add_component("api", "pypi", "lib", "1.0-1")
        for lib_version in ("1.0.post1", "1.0-1"):
            self.catalog.add_dependency(
                "api", "pypi", "app", "2.0.0",
                "api", "pypi", "lib", lib_version,
            )
        self.catalog.import_osv(
            "src", [osv_record("CVE-1", versions=["1.0.post1"])]
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
        self.assertEqual(direct_versions, {"1.0.post1", "1.0-1"})
        app = next(r for r in records if r["component"]["name"] == "app")
        self.assertFalse(app["direct"])
        # The shortest-path tie-break (ecosystem, name, version) selects one
        # terminal deterministically; the path still ends at a genuinely hit
        # post registered verbatim.
        self.assertEqual(len(app["path"]), 2)
        self.assertEqual(app["path"][-1]["name"], "lib")
        self.assertIn(app["path"][-1]["version"], direct_versions)
        self.assertEqual(app["matched_conditions"], ["==1.0.post1"])

    def test_summary_and_report_count_the_two_identities_separately(self) -> None:
        # Equivalent spellings are two component identities and are counted
        # twice, alongside the indirectly affected app — three identities in
        # both the summary and the unhandled-component report.
        summary = self.catalog.summary()
        self.assertEqual(summary.components, 3)
        self.assertEqual(summary.affected_components, 3)
        report = self.catalog.risk_report(evaluated_at="2026-10-07T00:00:00Z")
        self.assertEqual(report["impact_count"], 3)
        self.assertEqual(report["unhandled_component_count"], 3)
        self.assertEqual(
            {
                (e["component"]["name"], e["component"]["version"])
                for e in report["impacts"]
            },
            {("app", "2.0.0"), ("lib", "1.0.post1"), ("lib", "1.0-1")},
        )


class PostInvertedIntervalTests(unittest.TestCase):
    """A PEP 440-inverted post interval rejects the import atomically."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        self.catalog.import_osv(
            "src", [osv_record("CVE-OK", versions=["1.0.post1"])]
        )

    def tearDown(self) -> None:
        self.catalog.close()

    def assert_previous_source_still_answers(self) -> None:
        self.catalog.add_component("api", "pypi", "lib", "1.0.post1")
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
        # post10 > post2 numerically; an interval opening at post10 with a
        # fix at post2 is inverted and must not import. The error names the
        # offending record, the range and both endpoints.
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

    def test_higher_post_introduced_with_lower_last_affected_rejected(self) -> None:
        # The same numerical inversion is caught for last_affected bounds as
        # well: introduced post10 cannot be above last_affected post2.
        with self.assertRaises(ValueError) as context:
            self.catalog.import_osv(
                "src",
                [
                    osv_record(
                        "CVE-BAD",
                        ranges=post_range(
                            ("introduced", "1.0.post10"),
                            ("last_affected", "1.0.post2"),
                        ),
                    )
                ],
            )
        message = str(context.exception)
        self.assertIn("记录 0", message)
        self.assertIn("区间倒置", message)
        self.assertIn("1.0.post10", message)
        self.assertIn("1.0.post2", message)
        self.assert_previous_source_still_answers()


if __name__ == "__main__":
    unittest.main()
