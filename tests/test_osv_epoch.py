"""Business regression tests for OSV matching when PyPI versions carry an epoch.

The existing OSV tests cover plain releases, simple pre-releases and local
versions, but never an epoch together with interval boundaries. Matching must
follow PEP 440 (the epoch before the ``!`` dominates, and release tuples are
compared numerically) end to end:

* real components are registered and a *local OSV file* is imported through
  the public entry points — these tests assert the impacts users actually
  query, not merely that version strings parse;
* ``introduced`` is inclusive, ``fixed`` is exclusive, ``last_affected`` is
  inclusive, and pre-releases keep their PEP 440 order under an epoch;
* explicit ``versions`` and ``ranges`` are a union, while one source's one
  vulnerability still yields a single record per hit component;
* the same answers show up through dependency propagation, ``summary`` and a
  fixed-instant ``risk-report``, and component version spellings (including
  the epoch) are preserved verbatim;
* an interval inverted by epoch magnitude fails the import, naming the
  offending record, and the source keeps its last successfully imported
  content.

Every scenario here is one that changes result when the epoch is dropped,
versions are compared as text, or an endpoint's inclusivity is flipped.
"""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from supply_guard.catalog import Catalog, parse_osv_record
from supply_guard.cli import main


PACKAGE = "epochlib"
EVALUATION_INSTANT = "2026-10-07T00:00:00+00:00"


def epoch_record(
    identifier,
    *,
    package=PACKAGE,
    versions=None,
    ranges=None,
    database_specific=None,
):
    entry = {"package": {"ecosystem": "PyPI", "name": package}}
    if versions is not None:
        entry["versions"] = versions
    if ranges is not None:
        entry["ranges"] = ranges
    record = {"id": identifier, "affected": [entry]}
    if database_specific is not None:
        record["database_specific"] = database_specific
    return record


def fixed_range(introduced, fixed=None, last_affected=None):
    """One ECOSYSTEM range from introduced to fixed/last_affected events."""
    events = [{"introduced": introduced}]
    if fixed is not None:
        events.append({"fixed": fixed})
    if last_affected is not None:
        events.append({"last_affected": last_affected})
    return [{"type": "ECOSYSTEM", "events": events}]


class EpochFileTestMixin:
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.directory = Path(self._directory.name)
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()
        self._directory.cleanup()

    def write_osv(self, records, name="osv.json") -> Path:
        path = self.directory / name
        path.write_text(json.dumps(records), encoding="utf-8")
        return path

    def import_file(self, source, records, name="osv.json") -> int:
        return self.catalog.import_osv_file(source, self.write_osv(records, name))

    def add(self, service, name, version):
        self.catalog.add_component(service, "pypi", name, version)

    def depends(self, service, dependent, version, dependency, dependency_version):
        self.catalog.add_dependency(
            service, "pypi", dependent, version,
            service, "pypi", dependency, dependency_version,
        )

    def hit_versions(self, records):
        return {r["component"]["version"] for r in records}


class EpochRangeBoundaryTests(EpochFileTestMixin, unittest.TestCase):
    """Direct matching: epoch ordering and endpoint inclusivity."""

    def register(self, *versions):
        for version in versions:
            self.add("api", PACKAGE, version)

    def test_numeric_release_order_inside_one_epoch_is_not_text_order(self) -> None:
        # 1!9.0 < 1!10.0 numerically; a text comparison would put "10" < "9"
        # and wrongly include 1!9.0 in [1!10.0, 2!1.0).
        self.register("1!9.0", "1!10.0", "1!99.0", "2!1.0")
        self.import_file(
            "src",
            [epoch_record("CVE-E1", ranges=fixed_range("1!10.0", fixed="2!1.0"))],
        )
        records = self.catalog.impact()
        self.assertEqual(self.hit_versions(records), {"1!10.0", "1!99.0"})
        for record in records:
            self.assertEqual(record["matched_conditions"], [">=1!10.0,<2!1.0"])
            self.assertTrue(record["direct"])
            self.assertEqual(record["component"]["version"][0:2], "1!")

    def test_higher_epoch_outranks_any_lower_epoch_release(self) -> None:
        # 2!1.0 > 1!99.0: an open range starting at 2!1.0 must not sweep in
        # 1!99.0, which text order ("1" < "2") and numeric-without-epoch
        # (99 > 1) would both misjudge in different ways.
        self.register("1!99.0", "2!1.0")
        self.import_file(
            "src",
            [epoch_record("CVE-E1", ranges=fixed_range("2!1.0"))],
        )
        records = self.catalog.impact()
        self.assertEqual(self.hit_versions(records), {"2!1.0"})

    def test_lower_epoch_release_stays_below_higher_epoch_bound(self) -> None:
        # 1!9.0 < 1!10.0: the introduced endpoint is reached exactly there.
        self.register("1!9.0", "1!10.0")
        self.import_file(
            "src",
            [epoch_record("CVE-E1", ranges=fixed_range("1!9.0", fixed="1!10.0"))],
        )
        records = self.catalog.impact()
        self.assertEqual(self.hit_versions(records), {"1!9.0"})
        self.assertEqual(records[0]["matched_conditions"], [">=1!9.0,<1!10.0"])

    def test_introduced_inclusive_fixed_exclusive_under_epoch(self) -> None:
        self.register("1!2.0", "1!2.5", "1!3.0")
        self.import_file(
            "src",
            [epoch_record("CVE-E1", ranges=fixed_range("1!2.0", fixed="1!3.0"))],
        )
        self.assertEqual(
            self.hit_versions(self.catalog.impact()), {"1!2.0", "1!2.5"}
        )

    def test_last_affected_endpoint_is_included_under_epoch(self) -> None:
        self.register("1!1.0", "1!2.0", "1!2.0.0", "1!2.0.1", "2!0.0")
        self.import_file(
            "src",
            [
                epoch_record(
                    "CVE-E1",
                    ranges=fixed_range("1!1.0", last_affected="1!2.0"),
                )
            ],
        )
        records = self.catalog.impact()
        # 1!2.0.0 is PEP 440-equal to the last_affected endpoint and is
        # therefore included too; 1!2.0.1 and the epoch-2 release are not.
        self.assertEqual(
            self.hit_versions(records), {"1!1.0", "1!2.0", "1!2.0.0"}
        )
        self.assertTrue(
            all(r["matched_conditions"] == [">=1!1.0,<=1!2.0"] for r in records)
        )

    def test_prerelease_at_epoch_bound_keeps_release_order(self) -> None:
        # 1!2.0rc1 < 1!2.0; the pre-release is affected inside
        # [1!2.0rc1, 1!2.0) while the final release is fixed (exclusive).
        self.register("1!1.9", "1!2.0rc1", "1!2.0")
        self.import_file(
            "src",
            [
                epoch_record(
                    "CVE-E1",
                    ranges=fixed_range("1!2.0rc1", fixed="1!2.0"),
                )
            ],
        )
        records = self.catalog.impact()
        self.assertEqual(self.hit_versions(records), {"1!2.0rc1"})
        self.assertEqual(
            records[0]["matched_conditions"], [">=1!2.0rc1,<1!2.0"]
        )

    def test_epoch_zero_fixed_bound_excludes_higher_epoch_release(self) -> None:
        # "9.0" and its explicit "0!9.0" spelling are one PEP 440 version and
        # both sit below the epoch-1 fixed bound; 1!9.0 is excluded despite
        # its release tuple looking smaller — the epoch decides first.
        self.register("9.0", "0!9.0", "1!9.0")
        self.import_file(
            "src",
            [epoch_record("CVE-E1", ranges=fixed_range("0", fixed="1!1.0"))],
        )
        self.assertEqual(
            self.hit_versions(self.catalog.impact()), {"9.0", "0!9.0"}
        )


class EpochEquivalenceAndUnionTests(EpochFileTestMixin, unittest.TestCase):
    """PEP 440-equivalent versions, distinct identities, union semantics."""

    def test_equivalent_versions_are_two_component_identities(self) -> None:
        # 1!2.0 and 1!2.0.0 compare equal in a vulnerability condition but
        # stay two independently registered components in the directory.
        self.add("api", PACKAGE, "1!2.0")
        self.add("api", PACKAGE, "1!2.0.0")
        identities = self.catalog.connection.execute(
            "SELECT version FROM components WHERE ecosystem = 'pypi' AND name = ?",
            (PACKAGE,),
        ).fetchall()
        self.assertEqual({row["version"] for row in identities},
                         {"1!2.0", "1!2.0.0"})
        self.import_file(
            "src",
            [epoch_record("CVE-E1", ranges=fixed_range("1!2.0", fixed="1!3.0"))],
        )
        records = self.catalog.impact()
        self.assertEqual(self.hit_versions(records), {"1!2.0", "1!2.0.0"})

    def test_explicit_epoch_version_matches_equivalent_spelling(self) -> None:
        # A component registered as 1!2.0 is hit by an explicit 1!2.0.0
        # condition; the component's own spelling is preserved.
        self.add("api", PACKAGE, "1!2.0")
        self.import_file(
            "src",
            [epoch_record("CVE-E1", versions=["1!2.0.0"])],
        )
        records = self.catalog.impact()
        self.assertEqual(len(records), 1)
        # The component keeps its registered spelling; the condition keeps
        # the OSV record's declared (normalized) spelling.
        self.assertEqual(records[0]["component"]["version"], "1!2.0")
        self.assertEqual(records[0]["matched_conditions"], ["==1!2.0.0"])

    def test_equivalent_terminals_keep_dependent_paths_distinct(self) -> None:
        # Each app depends on one specific spelling; equivalence applies only
        # to matching, never to dependency endpoint resolution.
        self.add("api", "appa", "1.0.0")
        self.add("api", "appb", "1.0.0")
        self.add("api", PACKAGE, "1!2.0")
        self.add("api", PACKAGE, "1!2.0.0")
        self.depends("api", "appa", "1.0.0", PACKAGE, "1!2.0")
        self.depends("api", "appb", "1.0.0", PACKAGE, "1!2.0.0")
        self.import_file(
            "src",
            [epoch_record("CVE-E1", versions=["1!2.0"])],
        )
        records = {
            (r["component"]["name"], r["direct"]): r
            for r in self.catalog.impact()
        }
        # Both equivalent library identities are directly hit.
        direct = {
            r["component"]["version"]
            for r in self.catalog.impact()
            if r["direct"] and r["component"]["name"] == PACKAGE
        }
        self.assertEqual(direct, {"1!2.0", "1!2.0.0"})
        app_a = records[("appa", False)]
        app_b = records[("appb", False)]
        self.assertEqual(
            [node["version"] for node in app_a["path"]], ["1.0.0", "1!2.0"]
        )
        self.assertEqual(
            [node["version"] for node in app_b["path"]], ["1.0.0", "1!2.0.0"]
        )
        self.assertEqual(app_a["matched_conditions"], ["==1!2.0"])
        self.assertEqual(app_b["matched_conditions"], ["==1!2.0"])

    def test_explicit_versions_and_ranges_union_with_one_record(self) -> None:
        # versions and ranges declared together are a union. A component
        # covered by both produces one record carrying both conditions; the
        # range-only and explicit-only components are hit through exactly
        # their own condition.
        self.add("api", PACKAGE, "1!1.5")
        self.add("api", PACKAGE, "1!2.0")
        self.add("api", PACKAGE, "1!2.5")
        self.import_file(
            "src",
            [
                epoch_record(
                    "CVE-E1",
                    versions=["1!2.5"],
                    ranges=fixed_range("1!1.0", fixed="1!2.0"),
                )
            ],
        )
        by_version = {
            r["component"]["version"]: r for r in self.catalog.impact()
        }
        self.assertEqual(set(by_version), {"1!1.5", "1!2.5"})
        self.assertEqual(
            by_version["1!1.5"]["matched_conditions"], [">=1!1.0,<1!2.0"]
        )
        self.assertEqual(by_version["1!2.5"]["matched_conditions"], ["==1!2.5"])
        # Same source + same vulnerability + same component = one record even
        # when the fixed endpoint spelling differs only by release padding.
        self.add("api", "otherlib", "1!1.5")
        second_import = [
            epoch_record(
                "CVE-E1",
                versions=["1!1.5.0"],
                ranges=fixed_range("1!1.0", fixed="1!2.0"),
            )
        ]
        self.catalog.import_osv_file("src", self.write_osv(second_import, "b.json"))
        overlap = [
            r for r in self.catalog.impact()
            if r["component"]["name"] == PACKAGE and r["component"]["version"] == "1!1.5"
        ]
        self.assertEqual(len(overlap), 1)
        self.assertEqual(
            overlap[0]["matched_conditions"],
            ["==1!1.5.0", ">=1!1.0,<1!2.0"],
        )


class EpochDependencyConsistencyTests(EpochFileTestMixin, unittest.TestCase):
    """Indirect impacts must follow the actually depended-upon epoch version."""

    def build_directory(self) -> None:
        # api: one app per library version; worker registers the same package
        # name independently in another service.
        self.add("api", "appgood", "1.0.0")
        self.add("api", "appsafe", "1.0.0")
        self.add("api", "appfixed", "1.0.0")
        for version in ("1!9.0", "1!10.0", "1!99.0", "2!1.0"):
            self.add("api", PACKAGE, version)
        self.depends("api", "appgood", "1.0.0", PACKAGE, "1!10.0")
        self.depends("api", "appsafe", "1.0.0", PACKAGE, "1!9.0")
        self.depends("api", "appfixed", "1.0.0", PACKAGE, "2!1.0")

        self.add("worker", "workerapp", "1.0.0")
        self.add("worker", PACKAGE, "1!10.0")
        self.depends("worker", "workerapp", "1.0.0", PACKAGE, "1!10.0")

    def import_vulnerability(self) -> None:
        self.import_file(
            "src",
            [
                epoch_record(
                    "CVE-E1",
                    ranges=fixed_range("1!10.0", fixed="2!1.0"),
                    database_specific={"severity": "high"},
                )
            ],
        )

    def test_indirect_record_uses_the_hit_dependency_version(self) -> None:
        self.build_directory()
        self.import_vulnerability()
        records = self.catalog.impact()
        by_identity = {
            (r["component"]["service"], r["component"]["name"],
             r["component"]["version"]): r
            for r in records
        }
        by_component = {
            (r["component"]["service"], r["component"]["name"]): r
            for r in records
        }
        # Direct hits: the two epoch-1 releases inside [1!10.0, 2!1.0) in
        # api, plus the same-named 1!10.0 component in worker.
        self.assertEqual(
            {key for key, r in by_identity.items() if r["direct"]},
            {
                ("api", PACKAGE, "1!10.0"),
                ("api", PACKAGE, "1!99.0"),
                ("worker", PACKAGE, "1!10.0"),
            },
        )
        self.assertEqual(
            by_identity[("api", PACKAGE, "1!10.0")]["matched_conditions"],
            [">=1!10.0,<2!1.0"],
        )

        # appgood is indirect through the version it actually declares.
        appgood = by_component[("api", "appgood")]
        self.assertFalse(appgood["direct"])
        self.assertEqual(
            [(node["name"], node["version"]) for node in appgood["path"]],
            [("appgood", "1.0.0"), (PACKAGE, "1!10.0")],
        )
        self.assertEqual(appgood["matched_conditions"], [">=1!10.0,<2!1.0"])

        # Apps depending on out-of-range versions are not brought in by the
        # shared package name.
        self.assertNotIn(("api", "appsafe"), by_component)
        self.assertNotIn(("api", "appfixed"), by_component)

        # worker's same-name components are a separate graph: workerapp is
        # indirect within worker, never linked to api's 1!10.0.
        workerapp = by_component[("worker", "workerapp")]
        self.assertFalse(workerapp["direct"])
        self.assertEqual(
            [node["service"] for node in workerapp["path"]], ["worker", "worker"]
        )
        self.assertEqual(
            [node["version"] for node in workerapp["path"]], ["1.0.0", "1!10.0"]
        )

    def test_summary_impact_and_risk_report_answer_same_directory(self) -> None:
        self.build_directory()
        self.import_vulnerability()
        impacts = self.catalog.impact()
        summary = self.catalog.summary()
        report = self.catalog.risk_report(evaluated_at=EVALUATION_INSTANT)

        # Distinct affected components:
        # api: epochlib 1!10.0, epochlib 1!99.0, appgood
        # worker: epochlib 1!10.0, workerapp
        affected_identities = {
            (r["component"]["service"], r["component"]["name"],
             r["component"]["version"])
            for r in impacts
        }
        self.assertEqual(len(affected_identities), 5)
        self.assertEqual(summary.affected_components, 5)
        self.assertEqual(summary.vulnerabilities, 1)
        self.assertEqual(summary.highest_severity, "high")

        self.assertEqual(report["impact_count"], len(impacts))
        self.assertEqual(report["unhandled_component_count"], 5)
        self.assertEqual(report["highest_severity"], "high")

        report_pairs = {
            (
                e["component"]["service"], e["component"]["name"],
                e["component"]["version"], e["direct"],
                tuple((n["name"], n["version"]) for n in e["path"]),
                tuple(e["matched_conditions"]),
            )
            for e in report["impacts"]
        }
        impact_pairs = {
            (
                r["component"]["service"], r["component"]["name"],
                r["component"]["version"], r["direct"],
                tuple((n["name"], n["version"]) for n in r["path"]),
                tuple(r["matched_conditions"]),
            )
            for r in impacts
        }
        self.assertEqual(report_pairs, impact_pairs)

        # Component versions keep their registered spelling everywhere.
        for entry in report["impacts"]:
            for node in entry["path"]:
                row = self.catalog.connection.execute(
                    "SELECT version FROM components WHERE service = ? "
                    "AND ecosystem = ? AND name = ? AND version = ?",
                    (node["service"], node["ecosystem"], node["name"],
                     node["version"]),
                ).fetchone()
                self.assertIsNotNone(row)

        # Fixed evaluation instant is deterministic.
        again = self.catalog.risk_report(evaluated_at=EVALUATION_INSTANT)
        self.assertEqual(again, report)


class EpochInvertedIntervalImportTests(EpochFileTestMixin, unittest.TestCase):
    """Bounds inverted by epoch must fail the import and name the record."""

    def test_parse_rejects_epoch_inverted_fixed_interval(self) -> None:
        # PEP 440: 1!2.0 > 0!9.0 even though the epoch-1 release tuple looks
        # smaller; the interval is inverted because of the epoch itself.
        record = epoch_record(
            "CVE-BAD", ranges=fixed_range("1!2.0", fixed="0!9.0")
        )
        with self.assertRaises(ValueError) as context:
            parse_osv_record(record)
        message = str(context.exception)
        self.assertIn("区间倒置", message)
        self.assertIn("affected[0].ranges[0]", message)
        self.assertIn("1!2.0", message)
        self.assertIn("0!9.0", message)

    def test_parse_rejects_numeric_inversion_hidden_from_text_order(self) -> None:
        # 2!10.0 > 2!9.0 numerically, but as text "2!10.0" < "2!9.0"; the
        # inversion exists only under PEP 440 ordering, for both endpoint
        # event kinds.
        with self.assertRaises(ValueError) as context:
            parse_osv_record(
                epoch_record("CVE-BAD", ranges=fixed_range("2!10.0", fixed="2!9.0"))
            )
        self.assertIn("区间倒置", str(context.exception))
        with self.assertRaises(ValueError) as context:
            parse_osv_record(
                epoch_record(
                    "CVE-BAD", ranges=fixed_range("2!10.0", last_affected="2!9.0")
                )
            )
        self.assertIn("区间倒置", str(context.exception))

    def test_failed_import_names_record_and_keeps_last_good_content(self) -> None:
        # First, a successful import: 1!2.0 is affected by [1!1.0, 1!3.0).
        self.import_file(
            "src",
            [epoch_record("CVE-GOOD", ranges=fixed_range("1!1.0", fixed="1!3.0"))],
            name="good.json",
        )
        # Another source and its hit must survive untouched.
        self.import_file(
            "other",
            [epoch_record("CVE-OTHER", package="otherlib", versions=["1!1.0"])],
            name="other.json",
        )
        self.add("api", PACKAGE, "1!2.0")
        self.add("api", PACKAGE, "1!5.0")
        self.add("api", "otherlib", "1!1.0")

        # The replacement carries a valid-looking first record (which must
        # NOT be partially applied) followed by an epoch-inverted record.
        replacement = [
            epoch_record("CVE-NEW", versions=["1!5.0"]),
            epoch_record(
                "CVE-BAD",
                ranges=fixed_range("2!10.0", last_affected="2!9.0"),
            ),
        ]
        with self.assertRaises(ValueError) as context:
            self.catalog.import_osv_file(
                "src", self.write_osv(replacement, "bad.json")
            )
        message = str(context.exception)
        self.assertIn("记录 1", message)
        self.assertIn("affected[0].ranges[0]", message)
        self.assertIn("2!10.0", message)
        self.assertIn("2!9.0", message)

        stored = self.catalog.connection.execute(
            "SELECT id FROM osv_vulnerabilities WHERE source = 'src'"
        ).fetchall()
        self.assertEqual([row["id"] for row in stored], ["CVE-GOOD"])

        # The catalog still answers from the last successful src import:
        # 1!2.0 hit by CVE-GOOD, 1!5.0 not hit, CVE-NEW never arrived.
        records = self.catalog.impact()
        by_key = {
            (r["vulnerability"], r["component"]["name"],
             r["component"]["version"]): r
            for r in records
        }
        self.assertIn(("CVE-GOOD", PACKAGE, "1!2.0"), by_key)
        self.assertNotIn(("CVE-NEW", PACKAGE, "1!5.0"), by_key)
        self.assertNotIn(("CVE-GOOD", PACKAGE, "1!5.0"), by_key)
        self.assertIn(("CVE-OTHER", "otherlib", "1!1.0"), by_key)

        # summary and risk-report read that same pre-replacement state.
        summary = self.catalog.summary()
        self.assertEqual(summary.vulnerabilities, 2)
        self.assertEqual(summary.affected_components, 2)
        report = self.catalog.risk_report(evaluated_at=EVALUATION_INSTANT)
        self.assertEqual(
            {e["vulnerability"] for e in report["impacts"]},
            {"CVE-GOOD", "CVE-OTHER"},
        )
        self.assertEqual(report["unhandled_component_count"], 2)

    def test_cli_failed_import_is_nonzero_and_source_survives(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            good = Path(directory, "good.json")
            good.write_text(
                json.dumps(
                    [epoch_record("CVE-GOOD",
                                  ranges=fixed_range("1!1.0", fixed="1!3.0"))]
                ),
                encoding="utf-8",
            )
            bad = Path(directory, "bad.json")
            bad.write_text(
                json.dumps(
                    [epoch_record(
                        "CVE-BAD",
                        ranges=fixed_range("1!2.0", fixed="0!9.0"),
                    )]
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                main(["--database", database, "import-osv", "src", str(good)]), 0
            )
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = main(
                    ["--database", database, "import-osv", "src", str(bad)]
                )
            self.assertEqual(result, 1)
            error = stderr.getvalue()
            self.assertIn("记录 0", error)
            self.assertIn("affected[0].ranges[0]", error)
            self.assertIn("区间倒置", error)
            self.assertIn("1!2.0", error)
            self.assertIn("0!9.0", error)
            self.assertNotIn("导入漏洞记录", stdout.getvalue())

            catalog = Catalog(database)
            catalog.add_component("api", "pypi", PACKAGE, "1!2.0")
            records = catalog.impact()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["vulnerability"], "CVE-GOOD")
            catalog.close()


class EpochCliEndToEndTests(unittest.TestCase):
    """Register components and import a local OSV source via the CLI itself."""

    def run_cli(self, database, *arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = main(["--database", database, *arguments])
        self.assertEqual(result, 0, stderr.getvalue())
        return stdout.getvalue()

    def test_epoch_matching_through_directories_import_and_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            osv_path = Path(directory, "epoch.json")
            osv_path.write_text(
                json.dumps(
                    [
                        epoch_record(
                            "CVE-E1",
                            ranges=fixed_range("1!10.0", fixed="2!1.0"),
                            database_specific={"severity": "high"},
                        )
                    ]
                ),
                encoding="utf-8",
            )

            self.run_cli(database, "init")
            for version in ("1!9.0", "1!10.0", "1!99.0", "2!1.0"):
                self.run_cli(database, "add-component", "api", "pypi",
                             PACKAGE, version)
            self.run_cli(database, "add-component", "api", "pypi",
                         "appgood", "1.0.0")
            self.run_cli(database, "add-component", "api", "pypi",
                         "appsafe", "1.0.0")
            self.run_cli(
                database, "add-dependency",
                "api", "pypi", "appgood", "1.0.0",
                "api", "pypi", PACKAGE, "1!10.0",
            )
            self.run_cli(
                database, "add-dependency",
                "api", "pypi", "appsafe", "1.0.0",
                "api", "pypi", PACKAGE, "1!9.0",
            )
            output = self.run_cli(database, "import-osv", "src", str(osv_path))
            self.assertIn("导入漏洞记录: 1 条", output)

            impacts = json.loads(self.run_cli(database, "impact"))
            by_name_version = {
                (r["component"]["name"], r["component"]["version"]): r
                for r in impacts
            }
            self.assertEqual(
                set(by_name_version),
                {
                    (PACKAGE, "1!10.0"),
                    (PACKAGE, "1!99.0"),
                    ("appgood", "1.0.0"),
                },
            )
            direct = by_name_version[(PACKAGE, "1!10.0")]
            self.assertTrue(direct["direct"])
            self.assertEqual(direct["matched_conditions"],
                             [">=1!10.0,<2!1.0"])
            indirect = by_name_version[("appgood", "1.0.0")]
            self.assertFalse(indirect["direct"])
            self.assertEqual(
                [(n["name"], n["version"]) for n in indirect["path"]],
                [("appgood", "1.0.0"), (PACKAGE, "1!10.0")],
            )

            report = json.loads(
                self.run_cli(
                    database, "risk-report", "--at", EVALUATION_INSTANT
                )
            )
            self.assertEqual(report["impact_count"], 3)
            self.assertEqual(report["unhandled_component_count"], 3)
            self.assertEqual(report["highest_severity"], "high")
            self.assertEqual(
                {(e["component"]["name"], e["component"]["version"])
                 for e in report["impacts"]},
                {(PACKAGE, "1!10.0"), (PACKAGE, "1!99.0"),
                 ("appgood", "1.0.0")},
            )

            # Reopening the database at the same instant reproduces the
            # report: epoch conditions are persisted, not re-derived loosely.
            reopened_stdout = io.StringIO()
            with redirect_stdout(reopened_stdout):
                self.assertEqual(
                    main([
                        "--database", database, "risk-report",
                        "--at", EVALUATION_INSTANT,
                    ]),
                    0,
                )
            self.assertEqual(
                json.loads(reopened_stdout.getvalue()), report
            )


if __name__ == "__main__":
    unittest.main()
