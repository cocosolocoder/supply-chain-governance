import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from supply_guard.catalog import Catalog, parse_osv_record
from supply_guard.cli import main


def osv_record(
    identifier,
    package="Flask",
    ecosystem="PyPI",
    database_specific=None,
    withdrawn=None,
    **affected,
):
    entry = {"package": {"ecosystem": ecosystem, "name": package}}
    entry.update(affected)
    record = {"id": identifier, "affected": [entry]}
    if database_specific is not None:
        record["database_specific"] = database_specific
    if withdrawn is not None:
        record["withdrawn"] = withdrawn
    return record


def osv_file(records):
    return json.dumps(records)


class ParseValidationTests(unittest.TestCase):
    def test_versions_and_ranges_are_accepted(self) -> None:
        rows = parse_osv_record(
            osv_record(
                "CVE-1",
                versions=["1.0.0", "2.0.0"],
                ranges=[
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "1.5.0"},
                            {"introduced": "2.0.0"},
                            {"last_affected": "2.5.0"},
                        ],
                    }
                ],
            )
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "CVE-1")
        self.assertEqual(rows[0]["package_name"], "flask")
        self.assertEqual(len(rows[0]["conditions"]), 4)

    def test_missing_id_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_osv_record({"affected": []})
        with self.assertRaises(ValueError):
            parse_osv_record({"id": "  ", "affected": []})

    def test_record_must_be_object(self) -> None:
        with self.assertRaises(ValueError):
            parse_osv_record("not-an-object")

    def test_affected_must_be_nonempty_array(self) -> None:
        with self.assertRaises(ValueError):
            parse_osv_record({"id": "CVE-1"})
        with self.assertRaises(ValueError):
            parse_osv_record({"id": "CVE-1", "affected": []})
        with self.assertRaises(ValueError):
            parse_osv_record({"id": "CVE-1", "affected": "nope"})

    def test_other_ecosystem_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_osv_record(osv_record("CVE-1", ecosystem="npm"))
        with self.assertRaises(ValueError):
            parse_osv_record(osv_record("CVE-1", ecosystem="Maven"))

    def test_ecosystem_is_case_insensitive(self) -> None:
        rows = parse_osv_record(
            osv_record("CVE-1", ecosystem="pypi", versions=["1.0.0"])
        )
        self.assertEqual(rows[0]["package_name"], "flask")

    def test_versions_must_be_parseable(self) -> None:
        with self.assertRaises(ValueError):
            parse_osv_record(osv_record("CVE-1", versions=["not-a-version"]))

    def test_range_type_must_be_ecosystem(self) -> None:
        with self.assertRaises(ValueError):
            parse_osv_record(
                osv_record(
                    "CVE-1",
                    ranges=[{"type": "SEMVER", "events": [{"introduced": "0"}]}],
                )
            )

    def test_unknown_event_type_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_osv_record(
                osv_record(
                    "CVE-1",
                    ranges=[{"type": "ECOSYSTEM", "events": [{"limit": "*"}]}],
                )
            )

    def test_event_with_extra_keys_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_osv_record(
                osv_record(
                    "CVE-1",
                    ranges=[
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0", "fixed": "1.0"}],
                        }
                    ],
                )
            )

    def test_event_order_must_be_legal(self) -> None:
        # Two introduced in a row.
        with self.assertRaises(ValueError):
            parse_osv_record(
                osv_record(
                    "CVE-1",
                    ranges=[
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "1.0"}, {"introduced": "2.0"}],
                        }
                    ],
                )
            )
        # End event without introduced.
        with self.assertRaises(ValueError):
            parse_osv_record(
                osv_record(
                    "CVE-1",
                    ranges=[
                        {"type": "ECOSYSTEM", "events": [{"fixed": "1.0"}]}
                    ],
                )
            )

    def test_inverted_interval_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_osv_record(
                osv_record(
                    "CVE-1",
                    ranges=[
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "2.0"}, {"fixed": "1.0"}],
                        }
                    ],
                )
            )
        with self.assertRaises(ValueError):
            parse_osv_record(
                osv_record(
                    "CVE-1",
                    ranges=[
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "2.0"},
                                {"last_affected": "1.0"},
                            ],
                        }
                    ],
                )
            )

    def test_unparseable_event_version_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_osv_record(
                osv_record(
                    "CVE-1",
                    ranges=[
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "not-a-version"}],
                        }
                    ],
                )
            )

    def test_missing_version_conditions_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_osv_record(osv_record("CVE-1"))

    def test_withdrawn_must_be_valid_timestamp(self) -> None:
        with self.assertRaises(ValueError):
            parse_osv_record(
                osv_record("CVE-1", versions=["1.0.0"], withdrawn="not-a-timestamp")
            )

    def test_missing_severity_defaults_to_medium(self) -> None:
        rows = parse_osv_record(osv_record("CVE-1", versions=["1.0.0"]))
        self.assertEqual(rows[0]["severity"], "medium")
        self.assertTrue(rows[0]["severity_default"])

    def test_declared_severity_is_used(self) -> None:
        rows = parse_osv_record(
            osv_record(
                "CVE-1",
                versions=["1.0.0"],
                database_specific={"severity": "CRITICAL"},
            )
        )
        self.assertEqual(rows[0]["severity"], "critical")
        self.assertFalse(rows[0]["severity_default"])

    def test_invalid_severity_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_osv_record(
                osv_record(
                    "CVE-1",
                    versions=["1.0.0"],
                    database_specific={"severity": "extreme"},
                )
            )

    def test_multiple_packages_produce_multiple_rows(self) -> None:
        record = {
            "id": "CVE-1",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "Flask"},
                    "versions": ["1.0.0"],
                },
                {
                    "package": {"ecosystem": "PyPI", "name": "Werkzeug"},
                    "versions": ["2.0.0"],
                },
            ],
        }
        rows = parse_osv_record(record)
        self.assertEqual(
            {row["package_name"] for row in rows}, {"flask", "werkzeug"}
        )


class MatchingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def import_records(self, records) -> None:
        self.catalog.import_osv("src", records)

    def test_name_normalization_and_ecosystem(self) -> None:
        self.catalog.add_component("api", "pypi", "Flask", "1.0.0")
        self.catalog.add_component("api", "pypi", "flask_restful", "1.0.0")
        self.catalog.add_component("api", "pypi", "flask.restful", "1.0.0")
        self.catalog.add_component("api", "npm", "flask", "1.0.0")
        self.import_records([osv_record("CVE-1", package="Flask-RESTful", versions=["1.0.0"])])
        records = self.catalog.impact()
        names = {r["component"]["name"] for r in records}
        self.assertEqual(names, {"flask_restful", "flask.restful"})

    def test_pypi_name_is_case_insensitive(self) -> None:
        self.catalog.add_component("api", "pypi", "Flask", "1.0.0")
        self.import_records([osv_record("CVE-1", package="flask", versions=["1.0.0"])])
        self.assertEqual(len(self.catalog.impact()), 1)

    def test_explicit_versions_match_pep440_equivalence(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1.0")
        self.import_records([osv_record("CVE-1", versions=["1.0.0"])])
        self.assertEqual(len(self.catalog.impact()), 1)

    def test_prerelease_and_local_versions_participate(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1.0a1")
        self.catalog.add_component("api", "pypi", "flask", "1.0")
        self.catalog.add_component("api", "pypi", "flask", "1.0+local")
        self.import_records(
            [
                osv_record(
                    "CVE-1",
                    ranges=[
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "1.0a1"}, {"fixed": "1.0"}],
                        }
                    ],
                    versions=["1.0+local"],
                )
            ]
        )
        records = self.catalog.impact()
        versions = {r["component"]["version"] for r in records}
        self.assertEqual(versions, {"1.0a1", "1.0+local"})

    def test_introduced_zero_means_no_lower_bound(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "0.0.1")
        self.catalog.add_component("api", "pypi", "flask", "99.0.0")
        self.import_records(
            [
                osv_record(
                    "CVE-1",
                    ranges=[
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1.0"}],
                        }
                    ],
                )
            ]
        )
        records = self.catalog.impact()
        self.assertEqual({r["component"]["version"] for r in records}, {"0.0.1"})

    def test_open_ended_range_has_no_upper_bound(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1.0")
        self.catalog.add_component("api", "pypi", "flask", "99.0.0")
        self.import_records(
            [
                osv_record(
                    "CVE-1",
                    ranges=[
                        {"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}]}
                    ],
                )
            ]
        )
        self.assertEqual(len(self.catalog.impact()), 2)

    def test_last_affected_is_included(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1.5")
        self.catalog.add_component("api", "pypi", "flask", "1.6")
        self.import_records(
            [
                osv_record(
                    "CVE-1",
                    ranges=[
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0"},
                                {"last_affected": "1.5"},
                            ],
                        }
                    ],
                )
            ]
        )
        records = self.catalog.impact()
        self.assertEqual({r["component"]["version"] for r in records}, {"1.5"})

    def test_fixed_is_excluded_and_reintroduction_allowed(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1.4")
        self.catalog.add_component("api", "pypi", "flask", "1.5")
        self.catalog.add_component("api", "pypi", "flask", "2.4")
        self.catalog.add_component("api", "pypi", "flask", "2.5")
        self.import_records(
            [
                osv_record(
                    "CVE-1",
                    ranges=[
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0"},
                                {"fixed": "1.5"},
                                {"introduced": "2.0"},
                                {"fixed": "2.5"},
                            ],
                        }
                    ],
                )
            ]
        )
        records = self.catalog.impact()
        self.assertEqual(
            {r["component"]["version"] for r in records}, {"1.4", "2.4"}
        )

    def test_unparseable_component_version_raises_with_component(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "not-a-version")
        self.import_records([osv_record("CVE-1", versions=["1.0.0"])])
        with self.assertRaises(ValueError) as context:
            self.catalog.impact()
        self.assertIn("版本无法解析", str(context.exception))
        self.assertIn("api/pypi/flask/not-a-version", str(context.exception))


class ServiceScopeIsolationTests(unittest.TestCase):
    """Invalid versions registered in other services must not fail scoped queries."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        # api: app depends on flask 1.0.0
        self.catalog.add_component("api", "pypi", "app", "1.0.0")
        self.catalog.add_component("api", "pypi", "flask", "1.0.0")
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "flask", "1.0.0"
        )
        # worker: another flask whose version PEP 440 cannot parse.
        self.catalog.add_component("worker", "pypi", "flask", "not-a-version")
        self.catalog.import_osv(
            "nvd", [osv_record("CVE-2026-777", versions=["1.0.0"])]
        )

    def tearDown(self) -> None:
        self.catalog.close()

    def test_scoped_impact_succeeds_with_full_direct_and_indirect_result(self) -> None:
        records = self.catalog.impact(service="api")
        by_name = {r["component"]["name"]: r for r in records}
        self.assertEqual(set(by_name), {"app", "flask"})
        self.assertTrue(by_name["flask"]["direct"])
        self.assertFalse(by_name["app"]["direct"])
        # The indirect explanation keeps the path app -> flask.
        self.assertEqual(
            [n["name"] for n in by_name["app"]["path"]], ["app", "flask"]
        )
        self.assertEqual(
            [n["version"] for n in by_name["app"]["path"]], ["1.0.0", "1.0.0"]
        )
        self.assertEqual(by_name["app"]["vulnerability"], "CVE-2026-777")
        self.assertEqual(by_name["app"]["source"], "nvd")

    def test_scoped_impact_excludes_other_service_components(self) -> None:
        records = self.catalog.impact(service="api")
        self.assertTrue(
            all(r["component"]["service"] == "api" for r in records)
        )
        self.assertFalse(
            any(
                r["component"]["name"] == "flask"
                and r["component"]["version"] == "not-a-version"
                for r in records
            )
        )

    def test_identity_filter_keeps_transitive_impacts_in_judgement(self) -> None:
        # Showing only app still relies on flask participating in OSV
        # matching: the indirect hit must not be dropped just because flask
        # is absent from the final component list.
        records = self.catalog.impact(
            service="api", ecosystem="pypi", name="app", version="1.0.0"
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["component"]["name"], "app")
        self.assertFalse(records[0]["direct"])
        self.assertEqual(
            [n["name"] for n in records[0]["path"]], ["app", "flask"]
        )

    def test_in_service_unparseable_version_still_errors(self) -> None:
        with self.assertRaises(ValueError) as context:
            self.catalog.impact(service="worker")
        message = str(context.exception)
        self.assertIn("版本无法解析", message)
        self.assertIn("worker/pypi/flask/not-a-version", message)

    def test_unknown_service_returns_empty_impacts(self) -> None:
        self.assertEqual(self.catalog.impact(service="ghost"), [])

    def test_scoped_risk_report_counts_and_highest_reflect_only_service(self) -> None:
        report = self.catalog.risk_report(service="api")
        self.assertEqual(report["service"], "api")
        self.assertEqual(report["impact_count"], 2)
        self.assertEqual(report["unhandled_component_count"], 2)
        self.assertEqual(report["highest_severity"], "medium")
        self.assertTrue(
            all(i["component"]["service"] == "api" for i in report["impacts"])
        )

    def test_scoped_risk_report_with_in_service_bad_version_errors(self) -> None:
        with self.assertRaises(ValueError) as context:
            self.catalog.risk_report(service="worker")
        self.assertIn("worker/pypi/flask/not-a-version", str(context.exception))

    def test_scoped_risk_report_unknown_service_is_empty_report(self) -> None:
        report = self.catalog.risk_report(service="ghost")
        self.assertEqual(report["impact_count"], 0)
        self.assertEqual(report["unhandled_component_count"], 0)
        self.assertIsNone(report["highest_severity"])
        self.assertEqual(report["impacts"], [])
        self.assertEqual(report["service"], "ghost")

    def test_unscoped_queries_keep_raising_on_any_bad_version(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.impact()
        with self.assertRaises(ValueError):
            self.catalog.summary()
        with self.assertRaises(ValueError):
            self.catalog.risk_report()

    def test_successful_scoped_query_does_not_modify_data(self) -> None:
        def snapshot():
            return (
                self.catalog.connection.execute(
                    "SELECT service, ecosystem, name, version FROM components "
                    "ORDER BY service, ecosystem, name, version"
                ).fetchall(),
                self.catalog.connection.execute(
                    "SELECT id, source, package_name FROM osv_vulnerabilities "
                    "ORDER BY id"
                ).fetchall(),
            )

        before = snapshot()
        self.catalog.impact(service="api")
        self.catalog.risk_report(service="api")
        self.assertEqual(snapshot(), before)
        # The worker's invalid registration is still present and still
        # makes a directory-wide query fail.
        with self.assertRaises(ValueError):
            self.catalog.impact()

    def test_cli_scoped_impact_succeeds_while_worker_version_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            osv_path = Path(directory, "osv.json")
            osv_path.write_text(
                osv_file([osv_record("CVE-2026-777", versions=["1.0.0"])])
            )
            self.assertEqual(
                main(["--database", database, "import-osv", "nvd", str(osv_path)]),
                0,
            )
            for args in (
                ["add-component", "api", "pypi", "app", "1.0.0"],
                ["add-component", "api", "pypi", "flask", "1.0.0"],
                [
                    "add-dependency", "api", "pypi", "app", "1.0.0",
                    "api", "pypi", "flask", "1.0.0",
                ],
                ["add-component", "worker", "pypi", "flask", "not-a-version"],
            ):
                self.assertEqual(
                    main(["--database", database, *args]), 0
                )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = main(
                    ["--database", database, "impact", "--service", "api"]
                )
            self.assertEqual(status, 0)
            records = json.loads(stdout.getvalue())
            self.assertEqual({r["component"]["name"] for r in records},
                             {"app", "flask"})

            # The worker service still fails with a non-zero status.
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = main(
                    ["--database", database, "impact", "--service", "worker"]
                )
            self.assertEqual(status, 1)
            self.assertIn("worker/pypi/flask/not-a-version", stderr.getvalue())


class ImportBehaviorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def test_empty_array_clears_source(self) -> None:
        self.catalog.import_osv("src", [osv_record("CVE-1", versions=["1.0.0"])])
        self.catalog.import_osv("src", [])
        self.catalog.add_component("api", "pypi", "flask", "1.0.0")
        self.assertEqual(self.catalog.impact(), [])

    def test_reimport_replaces_without_accumulation(self) -> None:
        record = osv_record("CVE-1", versions=["1.0.0"])
        self.catalog.import_osv("src", [record])
        self.catalog.import_osv("src", [record])
        self.catalog.add_component("api", "pypi", "flask", "1.0.0")
        self.assertEqual(len(self.catalog.impact()), 1)

    def test_other_sources_and_manual_vulnerabilities_preserved(self) -> None:
        self.catalog.import_osv("a", [osv_record("CVE-1", versions=["1.0.0"])])
        self.catalog.import_osv(
            "b", [osv_record("CVE-2", package="werkzeug", versions=["1.0.0"])]
        )
        self.catalog.add_vulnerability("CVE-3", "flask", "high")
        self.catalog.import_osv("a", [])
        self.catalog.add_component("api", "pypi", "flask", "1.0.0")
        self.catalog.add_component("api", "pypi", "werkzeug", "1.0.0")
        records = self.catalog.impact()
        ids = {r["vulnerability"] for r in records}
        self.assertEqual(ids, {"CVE-2", "CVE-3"})

    def test_duplicate_id_in_file_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_osv(
                "src",
                [
                    osv_record("CVE-1", versions=["1.0.0"]),
                    osv_record("CVE-1", versions=["2.0.0"]),
                ],
            )

    def test_failure_leaves_catalog_unchanged(self) -> None:
        self.catalog.import_osv("src", [osv_record("CVE-1", versions=["1.0.0"])])
        with self.assertRaises(ValueError):
            self.catalog.import_osv(
                "src",
                [
                    osv_record("CVE-2", versions=["1.0.0"]),
                    osv_record("CVE-3", ecosystem="npm"),
                ],
            )
        self.catalog.add_component("api", "pypi", "flask", "1.0.0")
        records = self.catalog.impact()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["vulnerability"], "CVE-1")

    def test_withdrawn_records_do_not_participate(self) -> None:
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    versions=["1.0.0"],
                    withdrawn="2023-01-15T12:00:00Z",
                )
            ],
        )
        self.catalog.add_component("api", "pypi", "flask", "1.0.0")
        self.assertEqual(self.catalog.impact(), [])
        self.assertEqual(self.catalog.summary().vulnerabilities, 0)

    def test_persistence_across_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory, "catalog.db")
            catalog = Catalog(database)
            catalog.import_osv("src", [osv_record("CVE-1", versions=["1.0.0"])])
            catalog.close()
            reopened = Catalog(database)
            reopened.add_component("api", "pypi", "flask", "1.0.0")
            self.assertEqual(len(reopened.impact()), 1)
            reopened.close()

    def test_empty_source_name_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_osv("  ", [])

    def test_records_must_be_array(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_osv("src", {"id": "CVE-1"})


class ImpactAndSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def test_propagation_and_shortest_path(self) -> None:
        self.catalog.add_component("api", "pypi", "app", "1.0.0")
        self.catalog.add_component("api", "pypi", "web", "1.0.0")
        self.catalog.add_component("api", "pypi", "lib", "1.0.0")
        self.catalog.add_dependency("api", "pypi", "app", "1.0.0", "api", "pypi", "web", "1.0.0")
        self.catalog.add_dependency("api", "pypi", "web", "1.0.0", "api", "pypi", "lib", "1.0.0")
        self.catalog.import_osv("src", [osv_record("CVE-1", package="lib", versions=["1.0.0"])])
        records = self.catalog.impact()
        by_name = {r["component"]["name"]: r for r in records}
        self.assertEqual(
            [n["name"] for n in by_name["app"]["path"]], ["app", "web", "lib"]
        )
        self.assertTrue(by_name["lib"]["direct"])
        self.assertFalse(by_name["app"]["direct"])

    def test_per_source_records_and_severity_basis(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1.0.0")
        self.catalog.import_osv(
            "a",
            [osv_record("CVE-1", versions=["1.0.0"], database_specific={"severity": "high"})],
        )
        self.catalog.import_osv("b", [osv_record("CVE-1", versions=["1.0.0"])])
        records = self.catalog.impact()
        self.assertEqual(len(records), 2)
        by_source = {r["source"]: r for r in records}
        self.assertEqual(by_source["a"]["severity"], "high")
        self.assertEqual(by_source["a"]["severity_basis"], "declared")
        self.assertEqual(by_source["b"]["severity"], "medium")
        self.assertEqual(by_source["b"]["severity_basis"], "default")

    def test_same_component_source_id_package_appears_once(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1.5.0")
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    versions=["1.5.0"],
                    ranges=[
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "1.0"}, {"fixed": "2.0"}],
                        }
                    ],
                )
            ],
        )
        records = self.catalog.impact()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["matched_conditions"], ["==1.5.0", ">=1.0,<2.0"])

    def test_fully_open_range_condition_format(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1.0.0")
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-1",
                    ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                )
            ],
        )
        records = self.catalog.impact()
        self.assertEqual(records[0]["matched_conditions"], ["*"])

    def test_manual_and_imported_same_id_counted_separately(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1.0.0")
        self.catalog.add_vulnerability("CVE-1", "flask", "low")
        self.catalog.import_osv("src", [osv_record("CVE-1", versions=["1.0.0"])])
        records = self.catalog.impact()
        self.assertEqual(len(records), 2)
        sources = {r["source"] for r in records}
        self.assertEqual(sources, {None, "src"})
        self.assertEqual(self.catalog.summary().vulnerabilities, 2)

    def test_summary_dedups_by_id_and_normalized_package(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1.0.0")
        self.catalog.import_osv("a", [osv_record("CVE-1", versions=["1.0.0"])])
        self.catalog.import_osv("b", [osv_record("CVE-1", versions=["1.0.0"])])
        self.assertEqual(self.catalog.summary().vulnerabilities, 1)

    def test_summary_counts_only_actual_hits(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1.0.0")
        self.catalog.import_osv(
            "src",
            [
                osv_record("CVE-1", versions=["1.0.0"]),
                osv_record("CVE-2", package="werkzeug", versions=["1.0.0"]),
            ],
        )
        self.assertEqual(self.catalog.summary().vulnerabilities, 1)

    def test_summary_highest_severity_across_all_hits(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1.0.0")
        self.catalog.add_component("api", "pypi", "werkzeug", "1.0.0")
        self.catalog.add_vulnerability("CVE-1", "flask", "medium")
        self.catalog.import_osv(
            "src",
            [
                osv_record(
                    "CVE-2",
                    package="werkzeug",
                    versions=["1.0.0"],
                    database_specific={"severity": "critical"},
                )
            ],
        )
        self.assertEqual(self.catalog.summary().highest_severity, "critical")

    def test_summary_highest_severity_defaults_to_imported(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1.0.0")
        self.catalog.import_osv("src", [osv_record("CVE-1", versions=["1.0.0"])])
        self.assertEqual(self.catalog.summary().highest_severity, "medium")

    def test_impact_filters_still_work(self) -> None:
        self.catalog.add_component("api", "pypi", "app", "1.0.0")
        self.catalog.add_component("other", "npm", "react", "1.0.0")
        self.catalog.import_osv("src", [osv_record("CVE-1", package="app", versions=["1.0.0"])])
        self.assertEqual(len(self.catalog.impact(service="api")), 1)
        self.assertEqual(self.catalog.impact(service="missing"), [])
        records = self.catalog.impact(
            service="api", ecosystem="pypi", name="app", version="1.0.0"
        )
        self.assertEqual(len(records), 1)
        with self.assertRaises(ValueError):
            self.catalog.impact(service="api", name="app")

    def test_impact_order_is_stable_across_reimports(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1.0.0")
        record = osv_record("CVE-1", versions=["1.0.0"])
        self.catalog.import_osv("src", [record])
        first = self.catalog.impact()
        self.catalog.import_osv("src", [record])
        second = self.catalog.impact()
        self.assertEqual(first, second)

    def test_terminal_conditions_follow_the_chosen_path(self) -> None:
        # The same normalized package is directly hit at two versions with
        # different explicit conditions; each dependent's explanation must
        # use the conditions of the terminal component of its own path.
        self.catalog.add_component("api", "pypi", "app", "1.0.0")
        self.catalog.add_component("api", "pypi", "x", "1.0.0")
        self.catalog.add_component("api", "pypi", "y", "1.0.0")
        self.catalog.add_component("api", "pypi", "lib", "1.0.0")
        self.catalog.add_component("api", "pypi", "lib", "2.0.0")
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "x", "1.0.0"
        )
        self.catalog.add_dependency(
            "api", "pypi", "x", "1.0.0", "api", "pypi", "lib", "1.0.0"
        )
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "y", "1.0.0"
        )
        self.catalog.add_dependency(
            "api", "pypi", "y", "1.0.0", "api", "pypi", "lib", "2.0.0"
        )
        self.catalog.import_osv(
            "src",
            [osv_record("CVE-1", package="lib", versions=["1.0.0", "2.0.0"])],
        )
        records = {r["component"]["name"]: r for r in self.catalog.impact()}
        self.assertEqual(
            [n["name"] + n["version"] for n in records["x"]["path"]],
            ["x1.0.0", "lib1.0.0"],
        )
        self.assertEqual(records["x"]["matched_conditions"], ["==1.0.0"])
        self.assertEqual(
            [n["name"] + n["version"] for n in records["y"]["path"]],
            ["y1.0.0", "lib2.0.0"],
        )
        self.assertEqual(records["y"]["matched_conditions"], ["==2.0.0"])
        # app reaches both terminals in two hops; one record, ending at the
        # identity-smallest terminal, with that terminal's conditions only.
        app_records = [
            r for r in self.catalog.impact() if r["component"]["name"] == "app"
        ]
        self.assertEqual(len(app_records), 1)
        self.assertEqual(
            [n["name"] + n["version"] for n in app_records[0]["path"]],
            ["app1.0.0", "x1.0.0", "lib1.0.0"],
        )
        self.assertEqual(app_records[0]["matched_conditions"], ["==1.0.0"])

    def test_output_is_independent_of_registration_order(self) -> None:
        def build(reversed_order: bool):
            catalog = Catalog()
            components = [
                ("api", "pypi", "app", "1.0.0"),
                ("api", "pypi", "x", "1.0.0"),
                ("api", "pypi", "y", "1.0.0"),
                ("api", "pypi", "lib", "1.0.0"),
                ("api", "pypi", "lib", "2.0.0"),
            ]
            dependencies = [
                ("api", "pypi", "app", "1.0.0", "api", "pypi", "x", "1.0.0"),
                ("api", "pypi", "x", "1.0.0", "api", "pypi", "lib", "1.0.0"),
                ("api", "pypi", "app", "1.0.0", "api", "pypi", "y", "1.0.0"),
                ("api", "pypi", "y", "1.0.0", "api", "pypi", "lib", "2.0.0"),
                # Cycle back to app: propagation must still terminate.
                ("api", "pypi", "lib", "1.0.0", "api", "pypi", "app", "1.0.0"),
            ]
            records = [osv_record("CVE-1", package="lib", versions=["1.0.0", "2.0.0"])]
            ordered_components = (
                reversed(components) if reversed_order else components
            )
            for component in ordered_components:
                catalog.add_component(*component)
            ordered_dependencies = (
                reversed(dependencies) if reversed_order else dependencies
            )
            for dependency in ordered_dependencies:
                catalog.add_dependency(*dependency)
            catalog.import_osv("src", records)
            return catalog

        first = build(False)
        second = build(True)
        self.assertEqual(first.impact(), second.impact())
        for record in first.impact():
            identities = [
                (n["service"], n["ecosystem"], n["name"], n["version"])
                for n in record["path"]
            ]
            self.assertEqual(len(identities), len(set(identities)))
        first.close()
        second.close()

    def test_same_id_manual_and_osv_keep_distinct_explanations(self) -> None:
        self.catalog.add_component("api", "pypi", "flask", "1.0.0")
        self.catalog.add_vulnerability("CVE-1", "flask", "high")
        self.catalog.import_osv(
            "src",
            [osv_record(
                "CVE-1",
                versions=["1.0.0"],
                database_specific={"severity": "low"},
            )],
        )
        records = sorted(self.catalog.impact(), key=lambda r: r["source"] or "")
        self.assertEqual(len(records), 2)
        manual, imported = records
        self.assertIsNone(manual["source"])
        self.assertIsNone(manual["severity_basis"])
        self.assertIsNone(manual["matched_conditions"])
        self.assertEqual(manual["severity"], "high")
        self.assertEqual(imported["source"], "src")
        self.assertEqual(imported["severity_basis"], "declared")
        self.assertEqual(imported["matched_conditions"], ["==1.0.0"])
        self.assertEqual(imported["severity"], "low")


class CliTests(unittest.TestCase):
    def test_import_osv_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            path = Path(directory, "osv.json")
            path.write_text(osv_file([osv_record("CVE-1", versions=["1.0.0"])]))
            self.assertEqual(
                main(["--database", database, "import-osv", "src", str(path)]), 0
            )

    def test_missing_file_returns_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            self.assertEqual(
                main(
                    [
                        "--database",
                        database,
                        "import-osv",
                        "src",
                        str(Path(directory, "missing.json")),
                    ]
                ),
                1,
            )

    def test_invalid_json_returns_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            path = Path(directory, "bad.json")
            path.write_text("{not json")
            self.assertEqual(
                main(["--database", database, "import-osv", "src", str(path)]), 1
            )

    def test_validation_error_returns_nonzero_and_preserves_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            good = Path(directory, "good.json")
            good.write_text(osv_file([osv_record("CVE-1", versions=["1.0.0"])]))
            bad = Path(directory, "bad.json")
            bad.write_text(
                osv_file(
                    [
                        osv_record("CVE-2", versions=["1.0.0"]),
                        osv_record("CVE-3", ecosystem="npm"),
                    ]
                )
            )
            self.assertEqual(
                main(["--database", database, "import-osv", "src", str(good)]), 0
            )
            self.assertEqual(
                main(["--database", database, "import-osv", "src", str(bad)]), 1
            )
            catalog = Catalog(database)
            catalog.add_component("api", "pypi", "flask", "1.0.0")
            records = catalog.impact()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["vulnerability"], "CVE-1")
            catalog.close()

    def test_repeated_import_does_not_accumulate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            path = Path(directory, "osv.json")
            path.write_text(osv_file([osv_record("CVE-1", versions=["1.0.0"])]))
            for _ in range(2):
                self.assertEqual(
                    main(["--database", database, "import-osv", "src", str(path)]), 0
                )
            catalog = Catalog(database)
            catalog.add_component("api", "pypi", "flask", "1.0.0")
            self.assertEqual(len(catalog.impact()), 1)
            catalog.close()


if __name__ == "__main__":
    unittest.main()
