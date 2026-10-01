import json
import tempfile
import unittest
from pathlib import Path

from supply_guard.catalog import (
    Catalog,
    InvalidVersion,
    normalize_pypi_name,
    parse_pep440,
)
from supply_guard.cli import main


def osv(vid, affected, database_specific=None, withdrawn=None):
    record = {"id": vid, "affected": affected}
    if database_specific is not None:
        record["database_specific"] = database_specific
    if withdrawn is not None:
        record["withdrawn"] = withdrawn
    return record


def affected(name, ecosystem="PyPI", versions=None, ranges=None):
    entry = {"package": {"ecosystem": ecosystem, "name": name}}
    if versions is not None:
        entry["versions"] = versions
    if ranges is not None:
        entry["ranges"] = ranges
    return entry


def range_(*events, range_type="ECOSYSTEM"):
    return {
        "type": range_type,
        "events": [{kind: value} for kind, value in events],
    }


class Pep440Tests(unittest.TestCase):
    def test_equivalent_versions_compare_equal(self) -> None:
        for left, right in (
            ("1.0", "1.0.0"),
            ("1.0a1", "1.0.alpha1"),
            ("1.0rc1", "1.0c1"),
            ("1.0.post1", "1.0-1"),
        ):
            self.assertEqual(parse_pep440(left), parse_pep440(right))

    def test_local_versions_participate_and_stay_distinct(self) -> None:
        # Local versions are ordered but differing local labels are not equal.
        self.assertNotEqual(parse_pep440("1.0+a"), parse_pep440("1.0+b"))
        self.assertEqual(parse_pep440("1.0"), parse_pep440("1.0.0"))
        self.assertLess(parse_pep440("1.0"), parse_pep440("1.0+local"))
        self.assertLess(parse_pep440("1.0a1"), parse_pep440("1.0"))
        self.assertLess(parse_pep440("1.0.dev1"), parse_pep440("1.0a1"))

    def test_invalid_versions_raise(self) -> None:
        for bad in ("", "   ", "abc", "1..0", "1.0+", "v"):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidVersion):
                    parse_pep440(bad)

    def test_name_normalization(self) -> None:
        self.assertEqual(
            normalize_pypi_name("Foo_Bar.baz--QUX"),
            normalize_pypi_name("foo-bar-baz-qux"),
        )


class OsvValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()
        self.catalog.add_component("svc", "pypi", "pkg", "1.0.0")

    def tearDown(self) -> None:
        self.catalog.close()

    def import_bad(self, document):
        with self.assertRaises(ValueError):
            self.catalog.import_osv("adv", document)

    def test_document_must_be_array(self) -> None:
        self.import_bad({})
        self.import_bad("nope")

    def test_id_must_be_non_empty(self) -> None:
        self.import_bad([osv("  ", [affected("pkg", versions=["1.0"])])])
        self.import_bad([{"affected": []}])

    def test_severity_choices_and_default(self) -> None:
        for severity in ("low", "medium", "high", "critical"):
            self.assertEqual(
                self.catalog.import_osv(
                    f"s-{severity}",
                    [osv("V", [affected("pkg", versions=["1.0"])],
                         {"severity": severity.upper()})],
                ),
                1,
            )
        self.import_bad(
            [osv("V", [affected("pkg", versions=["1.0"])], {"severity": "urgent"})]
        )

    def test_other_ecosystem_rejected(self) -> None:
        self.import_bad([osv("V", [affected("pkg", ecosystem="npm", versions=["1.0"])])])
        self.import_bad([osv("V", [affected("pkg", ecosystem="Go", versions=["1.0"])])])

    def test_other_range_types_rejected(self) -> None:
        self.import_bad(
            [osv("V", [affected("pkg", ranges=[range_(("introduced", "0"), range_type="GIT")])])]
        )
        self.import_bad(
            [osv("V", [affected("pkg", ranges=[range_(("introduced", "0"), range_type="SEMVER")])])]
        )

    def test_unsupported_events_rejected(self) -> None:
        self.import_bad([osv("V", [{
            "package": {"ecosystem": "PyPI", "name": "pkg"},
            "ranges": [{"type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"git_commit": "abc"}]}],
        }])])

    def test_event_value_must_be_version(self) -> None:
        self.import_bad(
            [osv("V", [affected("pkg", ranges=[range_(("introduced", "nope"))])])]
        )
        self.import_bad(
            [osv("V", [affected("pkg", ranges=[
                range_(("introduced", "0"), ("fixed", "nope"))])])]
        )

    def test_explicit_versions_must_parse(self) -> None:
        self.import_bad([osv("V", [affected("pkg", versions=["1.0", "garbage"])])])

    def test_no_valid_version_condition_rejected(self) -> None:
        self.import_bad([osv("V", [affected("pkg")])])
        self.import_bad([osv("V", [affected("pkg", ranges=[
            {"type": "ECOSYSTEM", "events": []}])])])

    def test_inverted_interval_rejected(self) -> None:
        self.import_bad([osv("V", [affected("pkg", ranges=[
            range_(("introduced", "2.0"), ("fixed", "1.0"))])])])
        # Equality is also an empty/illegal interval (fixed must be greater).
        self.import_bad([osv("V", [affected("pkg", ranges=[
            range_(("introduced", "1.0"), ("fixed", "1.0"))])])])

    def test_illegal_event_order_rejected(self) -> None:
        self.import_bad([osv("V", [affected("pkg", ranges=[
            range_(("fixed", "1.0"))])])])
        self.import_bad([osv("V", [affected("pkg", ranges=[
            range_(("introduced", "0"), ("introduced", "1.0"))])])])
        self.import_bad([osv("V", [affected("pkg", ranges=[
            range_(("introduced", "0"), ("fixed", "1.0"), ("last_affected", "2.0"))])])])

    def test_withdrawn_must_be_timestamp(self) -> None:
        self.import_bad(
            [osv("V", [affected("pkg", versions=["1.0"])], withdrawn="not-a-date")]
        )

    def test_duplicate_id_in_file_rejected(self) -> None:
        self.import_bad([
            osv("DUP", [affected("pkg", versions=["1.0"])]),
            osv("DUP", [affected("other", versions=["1.0"])]),
        ])

    def test_record_must_be_object(self) -> None:
        self.import_bad(["nope"])

    def test_failed_import_preserves_existing_data(self) -> None:
        self.catalog.import_osv("adv", [osv("KEEP", [affected("pkg", versions=["1.0"])])])
        self.import_bad([osv("BAD", [affected("pkg", ranges=[
            range_(("introduced", "2.0"), ("fixed", "1.0"))])])])
        rows = self.catalog.connection.execute(
            "SELECT vid FROM osv_vulnerabilities"
        ).fetchall()
        self.assertEqual([row["vid"] for row in rows], ["KEEP"])
        self.assertEqual(
            [r["vulnerability"] for r in self.catalog.impact()], ["KEEP"]
        )


class OsvMatchingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()
        versions = ("1.0", "1.5", "2.0", "2.0+ubuntu1", "2.5a1", "3.0", "3.1")
        for version in versions:
            self.catalog.add_component("svc", "pypi", "pkg", version)
        # npm component with the same name must never be a direct hit.
        self.catalog.add_component("svc", "npm", "pkg", "1.5")
        # Different spelling of the same normalized name keeps its identity.
        self.catalog.add_component("svc", "pypi", "P.K_G", "1.2")
        self.catalog.add_component("svc", "pypi", "app", "4.0")
        self.catalog.add_dependency(
            "svc", "pypi", "app", "4.0", "svc", "pypi", "pkg", "1.5"
        )

    def tearDown(self) -> None:
        self.catalog.close()

    def import_v(self, *args, **kwargs):
        self.catalog.import_osv("adv", [osv(*args, **kwargs)])

    def hit_versions(self, vid="V-1"):
        return {
            record["component"]["version"]
            for record in self.catalog.impact()
            if record["vulnerability"] == vid
            and record.get("source") == "adv"
            and record["direct"]
        }

    def test_versions_and_ranges_union_with_boundaries(self) -> None:
        self.import_v(
            "V-1",
            [affected(
                "pkg",
                versions=["2.0+ubuntu1"],
                ranges=[range_(
                    ("introduced", "1.0"), ("fixed", "2.0"),
                    ("introduced", "2.5a1"), ("last_affected", "3.0"),
                )],
            )],
        )
        # [1.0, 2.0): 1.0 and 1.5 hit; 2.0 itself is excluded by fixed.
        # [2.5a1, 3.0]: prerelease 2.5a1 and 3.0 hit; 3.1 is outside.
        # Explicit 2.0+ubuntu1 still hits via the versions union.
        self.assertEqual(
            self.hit_versions(),
            {"1.0", "1.5", "2.5a1", "3.0", "2.0+ubuntu1"},
        )

    def test_open_lower_bound_and_open_ended_range(self) -> None:
        self.import_v(
            "V-1",
            [affected("pkg", ranges=[range_(("introduced", "0"), ("fixed", "2.0"))])],
        )
        self.assertEqual(self.hit_versions(), {"1.0", "1.5"})
        self.catalog.import_osv("adv2", [osv("V-2", [affected(
            "pkg", ranges=[range_(("introduced", "3.0"))])])])
        self.assertEqual(
            {r["component"]["version"] for r in self.catalog.impact()
             if r["vulnerability"] == "V-2" and r["direct"]},
            {"3.0", "3.1"},
        )

    def test_reintroduced_after_fix(self) -> None:
        self.import_v(
            "V-1",
            [affected("pkg", ranges=[range_(
                ("introduced", "0"), ("fixed", "1.5"),
                ("introduced", "3.0"),
            )])],
        )
        self.assertEqual(self.hit_versions(), {"1.0", "3.0", "3.1"})

    def test_name_normalization_and_identity_preserved(self) -> None:
        self.import_v("V-1", [affected("URLLIB_x", versions=["9.9"])])
        self.assertEqual(self.hit_versions(), set())
        self.import_v("V-2", [affected("P.K-G", versions=["1.2.0"])])
        records = [
            record for record in self.catalog.impact()
            if record["vulnerability"] == "V-2"
        ]
        self.assertEqual(len(records), 1)
        # The component keeps its original name/version spelling.
        self.assertEqual(records[0]["component"]["name"], "P.K_G")
        self.assertEqual(records[0]["matched_package"], "p-k-g")

    def test_npm_same_name_is_not_a_direct_hit(self) -> None:
        self.import_v("V-1", [affected("pkg", versions=["1.5"])])
        npm_records = [
            record for record in self.catalog.impact()
            if record["component"]["ecosystem"] == "npm"
        ]
        self.assertEqual(npm_records, [])

    def test_propagation_along_dependencies(self) -> None:
        self.import_v("V-1", [affected("pkg", versions=["1.5"])])
        app = [
            record for record in self.catalog.impact()
            if record["component"]["name"] == "app"
        ]
        self.assertEqual(len(app), 1)
        record = app[0]
        self.assertFalse(record["direct"])
        self.assertEqual(
            [node["name"] for node in record["path"]], ["app", "pkg"]
        )
        self.assertEqual(record["version_condition"], "version:1.5")
        self.assertEqual(record["matched_name"], "pkg")

    def test_default_severity_is_marked_in_basis(self) -> None:
        self.import_v("V-1", [affected("pkg", versions=["1.0"])])
        record = next(
            record for record in self.catalog.impact()
            if record["vulnerability"] == "V-1" and record["direct"]
        )
        self.assertEqual(record["severity"], "medium")
        self.assertTrue(record["severity_defaulted"])
        self.assertIn("默认", record["severity_basis"])

    def test_explicit_severity_basis(self) -> None:
        self.import_v(
            "V-1", [affected("pkg", versions=["1.0"])], {"severity": "critical"}
        )
        record = next(
            record for record in self.catalog.impact()
            if record["vulnerability"] == "V-1" and record["direct"]
        )
        self.assertEqual(record["severity"], "critical")
        self.assertFalse(record["severity_defaulted"])

    def test_withdrawn_record_does_not_affect(self) -> None:
        self.catalog.import_osv("adv", [osv(
            "V-1", [affected("pkg", versions=["1.0"])],
            withdrawn="2026-01-02T03:04:05Z",
        )])
        self.assertEqual(
            [r for r in self.catalog.impact() if r.get("source") == "adv"], []
        )
        self.assertEqual(self.catalog.summary().highest_severity, None)

    def test_unparseable_candidate_version_errors_and_names_component(self) -> None:
        self.catalog.add_component("svc", "pypi", "pkg", "broken-version!!")
        self.import_v("V-1", [affected("pkg", versions=["1.0"])])
        with self.assertRaises(ValueError) as context:
            self.catalog.impact()
        self.assertIn("svc/pypi/pkg/broken-version!!", str(context.exception))
        with self.assertRaises(ValueError):
            self.catalog.summary()

    def test_one_record_per_component_source_vuln_package(self) -> None:
        # Two affected entries with the same normalized package merge into one
        # impact record per component, even when both conditions match.
        self.catalog.import_osv("adv", [osv("V-1", [
            affected("pkg", versions=["1.0"]),
            affected("Pkg", ranges=[range_(("introduced", "0"), ("fixed", "2.0"))]),
        ])])
        direct = [
            record for record in self.catalog.impact()
            if record["vulnerability"] == "V-1" and record["direct"]
        ]
        # Hits: pkg 1.0 (matches both entries, one record) and pkg 1.5; the
        # differently-normalized P.K_G and pkg 2.0 (fixed boundary) do not hit.
        self.assertEqual(
            {record["component"]["version"] for record in direct},
            {"1.0", "1.5"},
        )
        self.assertEqual(len(direct), 2)


class OsvSourceManagementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()
        self.catalog.add_component("svc", "pypi", "pkg", "1.0")
        self.catalog.add_component("svc", "pypi", "other", "1.0")

    def tearDown(self) -> None:
        self.catalog.close()

    def test_reimport_replaces_source(self) -> None:
        self.catalog.import_osv("adv", [
            osv("A", [affected("pkg", versions=["1.0"])]),
            osv("B", [affected("other", versions=["1.0"])]),
        ])
        self.catalog.import_osv("adv", [
            osv("C", [affected("pkg", versions=["1.0"])]),
        ])
        self.assertEqual(
            sorted(
                row["vid"]
                for row in self.catalog.connection.execute(
                    "SELECT vid FROM osv_vulnerabilities"
                )
            ),
            ["C"],
        )

    def test_empty_array_clears_source(self) -> None:
        self.catalog.import_osv("adv", [osv("A", [affected("pkg", versions=["1.0"])])])
        self.assertEqual(self.catalog.import_osv("adv", []), 0)
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM osv_vulnerabilities"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(self.catalog.impact(), [])

    def test_other_sources_and_manual_vulnerabilities_survive(self) -> None:
        self.catalog.import_osv("s1", [osv("A", [affected("pkg", versions=["1.0"])])])
        self.catalog.add_vulnerability("MANUAL", "other", "high")
        self.catalog.import_osv("s2", [osv("B", [affected("other", versions=["1.0"])])])
        self.catalog.import_osv("s1", [])
        vids = {record["vulnerability"] for record in self.catalog.impact()}
        self.assertEqual(vids, {"B", "MANUAL"})

    def test_same_id_in_different_sources_is_independent(self) -> None:
        self.catalog.import_osv("s1", [
            osv("SAME", [affected("pkg", versions=["1.0"])], {"severity": "low"})
        ])
        self.catalog.import_osv("s2", [
            osv("SAME", [affected("pkg", versions=["1.0"])], {"severity": "critical"})
        ])
        records = [
            record for record in self.catalog.impact() if record["vulnerability"] == "SAME"
        ]
        self.assertEqual(len(records), 2)
        self.assertEqual({record["source"] for record in records}, {"s1", "s2"})
        severities = {record["source"]: record["severity"] for record in records}
        self.assertEqual(severities, {"s1": "low", "s2": "critical"})

    def test_blank_source_name_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_osv("  ", [])

    def test_reimport_identical_is_idempotent(self) -> None:
        document = [osv("A", [
            affected("pkg", versions=["1.0"]),
            affected("other", ranges=[range_(("introduced", "0"))]),
        ])]
        self.catalog.import_osv("adv", document)
        first = self.catalog.impact()
        self.catalog.import_osv("adv", document)
        second = self.catalog.impact()
        self.assertEqual(first, second)
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM osv_vulnerabilities"
            ).fetchone()[0],
            1,
        )


class OsvSummaryTests(unittest.TestCase):
    def test_imported_vulns_deduped_by_id_and_normalized_package(self) -> None:
        catalog = Catalog()
        catalog.add_component("svc", "pypi", "pkg", "1.0")
        catalog.add_component("svc", "pypi", "other", "1.0")
        # Same id + normalized package across two affected entries -> one count.
        catalog.import_osv("adv", [osv("V-1", [
            affected("pkg", versions=["1.0"]),
            affected("P.KG", versions=["1.0.0"]),
        ])])
        # Same id, different package -> separate count.
        catalog.import_osv("adv2", [osv("V-1", [affected("other", versions=["1.0"])])])
        # Record that matches nothing is not counted.
        catalog.import_osv("adv3", [osv("V-DEAD", [affected("ghost", versions=["1.0"])])])
        summary = catalog.summary()
        self.assertEqual(summary.vulnerabilities, 2)
        catalog.close()

    def test_manual_and_imported_same_id_counted_separately(self) -> None:
        catalog = Catalog()
        catalog.add_component("svc", "pypi", "pkg", "1.0")
        catalog.add_vulnerability("V-1", "pkg", "low")
        catalog.import_osv(
            "adv", [osv("V-1", [affected("pkg", versions=["1.0"])],
                        {"severity": "critical"})]
        )
        summary = catalog.summary()
        self.assertEqual(summary.vulnerabilities, 2)
        self.assertEqual(summary.highest_severity, "critical")
        catalog.close()


class OsvPersistenceTests(unittest.TestCase):
    def test_import_persists_and_queries_use_current_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory, "catalog.db")
            catalog = Catalog(database)
            catalog.import_osv(
                "adv",
                [osv("V-1", [affected("pkg", ranges=[
                    range_(("introduced", "0"), ("fixed", "2.0"))])])],
            )
            catalog.close()

            reopened = Catalog(database)
            reopened.add_component("svc", "pypi", "pkg", "1.0")
            reopened.close()

            again = Catalog(database)
            self.assertEqual(
                [record["vulnerability"] for record in again.impact()], ["V-1"]
            )
            # Replacing the SBOM state does not lose the imported advisories.
            again.add_component("svc2", "pypi", "pkg", "1.5")
            hits = {record["component"]["service"] for record in again.impact()}
            self.assertEqual(hits, {"svc", "svc2"})
            again.close()


class OsvCliTests(unittest.TestCase):
    def write(self, directory, name, payload):
        path = Path(directory, name)
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_import_osv_command_and_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            path = self.write(directory, "osv.json", [
                osv("V-1", [affected("pkg", versions=["1.0"])])
            ])
            self.assertEqual(
                main(["--database", database, "import-osv", "adv", str(path)]),
                0,
            )

    def test_missing_file_returns_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            self.assertEqual(
                main([
                    "--database", database, "import-osv", "adv",
                    str(Path(directory, "missing.json")),
                ]),
                1,
            )

    def test_bad_json_and_bad_records_return_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            bad_json = Path(directory, "bad.json")
            bad_json.write_text("{not json", encoding="utf-8")
            self.assertEqual(
                main(["--database", database, "import-osv", "adv", str(bad_json)]),
                1,
            )
            bad_record = self.write(directory, "badrec.json", [
                osv("V-1", [affected("pkg", ranges=[
                    range_(("introduced", "2.0"), ("fixed", "1.0"))])])
            ])
            self.assertEqual(
                main(["--database", database, "import-osv", "adv", str(bad_record)]),
                1,
            )
            catalog = Catalog(database)
            self.assertEqual(
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM osv_vulnerabilities"
                ).fetchone()[0],
                0,
            )
            catalog.close()


if __name__ == "__main__":
    unittest.main()
