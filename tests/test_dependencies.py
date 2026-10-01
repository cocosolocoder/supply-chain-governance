import json
import tempfile
import unittest
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard.cli import main, render_impact


def identities(records):
    return [
        (
            record.component.service,
            record.component.ecosystem,
            record.component.name,
            record.component.version,
            record.vulnerability.identifier,
            record.vulnerability.component_name,
        )
        for record in records
    ]


class DependencyPropagationTests(unittest.TestCase):
    def test_direct_and_transitive_impact(self) -> None:
        catalog = Catalog()
        catalog.add_component("api", "pypi", "fastapi", "0.115.0")
        catalog.add_component("api", "pypi", "gunicorn", "21.2.0")
        catalog.add_component("api", "pypi", "uvicorn", "0.30.0")
        catalog.add_dependency(
            "api", "pypi", "gunicorn", "21.2.0",
            "api", "pypi", "fastapi", "0.115.0",
        )
        catalog.add_dependency(
            "api", "pypi", "uvicorn", "0.30.0",
            "api", "pypi", "gunicorn", "21.2.0",
        )
        catalog.add_vulnerability("CVE-2026-1", "fastapi", "high")

        records = catalog.impact()
        by_component = {
            (r.component.service, r.component.name, r.component.version): r
            for r in records
        }
        self.assertEqual(
            by_component[("api", "fastapi", "0.115.0")].path,
            (by_component[("api", "fastapi", "0.115.0")].component,),
        )
        self.assertTrue(by_component[("api", "fastapi", "0.115.0")].direct)
        self.assertFalse(by_component[("api", "gunicorn", "21.2.0")].direct)
        self.assertEqual(
            [node.name for node in by_component[("api", "gunicorn", "21.2.0")].path],
            ["gunicorn", "fastapi"],
        )
        self.assertEqual(
            [node.name for node in by_component[("api", "uvicorn", "0.30.0")].path],
            ["uvicorn", "gunicorn", "fastapi"],
        )
        summary = catalog.summary()
        self.assertEqual(summary.affected_components, 3)
        self.assertEqual(summary.vulnerabilities, 1)
        self.assertEqual(summary.highest_severity, "high")
        self.assertEqual(catalog.affected_services(), ["api"])
        catalog.close()

    def test_no_dependencies_keeps_direct_only_behavior(self) -> None:
        catalog = Catalog()
        catalog.add_component("api", "pypi", "urllib3", "2.2.2")
        catalog.add_component("worker", "pypi", "urllib3", "2.2.2")
        catalog.add_vulnerability("CVE-2026-1", "urllib3", "critical")
        records = catalog.impact()
        self.assertEqual(len(records), 2)
        self.assertTrue(all(record.direct for record in records))
        self.assertEqual(catalog.summary().affected_components, 2)
        catalog.close()

    def test_isolated_component_without_vulnerability_unaffected(self) -> None:
        catalog = Catalog()
        catalog.add_component("api", "pypi", "fastapi", "0.115.0")
        catalog.add_component("api", "pypi", "orphan", "1.0.0")
        catalog.add_vulnerability("CVE-2026-1", "fastapi", "medium")
        records = catalog.impact()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].component.name, "fastapi")
        catalog.close()

    def test_cycle_propagates_without_duplicates(self) -> None:
        catalog = Catalog()
        for name in ("a", "b", "c"):
            catalog.add_component("ring", "npm", name, "1.0.0")
        catalog.add_dependency("ring", "npm", "a", "1.0.0", "ring", "npm", "b", "1.0.0")
        catalog.add_dependency("ring", "npm", "b", "1.0.0", "ring", "npm", "c", "1.0.0")
        catalog.add_dependency("ring", "npm", "c", "1.0.0", "ring", "npm", "a", "1.0.0")
        catalog.add_vulnerability("CVE-2026-1", "c", "high")
        records = catalog.impact()
        self.assertEqual(
            sorted((r.component.name, r.direct, len(r.path)) for r in records),
            [("a", False, 3), ("b", False, 2), ("c", True, 1)],
        )
        self.assertEqual(catalog.summary().affected_components, 3)
        self.assertEqual(catalog.summary().vulnerabilities, 1)
        catalog.close()

    def test_converging_paths_keep_shortest_then_lexicographic(self) -> None:
        catalog = Catalog()
        # diamond: top -> {left, right} -> bottom; bottom is directly hit
        for name in ("top", "left", "right", "bottom"):
            catalog.add_component("svc", "pypi", name, "1.0.0")
        catalog.add_dependency("svc", "pypi", "top", "1.0.0", "svc", "pypi", "left", "1.0.0")
        catalog.add_dependency("svc", "pypi", "top", "1.0.0", "svc", "pypi", "right", "1.0.0")
        catalog.add_dependency("svc", "pypi", "left", "1.0.0", "svc", "pypi", "bottom", "1.0.0")
        catalog.add_dependency("svc", "pypi", "right", "1.0.0", "svc", "pypi", "bottom", "1.0.0")
        catalog.add_vulnerability("CVE-2026-1", "bottom", "low")
        records = catalog.impact()
        top_record = next(r for r in records if r.component.name == "top")
        self.assertEqual(
            [node.name for node in top_record.path],
            ["top", "left", "bottom"],  # same length, left < right
        )
        self.assertEqual(catalog.summary().affected_components, 4)
        catalog.close()

    def test_long_chain_single_component_query(self) -> None:
        catalog = Catalog()
        catalog.add_component("svc", "pypi", "lib-0", "1.0.0")
        for index in range(1, 10000):
            catalog.add_component("svc", "pypi", f"lib-{index}", "1.0.0")
            catalog.add_dependency(
                "svc", "pypi", f"lib-{index}", "1.0.0",
                "svc", "pypi", f"lib-{index - 1}", "1.0.0",
            )
        catalog.add_vulnerability("CVE-2026-1", "lib-0", "critical")
        records = catalog.impact("svc", "pypi", "lib-9999", "1.0.0")
        self.assertEqual(len(records), 1)
        self.assertEqual(len(records[0].path), 10000)
        self.assertEqual(records[0].path[0].name, "lib-9999")
        self.assertEqual(records[0].path[-1].name, "lib-0")
        catalog.close()

    def test_same_vulnerability_name_across_versions_deduplicates(self) -> None:
        catalog = Catalog()
        catalog.add_component("api", "pypi", "fastapi", "0.115.0")
        catalog.add_component("api", "pypi", "fastapi", "0.116.0")
        catalog.add_dependency(
            "api", "pypi", "fastapi", "0.116.0",
            "api", "pypi", "fastapi", "0.115.0",
        )
        catalog.add_vulnerability("CVE-2026-1", "fastapi", "high")
        records = catalog.impact()
        # one record per component for the single vulnerability
        self.assertEqual(len(records), 2)
        pairs = {
            (r.component.version, r.direct, tuple(n.version for n in r.path))
            for r in records
        }
        self.assertIn(("0.115.0", True, ("0.115.0",)), pairs)
        self.assertIn(("0.116.0", True, ("0.116.0",)), pairs)
        self.assertEqual(catalog.summary().vulnerabilities, 1)
        catalog.close()


class DependencyValidationTests(unittest.TestCase):
    def test_missing_both_components_rejected(self) -> None:
        catalog = Catalog()
        catalog.add_component("api", "pypi", "fastapi", "0.115.0")
        with self.assertRaises(ValueError):
            catalog.add_dependency(
                "api", "pypi", "fastapi", "0.115.0",
                "api", "pypi", "missing", "1.0.0",
            )
        with self.assertRaises(ValueError):
            catalog.add_dependency(
                "api", "pypi", "missing", "1.0.0",
                "api", "pypi", "fastapi", "0.115.0",
            )
        self.assertEqual(catalog.impact(), [])
        catalog.close()

    def test_cross_service_relationship_rejected(self) -> None:
        catalog = Catalog()
        catalog.add_component("api", "pypi", "fastapi", "0.115.0")
        catalog.add_component("worker", "pypi", "fastapi", "0.115.0")
        with self.assertRaises(ValueError):
            catalog.add_dependency(
                "api", "pypi", "fastapi", "0.115.0",
                "worker", "pypi", "fastapi", "0.115.0",
            )
        self.assertEqual(catalog.impact(), [])
        catalog.close()

    def test_self_dependency_rejected(self) -> None:
        catalog = Catalog()
        catalog.add_component("api", "pypi", "fastapi", "0.115.0")
        with self.assertRaises(ValueError):
            catalog.add_dependency(
                "api", "pypi", "fastapi", "0.115.0",
                "api", "pypi", "fastapi", "0.115.0",
            )
        catalog.close()

    def test_empty_fields_rejected(self) -> None:
        catalog = Catalog()
        catalog.add_component("api", "pypi", "fastapi", "0.115.0")
        with self.assertRaises(ValueError):
            catalog.add_dependency(
                "", "pypi", "fastapi", "0.115.0",
                "api", "pypi", "fastapi", "0.115.0",
            )
        with self.assertRaises(ValueError):
            catalog.add_dependency(
                "api", "pypi", "fastapi", "0.115.0",
                "api", "", "fastapi", "0.115.0",
            )
        catalog.close()

    def test_duplicate_dependency_is_idempotent(self) -> None:
        catalog = Catalog()
        catalog.add_component("api", "pypi", "a", "1.0.0")
        catalog.add_component("api", "pypi", "b", "1.0.0")
        for _ in range(3):
            catalog.add_dependency(
                "api", "pypi", "a", "1.0.0", "api", "pypi", "b", "1.0.0"
            )
        catalog.add_vulnerability("CVE-2026-1", "b", "high")
        self.assertEqual(len(catalog.impact()), 2)
        catalog.close()

    def test_delete_missing_dependency_is_success(self) -> None:
        catalog = Catalog()
        catalog.add_component("api", "pypi", "a", "1.0.0")
        catalog.add_component("api", "pypi", "b", "1.0.0")
        catalog.delete_dependency(
            "api", "pypi", "a", "1.0.0", "api", "pypi", "b", "1.0.0"
        )
        catalog.close()

    def test_delete_dependency_stops_propagation_immediately(self) -> None:
        catalog = Catalog()
        catalog.add_component("api", "pypi", "a", "1.0.0")
        catalog.add_component("api", "pypi", "b", "1.0.0")
        catalog.add_dependency(
            "api", "pypi", "a", "1.0.0", "api", "pypi", "b", "1.0.0"
        )
        catalog.add_vulnerability("CVE-2026-1", "b", "high")
        self.assertEqual(catalog.summary().affected_components, 2)
        catalog.delete_dependency(
            "api", "pypi", "a", "1.0.0", "api", "pypi", "b", "1.0.0"
        )
        self.assertEqual(catalog.summary().affected_components, 1)
        records = catalog.impact()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].component.name, "b")
        catalog.close()

    def test_severity_update_reflected_immediately(self) -> None:
        catalog = Catalog()
        catalog.add_component("api", "pypi", "a", "1.0.0")
        catalog.add_component("api", "pypi", "b", "1.0.0")
        catalog.add_dependency(
            "api", "pypi", "a", "1.0.0", "api", "pypi", "b", "1.0.0"
        )
        catalog.add_vulnerability("CVE-2026-1", "b", "low")
        self.assertEqual(catalog.summary().highest_severity, "low")
        catalog.add_vulnerability("CVE-2026-1", "b", "critical")
        self.assertEqual(catalog.summary().highest_severity, "critical")
        catalog.close()


class PersistenceAndOrderTests(unittest.TestCase):
    def test_dependencies_survive_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory, "catalog.db")
            catalog = Catalog(database)
            catalog.add_component("api", "pypi", "a", "1.0.0")
            catalog.add_component("api", "pypi", "b", "1.0.0")
            catalog.add_dependency(
                "api", "pypi", "a", "1.0.0", "api", "pypi", "b", "1.0.0"
            )
            catalog.add_vulnerability("CVE-2026-1", "b", "high")
            catalog.close()

            reopened = Catalog(database)
            self.assertEqual(reopened.summary().affected_components, 2)
            records = reopened.impact()
            self.assertEqual(len(records), 2)
            self.assertEqual(
                [node.name for node in records[0].path], ["a", "b"]
            )
            reopened.close()

    def test_registration_order_does_not_change_output(self) -> None:
        def build(register) -> list:
            catalog = Catalog()
            register(catalog)
            records = catalog.impact()
            catalog.close()
            return identities(records)

        def order_one(catalog: Catalog) -> None:
            catalog.add_vulnerability("CVE-2026-9", "bottom", "high")
            catalog.add_component("svc", "pypi", "top", "1.0.0")
            catalog.add_component("svc", "pypi", "bottom", "1.0.0")
            catalog.add_dependency(
                "svc", "pypi", "top", "1.0.0", "svc", "pypi", "bottom", "1.0.0"
            )

        def order_two(catalog: Catalog) -> None:
            catalog.add_component("svc", "pypi", "bottom", "1.0.0")
            catalog.add_component("svc", "pypi", "top", "1.0.0")
            catalog.add_dependency(
                "svc", "pypi", "top", "1.0.0", "svc", "pypi", "bottom", "1.0.0"
            )
            catalog.add_vulnerability("CVE-2026-9", "bottom", "high")

        self.assertEqual(build(order_one), build(order_two))


class ImpactFilterTests(unittest.TestCase):
    def test_filter_by_service_and_component(self) -> None:
        catalog = Catalog()
        catalog.add_component("api", "pypi", "fastapi", "0.115.0")
        catalog.add_component("api", "pypi", "gunicorn", "21.2.0")
        catalog.add_component("worker", "pypi", "fastapi", "0.115.0")
        catalog.add_dependency(
            "api", "pypi", "gunicorn", "21.2.0",
            "api", "pypi", "fastapi", "0.115.0",
        )
        catalog.add_vulnerability("CVE-2026-1", "fastapi", "high")

        api_records = catalog.impact(service="api")
        self.assertEqual(
            sorted({r.component.service for r in api_records}), ["api"]
        )
        component_records = catalog.impact("api", "pypi", "gunicorn", "21.2.0")
        self.assertEqual(len(component_records), 1)
        self.assertEqual(component_records[0].path[0].name, "gunicorn")
        self.assertEqual(catalog.impact(service="unknown"), [])
        self.assertEqual(
            catalog.impact("api", "pypi", "missing", "1.0.0"), []
        )
        catalog.close()

    def test_impact_json_shape(self) -> None:
        catalog = Catalog()
        catalog.add_component("api", "pypi", "fastapi", "0.115.0")
        catalog.add_component("api", "pypi", "gunicorn", "21.2.0")
        catalog.add_dependency(
            "api", "pypi", "gunicorn", "21.2.0",
            "api", "pypi", "fastapi", "0.115.0",
        )
        catalog.add_vulnerability("CVE-2026-1", "fastapi", "high")
        payload = json.loads(render_impact(catalog.impact()))
        self.assertEqual(len(payload), 2)
        self.assertEqual(
            [row["service"] for row in payload], ["api", "api"]
        )
        direct = next(row for row in payload if row["name"] == "fastapi")
        indirect = next(row for row in payload if row["name"] == "gunicorn")
        self.assertTrue(direct["direct"])
        self.assertEqual(direct["path"], [
            {"service": "api", "ecosystem": "pypi", "name": "fastapi", "version": "0.115.0"}
        ])
        self.assertFalse(indirect["direct"])
        self.assertEqual(
            [node["name"] for node in indirect["path"]], ["gunicorn", "fastapi"]
        )
        self.assertEqual(indirect["vulnerability_id"], "CVE-2026-1")
        self.assertEqual(indirect["vulnerability_name"], "fastapi")
        self.assertEqual(indirect["severity"], "high")
        catalog.close()


class CliErrorTests(unittest.TestCase):
    def test_invalid_dependency_exits_nonzero_and_keeps_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            self.assertEqual(
                main(["--database", database, "add-component", "api", "pypi", "a", "1.0.0"]),
                0,
            )
            self.assertEqual(
                main(["--database", database, "add-component", "api", "pypi", "b", "1.0.0"]),
                0,
            )
            self.assertNotEqual(
                main([
                    "--database", database, "add-dependency",
                    "api", "pypi", "a", "1.0.0",
                    "api", "pypi", "missing", "1.0.0",
                ]),
                0,
            )
            catalog = Catalog(database)
            self.assertEqual(catalog.impact(), [])
            catalog.close()

    def test_component_filter_requires_full_identity(self) -> None:
        catalog = Catalog()
        with self.assertRaises(ValueError):
            catalog.impact(service="api", name="fastapi")
        catalog.close()


if __name__ == "__main__":
    unittest.main()
