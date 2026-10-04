import json
import tempfile
import unittest
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard.cli import main, render_summary


class CatalogTests(unittest.TestCase):
    def test_catalog_persists_and_reports_affected_services(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory, "catalog.db")
            catalog = Catalog(database)
            catalog.add_component("api", "pypi", "urllib3", "2.2.2")
            catalog.add_component("worker", "pypi", "urllib3", "2.2.2")
            catalog.add_vulnerability("CVE-2026-1", "urllib3", "critical")
            self.assertEqual(catalog.affected_services(), ["api", "worker"])
            self.assertEqual(catalog.summary().affected_components, 2)
            catalog.close()

            reopened = Catalog(database)
            self.assertEqual(reopened.summary().highest_severity, "critical")
            reopened.close()

    def test_repeated_component_and_vulnerability_are_idempotent(self) -> None:
        catalog = Catalog()
        for _ in range(2):
            catalog.add_component("api", "pypi", "fastapi", "0.115.0")
            catalog.add_vulnerability("CVE-2026-2", "fastapi", "high")
        catalog.add_component("portal", "npm", "react", "18.3.1")
        summary = catalog.summary()
        self.assertEqual(summary.components, 2)
        self.assertEqual(summary.affected_components, 1)
        self.assertEqual(summary.vulnerabilities, 1)
        catalog.close()

    def test_summary_is_deterministic_for_empty_catalog(self) -> None:
        catalog = Catalog()
        self.assertIn("最高风险: none", render_summary(catalog))
        self.assertEqual(catalog.affected_services(), [])
        catalog.close()


class DependencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def add_chain(self, *names: str) -> None:
        for name in names:
            self.catalog.add_component("api", "pypi", name, "1.0.0")
        for upstream, downstream in zip(names, names[1:]):
            self.catalog.add_dependency(
                "api", "pypi", upstream, "1.0.0",
                "api", "pypi", downstream, "1.0.0",
            )

    def test_impact_propagates_along_dependencies(self) -> None:
        self.add_chain("app", "web", "lib")
        self.catalog.add_component("api", "pypi", "solo", "1.0.0")
        self.catalog.add_vulnerability("CVE-1", "lib", "high")
        summary = self.catalog.summary()
        self.assertEqual(summary.components, 4)
        self.assertEqual(summary.affected_components, 3)
        self.assertEqual(summary.vulnerabilities, 1)
        self.assertEqual(summary.highest_severity, "high")
        self.assertEqual(self.catalog.affected_services(), ["api"])

    def test_impact_records_include_paths_and_direct_flag(self) -> None:
        self.add_chain("app", "web", "lib")
        self.catalog.add_vulnerability("CVE-1", "lib", "high")
        records = self.catalog.impact()
        self.assertEqual(len(records), 3)
        by_name = {record["component"]["name"]: record for record in records}
        direct = by_name["lib"]
        self.assertTrue(direct["direct"])
        self.assertEqual([node["name"] for node in direct["path"]], ["lib"])
        indirect = by_name["app"]
        self.assertFalse(indirect["direct"])
        self.assertEqual(
            [node["name"] for node in indirect["path"]], ["app", "web", "lib"]
        )
        self.assertEqual(indirect["vulnerability"], "CVE-1")
        self.assertEqual(indirect["matched_name"], "lib")
        self.assertEqual(indirect["severity"], "high")

    def test_dependencies_persist_across_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory, "catalog.db")
            catalog = Catalog(database)
            catalog.add_component("api", "pypi", "app", "1.0.0")
            catalog.add_component("api", "pypi", "lib", "1.0.0")
            catalog.add_dependency(
                "api", "pypi", "app", "1.0.0", "api", "pypi", "lib", "1.0.0"
            )
            catalog.add_vulnerability("CVE-1", "lib", "low")
            catalog.close()

            reopened = Catalog(database)
            self.assertEqual(reopened.summary().affected_components, 2)
            reopened.close()

    def test_duplicate_dependency_is_idempotent_and_remove_is_lenient(self) -> None:
        self.add_chain("app", "lib")
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "lib", "1.0.0"
        )
        self.catalog.add_vulnerability("CVE-1", "lib", "low")
        self.assertEqual(self.catalog.summary().affected_components, 2)
        self.catalog.remove_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "lib", "1.0.0"
        )
        self.catalog.remove_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "lib", "1.0.0"
        )
        self.assertEqual(self.catalog.summary().affected_components, 1)

    def test_dependency_validation_errors(self) -> None:
        self.catalog.add_component("api", "pypi", "app", "1.0.0")
        self.catalog.add_component("api", "pypi", "lib", "1.0.0")
        self.catalog.add_component("other", "pypi", "lib", "1.0.0")
        with self.assertRaises(ValueError):
            self.catalog.add_dependency(
                "api", "pypi", "app", "1.0.0", "api", "pypi", "ghost", "1.0.0"
            )
        with self.assertRaises(ValueError):
            self.catalog.add_dependency(
                "api", "pypi", "app", "1.0.0", "other", "pypi", "lib", "1.0.0"
            )
        with self.assertRaises(ValueError):
            self.catalog.add_dependency(
                "api", "pypi", "app", "1.0.0", "api", "pypi", "app", "1.0.0"
            )
        with self.assertRaises(ValueError):
            self.catalog.add_dependency(
                "api", "pypi", "app", "1.0.0", "api", "pypi", "lib", " "
            )
        self.assertEqual(self.catalog.summary().affected_components, 0)

    def test_cycles_do_not_break_propagation(self) -> None:
        self.add_chain("a", "b", "c")
        self.catalog.add_dependency(
            "api", "pypi", "c", "1.0.0", "api", "pypi", "a", "1.0.0"
        )
        self.catalog.add_vulnerability("CVE-1", "c", "medium")
        summary = self.catalog.summary()
        self.assertEqual(summary.affected_components, 3)
        records = self.catalog.impact()
        self.assertEqual(len(records), 3)
        for record in records:
            names = [node["name"] for node in record["path"]]
            self.assertEqual(names[0], record["component"]["name"])
            self.assertEqual(names[-1], "c")
            self.assertEqual(len(names), len(set(names)))

    def test_shortest_path_wins_and_ties_break_by_identity(self) -> None:
        for name in ("app", "fast", "slow1", "slow2", "lib"):
            self.catalog.add_component("api", "pypi", name, "1.0.0")
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "fast", "1.0.0"
        )
        self.catalog.add_dependency(
            "api", "pypi", "fast", "1.0.0", "api", "pypi", "lib", "1.0.0"
        )
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "slow1", "1.0.0"
        )
        self.catalog.add_dependency(
            "api", "pypi", "slow1", "1.0.0", "api", "pypi", "slow2", "1.0.0"
        )
        self.catalog.add_dependency(
            "api", "pypi", "slow2", "1.0.0", "api", "pypi", "lib", "1.0.0"
        )
        self.catalog.add_vulnerability("CVE-1", "lib", "low")
        (record,) = [
            record
            for record in self.catalog.impact()
            if record["component"]["name"] == "app"
        ]
        self.assertEqual(
            [node["name"] for node in record["path"]], ["app", "fast", "lib"]
        )

    def test_same_vulnerability_hit_by_multiple_components_yields_one_record(self) -> None:
        self.catalog.add_component("api", "pypi", "app", "1.0.0")
        self.catalog.add_component("api", "pypi", "lib", "1.0.0")
        self.catalog.add_component("api", "pypi", "lib", "2.0.0")
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "lib", "2.0.0"
        )
        self.catalog.add_vulnerability("CVE-1", "lib", "high")
        records = [
            record
            for record in self.catalog.impact()
            if record["component"]["name"] == "app"
        ]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["path"][-1]["version"], "2.0.0")
        self.assertEqual(self.catalog.summary().affected_components, 3)
        self.assertEqual(self.catalog.summary().vulnerabilities, 1)

    def test_impact_filters_by_service_and_identity(self) -> None:
        self.add_chain("app", "lib")
        self.catalog.add_component("other", "npm", "tool", "1.0.0")
        self.catalog.add_vulnerability("CVE-1", "lib", "low")
        self.catalog.add_vulnerability("CVE-2", "tool", "critical")
        self.assertEqual(len(self.catalog.impact(service="api")), 2)
        self.assertEqual(self.catalog.impact(service="missing"), [])
        self.assertEqual(
            self.catalog.impact(service="api", ecosystem="pypi", name="lib", version="9"),
            [],
        )
        records = self.catalog.impact(
            service="api", ecosystem="pypi", name="app", version="1.0.0"
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["component"]["name"], "app")
        with self.assertRaises(ValueError):
            self.catalog.impact(service="api", name="app")

    def test_long_chain_queries_do_not_overflow(self) -> None:
        depth = 10000
        self.catalog.add_component("api", "pypi", "c0", "1.0.0")
        for index in range(1, depth):
            self.catalog.add_component("api", "pypi", f"c{index}", "1.0.0")
            self.catalog.add_dependency(
                "api", "pypi", f"c{index - 1}", "1.0.0",
                "api", "pypi", f"c{index}", "1.0.0",
            )
        self.catalog.add_vulnerability("CVE-1", f"c{depth - 1}", "low")
        records = self.catalog.impact(
            service="api", ecosystem="pypi", name="c0", version="1.0.0"
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(len(records[0]["path"]), depth)
        # Only the chain tail is hit directly.
        direct = self.catalog.impact(
            service="api",
            ecosystem="pypi",
            name=f"c{depth - 1}",
            version="1.0.0",
        )
        self.assertEqual(len(direct), 1)
        self.assertTrue(direct[0]["direct"])
        self.assertEqual(
            [node["name"] for node in direct[0]["path"]], [f"c{depth - 1}"]
        )

    def test_identity_query_memory_scales_with_graph_and_returned_path(self) -> None:
        # A full-identity query must not materialize the paths of the other
        # (unreturned) affected components: the old implementation built one
        # full path per component per vulnerability group, so a 2000-node
        # chain peaked at hundreds of MB while returning one record. A linear
        # graph query here stays an order of magnitude below that.
        import tracemalloc

        depth = 2000
        self.catalog.add_component("api", "pypi", "c0", "1.0.0")
        for index in range(1, depth):
            self.catalog.add_component("api", "pypi", f"c{index}", "1.0.0")
            self.catalog.add_dependency(
                "api", "pypi", f"c{index - 1}", "1.0.0",
                "api", "pypi", f"c{index}", "1.0.0",
            )
        self.catalog.add_vulnerability("CVE-1", f"c{depth - 1}", "low")

        tracemalloc.start()
        records = self.catalog.impact(
            service="api", ecosystem="pypi", name="c0", version="1.0.0"
        )
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        self.assertEqual(len(records), 1)
        self.assertEqual(len(records[0]["path"]), depth)
        self.assertLess(peak, 25 * 1024 * 1024)

    def test_identity_query_keeps_shortest_path_tie_and_terminal_conditions(self) -> None:
        # Two equal-length routes end at two directly hit versions of the same
        # normalized package; the target's single record follows the
        # identity-smallest route and carries only that terminal's conditions.
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
            [
                {
                    "id": "CVE-1",
                    "affected": [
                        {
                            "package": {"ecosystem": "PyPI", "name": "lib"},
                            "versions": ["1.0.0", "2.0.0"],
                        }
                    ],
                }
            ],
        )
        (record,) = self.catalog.impact(
            service="api", ecosystem="pypi", name="app", version="1.0.0"
        )
        self.assertEqual(
            [node["name"] + node["version"] for node in record["path"]],
            ["app1.0.0", "x1.0.0", "lib1.0.0"],
        )
        self.assertEqual(record["matched_conditions"], ["==1.0.0"])
        # The directly hit terminal gets its own self-only path.
        (terminal,) = self.catalog.impact(
            service="api", ecosystem="pypi", name="lib", version="2.0.0"
        )
        self.assertTrue(terminal["direct"])
        self.assertEqual(terminal["matched_conditions"], ["==2.0.0"])
        self.assertEqual(
            [node["version"] for node in terminal["path"]], ["2.0.0"]
        )

    def test_cli_dependency_commands_and_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            self.assertEqual(
                main(["--database", database, "add-component", "api", "pypi", "app", "1"]),
                0,
            )
            self.assertEqual(
                main(["--database", database, "add-component", "api", "pypi", "lib", "1"]),
                0,
            )
            self.assertEqual(
                main(
                    ["--database", database, "add-dependency",
                     "api", "pypi", "app", "1", "api", "pypi", "lib", "1"]
                ),
                0,
            )
            self.assertEqual(
                main(
                    ["--database", database, "add-dependency",
                     "api", "pypi", "app", "1", "api", "pypi", "ghost", "1"]
                ),
                1,
            )
            self.assertEqual(
                main(["--database", database, "add-vulnerability", "CVE-1", "lib", "high"]),
                0,
            )
            self.assertEqual(
                main(["--database", database, "impact", "--service", "api"]), 0
            )
            self.assertEqual(
                main(
                    ["--database", database, "remove-dependency",
                     "api", "pypi", "app", "1", "api", "pypi", "lib", "1"]
                ),
                0,
            )


if __name__ == "__main__":
    unittest.main()
