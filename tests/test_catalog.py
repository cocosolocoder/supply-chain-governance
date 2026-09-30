import tempfile
import unittest
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard.cli import render_summary


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


if __name__ == "__main__":
    unittest.main()
