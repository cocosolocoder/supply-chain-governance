"""Characterization tests for the shared dependency propagation engine.

Manual observations and imported OSV records run through one propagation
implementation. These tests pin the rules that both sources must obey
identically: one record per (component, vulnerability, source, matched
package), shortest paths with identity-based tie breaks, order
independence, cycle safety, and hit details taken from the path's own
terminal component.
"""

import unittest

from supply_guard.catalog import Catalog


def osv_record(identifier, package="lib", **affected):
    entry = {"package": {"ecosystem": "PyPI", "name": package}}
    entry.update(affected)
    return {"id": identifier, "affected": [entry]}


class SharedPropagationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def add(self, service, name, version="1.0.0"):
        self.catalog.add_component(service, "pypi", name, version)

    def dep(self, dependent, dependency, service="api",
            dependent_version="1.0.0", dependency_version="1.0.0"):
        self.catalog.add_dependency(
            service, "pypi", dependent, dependent_version,
            service, "pypi", dependency, dependency_version,
        )

    def test_osv_cycle_terminates_without_repeating_components(self) -> None:
        self.add("api", "a")
        self.add("api", "b")
        self.add("api", "c")
        self.dep("a", "b")
        self.dep("b", "c")
        self.dep("c", "a")
        self.catalog.import_osv(
            "nvd", [osv_record("CVE-1", package="c", versions=["1.0.0"])]
        )
        records = self.catalog.impact()
        self.assertEqual({r["component"]["name"] for r in records}, {"a", "b", "c"})
        for record in records:
            names = [node["name"] for node in record["path"]]
            self.assertEqual(names[0], record["component"]["name"])
            self.assertEqual(names[-1], "c")
            self.assertEqual(len(names), len(set(names)))

    def test_diamond_reaches_one_record_for_one_source(self) -> None:
        for name in ("app", "left", "right", "lib"):
            self.add("api", name)
        self.dep("app", "left")
        self.dep("app", "right")
        self.dep("left", "lib")
        self.dep("right", "lib")
        self.catalog.import_osv(
            "nvd", [osv_record("CVE-1", package="lib", versions=["1.0.0"])]
        )
        app_records = [
            record for record in self.catalog.impact()
            if record["component"]["name"] == "app"
        ]
        self.assertEqual(len(app_records), 1)
        record = app_records[0]
        self.assertEqual([node["name"] for node in record["path"]],
                         ["app", "left", "lib"])
        self.assertFalse(record["direct"])
        self.assertEqual(record["matched_conditions"], ["==1.0.0"])

    def test_conditions_come_from_the_selected_terminal_version(self) -> None:
        # app reaches vulnerable package x at 1.0.0 in one hop and at 2.0.0
        # through a longer route; only the one-hop terminal's conditions may
        # be shown.
        self.add("api", "app")
        self.add("api", "mid")
        self.add("api", "x", "1.0.0")
        self.add("api", "x", "2.0.0")
        self.dep("app", "x", dependency_version="1.0.0")
        self.dep("app", "mid")
        self.dep("mid", "x", dependency_version="2.0.0")
        self.catalog.import_osv(
            "nvd",
            [osv_record("CVE-1", package="x", versions=["1.0.0", "2.0.0"])],
        )
        by_component = {
            (r["component"]["name"], r["component"]["version"]): r
            for r in self.catalog.impact()
        }
        self.assertEqual(
            by_component[("x", "1.0.0")]["matched_conditions"], ["==1.0.0"]
        )
        self.assertEqual(
            by_component[("x", "2.0.0")]["matched_conditions"], ["==2.0.0"]
        )
        app = by_component[("app", "1.0.0")]
        self.assertEqual(
            [(n["name"], n["version"]) for n in app["path"]],
            [("app", "1.0.0"), ("x", "1.0.0")],
        )
        self.assertEqual(app["matched_conditions"], ["==1.0.0"])

        # Mirror topology: the short route now ends at 2.0.0 instead.
        other = Catalog()
        for name in ("app", "mid"):
            other.add_component("api", "pypi", name, "1.0.0")
        other.add_component("api", "pypi", "x", "1.0.0")
        other.add_component("api", "pypi", "x", "2.0.0")
        other.add_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "x", "2.0.0"
        )
        other.add_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "mid", "1.0.0"
        )
        other.add_dependency(
            "api", "pypi", "mid", "1.0.0", "api", "pypi", "x", "1.0.0"
        )
        other.import_osv(
            "nvd",
            [osv_record("CVE-1", package="x", versions=["1.0.0", "2.0.0"])],
        )
        app_other = next(
            r for r in other.impact() if r["component"]["name"] == "app"
        )
        self.assertEqual(
            [(n["name"], n["version"]) for n in app_other["path"]],
            [("app", "1.0.0"), ("x", "2.0.0")],
        )
        self.assertEqual(app_other["matched_conditions"], ["==2.0.0"])
        other.close()

    def test_same_id_from_two_osv_sources_and_manual_stays_separate(self) -> None:
        self.add("api", "flask")
        self.catalog.add_vulnerability("CVE-1", "flask", "high")
        self.catalog.import_osv(
            "a", [osv_record("CVE-1", package="flask", versions=["1.0.0"])]
        )
        self.catalog.import_osv(
            "b", [osv_record("CVE-1", package="flask", versions=["1.0.0"])]
        )
        records = self.catalog.impact()
        self.assertEqual(len(records), 3)
        by_source = {r["source"]: r for r in records}
        self.assertIsNone(by_source[None]["severity_basis"])
        self.assertIsNone(by_source[None]["matched_conditions"])
        self.assertEqual(by_source["a"]["source"], "a")
        self.assertEqual(by_source["b"]["source"], "b")
        # The manual observation remains the declared high rating while both
        # imported records keep their default-medium basis.
        self.assertEqual(by_source[None]["severity"], "high")
        self.assertEqual(by_source["a"]["severity"], "medium")
        self.assertEqual(by_source["a"]["severity_basis"], "default")
        self.assertEqual(by_source["b"]["severity_basis"], "default")

    def test_manual_and_osv_outputs_are_independent_of_insert_order(self) -> None:
        def build(reverse_edges: bool) -> Catalog:
            catalog = Catalog()
            for service, name, version in [
                ("api", "app", "1.0.0"),
                ("api", "web", "1.0.0"),
                ("api", "lib", "1.0.0"),
                ("api", "lib", "2.0.0"),
            ]:
                catalog.add_component(service, "pypi", name, version)
            edges = [
                ("app", "1.0.0", "web", "1.0.0"),
                ("web", "1.0.0", "lib", "1.0.0"),
                ("app", "1.0.0", "lib", "2.0.0"),
            ]
            for dependent, dv, dependency, uv in (
                reversed(edges) if reverse_edges else edges
            ):
                catalog.add_dependency(
                    "api", "pypi", dependent, dv,
                    "api", "pypi", dependency, uv,
                )
            catalog.add_vulnerability("CVE-MAN", "lib", "high")
            catalog.import_osv(
                "nvd",
                [osv_record("CVE-OSV", package="lib",
                            versions=["1.0.0", "2.0.0"])],
            )
            return catalog

        first = build(False)
        second = build(True)
        self.assertEqual(first.impact(), second.impact())
        # One route per (vulnerability, source) even though lib has two hit
        # versions and app reaches both.
        app_records = [
            r for r in first.impact() if r["component"]["name"] == "app"
        ]
        self.assertEqual({(r["vulnerability"], r["source"]) for r in app_records},
                         {("CVE-MAN", None), ("CVE-OSV", "nvd")})
        first.close()
        second.close()


if __name__ == "__main__":
    unittest.main()
