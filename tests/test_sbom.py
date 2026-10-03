import json
import tempfile
import unittest
from pathlib import Path

from supply_guard.catalog import Catalog, ImportResult, parse_purl
from supply_guard.cli import main


def sbom(components, dependencies=None, metadata=None):
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": components,
    }
    if dependencies is not None:
        document["dependencies"] = dependencies
    if metadata is not None:
        document["metadata"] = metadata
    return document


def component(ref, purl, **extra):
    entry = {"bom-ref": ref, "purl": purl}
    entry.update(extra)
    return entry


class PurlParsingTests(unittest.TestCase):
    def test_pypi(self) -> None:
        self.assertEqual(parse_purl("pkg:pypi/django@4.0.0"), ("pypi", "django", "4.0.0"))

    def test_npm_unscoped(self) -> None:
        self.assertEqual(parse_purl("pkg:npm/react@18.3.1"), ("npm", "react", "18.3.1"))

    def test_npm_scoped(self) -> None:
        self.assertEqual(
            parse_purl("pkg:npm/%40scope/pkg@1.0.0"), ("npm", "@scope/pkg", "1.0.0")
        )

    def test_percent_encoding_restored(self) -> None:
        self.assertEqual(
            parse_purl("pkg:pypi/my%2Dpkg@1%2E0%2E0"), ("pypi", "my-pkg", "1.0.0")
        )

    def test_type_is_case_insensitive(self) -> None:
        self.assertEqual(parse_purl("pkg:PyPI/foo@1"), ("pypi", "foo", "1"))

    def test_missing_version_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_purl("pkg:pypi/foo")

    def test_unsupported_ecosystem_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_purl("pkg:maven/org.example/foo@1.0")

    def test_malformed_rejected(self) -> None:
        for bad in ("not-a-purl", "pkg:", "pkg:pypi/", "pkg:pypi/foo@", "pkg:pypi/@1"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    parse_purl(bad)

    def test_pypi_namespace_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_purl("pkg:pypi/namespace/foo@1")


class ImportValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def test_basic_import_registers_components_and_edges(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [component("a", "pkg:pypi/foo@1"), component("b", "pkg:pypi/bar@2")],
                [{"ref": "a", "dependsOn": ["b"]}],
            ),
        )
        self.assertEqual(result.source_components, 2)
        self.assertEqual(result.added_components, 2)
        self.assertEqual(result.added_dependencies, 1)
        rows = self.catalog.connection.execute(
            "SELECT ecosystem, name, version FROM components WHERE service = 'api'"
        ).fetchall()
        self.assertEqual(
            sorted((r["ecosystem"], r["name"], r["version"]) for r in rows),
            [("pypi", "bar", "2"), ("pypi", "foo", "1")],
        )

    def test_npm_scope_preserved(self) -> None:
        self.catalog.import_sbom(
            "api", "src", sbom([component("a", "pkg:npm/%40scope/pkg@1.0.0")])
        )
        row = self.catalog.connection.execute(
            "SELECT name FROM components WHERE service = 'api'"
        ).fetchone()
        self.assertEqual(row["name"], "@scope/pkg")

    def test_version_field_must_match_purl(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                sbom([component("a", "pkg:pypi/foo@1.0.0", version="2.0.0")]),
            )

    def test_version_field_matching_is_accepted(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            sbom([component("a", "pkg:pypi/foo@1.0.0", version="1.0.0")]),
        )
        self.assertEqual(result.source_components, 1)

    def test_same_identity_different_refs_merge(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [
                    component("a", "pkg:pypi/foo@1"),
                    component("b", "pkg:pypi/foo@1"),
                    component("c", "pkg:pypi/bar@1"),
                ],
                [{"ref": "a", "dependsOn": ["c"]}],
            ),
        )
        # a and b merge into one component; the edge a->c is registered once.
        self.assertEqual(result.source_components, 2)
        self.assertEqual(result.added_components, 2)
        self.assertEqual(result.added_dependencies, 1)

    def test_cycles_are_allowed(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [
                    component("a", "pkg:pypi/foo@1"),
                    component("b", "pkg:pypi/bar@1"),
                ],
                [
                    {"ref": "a", "dependsOn": ["b"]},
                    {"ref": "b", "dependsOn": ["a"]},
                ],
            ),
        )
        self.assertEqual(result.added_dependencies, 2)

    def test_duplicate_relationship_counts_once(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [
                    component("a", "pkg:pypi/foo@1"),
                    component("b", "pkg:pypi/bar@1"),
                ],
                [
                    {"ref": "a", "dependsOn": ["b"]},
                    {"ref": "a", "dependsOn": ["b"]},
                ],
            ),
        )
        self.assertEqual(result.added_dependencies, 1)

    def test_missing_dependencies_means_empty(self) -> None:
        result = self.catalog.import_sbom(
            "api", "src", sbom([component("a", "pkg:pypi/foo@1")])
        )
        self.assertEqual(result.added_dependencies, 0)

    def test_metadata_root_ref_rules(self) -> None:
        # Root ref cannot collide with a component ref.
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                sbom(
                    [component("root", "pkg:pypi/foo@1")],
                    metadata={"component": {"bom-ref": "root"}},
                ),
            )
        # A component cannot depend on the root ref.
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                sbom(
                    [component("a", "pkg:pypi/foo@1")],
                    [{"ref": "a", "dependsOn": ["root"]}],
                    metadata={"component": {"bom-ref": "root"}},
                ),
            )
        # The root's own outgoing edges are not registered.
        result = self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [component("a", "pkg:pypi/foo@1")],
                [{"ref": "root", "dependsOn": ["a"]}],
                metadata={"component": {"bom-ref": "root"}},
            ),
        )
        self.assertEqual(result.added_dependencies, 0)

    def test_rejection_leaves_catalog_unchanged(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            sbom([component("a", "pkg:pypi/foo@1")]),
        )
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                sbom(
                    [component("x", "pkg:pypi/new@1")],
                    [{"ref": "x", "dependsOn": ["ghost"]}],
                ),
            )
        rows = self.catalog.connection.execute(
            "SELECT name FROM components WHERE service = 'api'"
        ).fetchall()
        self.assertEqual([r["name"] for r in rows], ["foo"])

    def test_bomformat_and_specversion(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom("api", "src", {"bomFormat": "Other", "specVersion": "1.5", "components": []})
        with self.assertRaises(ValueError):
            self.catalog.import_sbom("api", "src", {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []})

    def test_components_must_be_array(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api", "src", {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": "nope"}
            )
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api", "src", {"bomFormat": "CycloneDX", "specVersion": "1.5"}
            )

    def test_duplicate_bom_ref_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                sbom(
                    [
                        component("a", "pkg:pypi/foo@1"),
                        component("a", "pkg:pypi/bar@1"),
                    ]
                ),
            )

    def test_empty_bom_ref_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api", "src", sbom([component("", "pkg:pypi/foo@1")])
            )

    def test_nested_components_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                sbom(
                    [
                        component(
                            "a",
                            "pkg:pypi/foo@1",
                            components=[component("b", "pkg:pypi/bar@1")],
                        )
                    ]
                ),
            )

    def test_unknown_dependency_ref_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                sbom(
                    [component("a", "pkg:pypi/foo@1")],
                    [{"ref": "a", "dependsOn": ["ghost"]}],
                ),
            )

    def test_direct_self_dependency_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                sbom(
                    [component("a", "pkg:pypi/foo@1")],
                    [{"ref": "a", "dependsOn": ["a"]}],
                ),
            )

    def test_dependencies_must_be_array(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                sbom([component("a", "pkg:pypi/foo@1")], dependencies="nope"),
            )

    def test_depends_on_must_be_array(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                sbom(
                    [component("a", "pkg:pypi/foo@1")],
                    [{"ref": "a", "dependsOn": "nope"}],
                ),
            )

    def test_unsupported_ecosystem_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api", "src", sbom([component("a", "pkg:maven/foo@1")])
            )

    def test_empty_service_or_source_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom("", "src", sbom([]))
        with self.assertRaises(ValueError):
            self.catalog.import_sbom("api", "  ", sbom([]))


class ImportReplacementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def test_reimport_replaces_source_ownership(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [
                    component("a", "pkg:pypi/foo@1"),
                    component("b", "pkg:pypi/bar@1"),
                ],
                [{"ref": "a", "dependsOn": ["b"]}],
            ),
        )
        result = self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [
                    component("a", "pkg:pypi/foo@1"),
                    component("c", "pkg:pypi/baz@1"),
                ],
                [{"ref": "a", "dependsOn": ["c"]}],
            ),
        )
        self.assertEqual(result.source_components, 2)
        self.assertEqual(result.added_components, 1)
        self.assertEqual(result.deleted_components, 1)
        self.assertEqual(result.added_dependencies, 1)
        self.assertEqual(result.deleted_dependencies, 1)
        names = [
            r["name"]
            for r in self.catalog.connection.execute(
                "SELECT name FROM components WHERE service = 'api'"
            )
        ]
        self.assertEqual(sorted(names), ["baz", "foo"])

    def test_empty_components_clears_source(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            sbom([component("a", "pkg:pypi/foo@1")]),
        )
        result = self.catalog.import_sbom("api", "src", sbom([]))
        self.assertEqual(result.source_components, 0)
        self.assertEqual(result.deleted_components, 1)
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM components").fetchone()[0],
            0,
        )

    def test_reimport_identical_is_idempotent(self) -> None:
        document = sbom(
            [component("a", "pkg:pypi/foo@1"), component("b", "pkg:pypi/bar@1")],
            [{"ref": "a", "dependsOn": ["b"]}],
        )
        first = self.catalog.import_sbom("api", "src", document)
        second = self.catalog.import_sbom("api", "src", document)
        self.assertEqual(second.added_components, 0)
        self.assertEqual(second.deleted_components, 0)
        self.assertEqual(second.added_dependencies, 0)
        self.assertEqual(second.deleted_dependencies, 0)
        self.assertEqual(second.source_components, first.source_components)

    def test_manual_components_survive_source_replacement(self) -> None:
        self.catalog.add_component("api", "pypi", "manual", "1.0.0")
        self.catalog.import_sbom(
            "api",
            "src",
            sbom([component("a", "pkg:pypi/foo@1")]),
        )
        self.catalog.import_sbom("api", "src", sbom([]))
        names = [
            r["name"]
            for r in self.catalog.connection.execute(
                "SELECT name FROM components WHERE service = 'api'"
            )
        ]
        self.assertEqual(names, ["manual"])

    def test_add_component_on_imported_content_makes_it_manual(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            sbom([component("a", "pkg:pypi/foo@1")]),
        )
        self.catalog.add_component("api", "pypi", "foo", "1")
        self.catalog.import_sbom("api", "src", sbom([]))
        names = [
            r["name"]
            for r in self.catalog.connection.execute(
                "SELECT name FROM components WHERE service = 'api'"
            )
        ]
        self.assertEqual(names, ["foo"])

    def test_manual_edges_survive_and_keep_endpoints(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [
                    component("a", "pkg:pypi/foo@1"),
                    component("b", "pkg:pypi/bar@1"),
                ],
                [{"ref": "a", "dependsOn": ["b"]}],
            ),
        )
        self.catalog.add_dependency("api", "pypi", "foo", "1", "api", "pypi", "bar", "1")
        self.catalog.import_sbom("api", "src", sbom([]))
        names = [
            r["name"]
            for r in self.catalog.connection.execute(
                "SELECT name FROM components WHERE service = 'api'"
            )
        ]
        self.assertEqual(sorted(names), ["bar", "foo"])
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM dependencies").fetchone()[0],
            1,
        )

    def test_remove_dependency_revokes_manual_only(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [
                    component("a", "pkg:pypi/foo@1"),
                    component("b", "pkg:pypi/bar@1"),
                ],
                [{"ref": "a", "dependsOn": ["b"]}],
            ),
        )
        self.catalog.add_vulnerability("CVE-1", "bar", "high")
        self.catalog.add_dependency("api", "pypi", "foo", "1", "api", "pypi", "bar", "1")
        self.catalog.remove_dependency("api", "pypi", "foo", "1", "api", "pypi", "bar", "1")
        # The relationship is still declared by the source -> foo still affected.
        self.assertEqual(self.catalog.summary().affected_components, 2)
        # Clearing the source removes the edge.
        self.catalog.import_sbom("api", "src", sbom([]))
        self.assertEqual(self.catalog.summary().affected_components, 0)

    def test_remove_dependency_deletes_endpoints_with_no_remaining_basis(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [
                    component("a", "pkg:pypi/app@1"),
                    component("b", "pkg:pypi/lib@1"),
                ],
                [{"ref": "a", "dependsOn": ["b"]}],
            ),
        )
        self.catalog.add_vulnerability("CVE-1", "lib", "high")
        self.catalog.add_dependency("api", "pypi", "app", "1", "api", "pypi", "lib", "1")
        # The original source withdraws both components and the edge; the
        # manual relationship is then what keeps the endpoints alive.
        self.catalog.import_sbom("api", "src", sbom([]))
        self.assertEqual(self.catalog.summary().components, 2)
        self.catalog.remove_dependency(
            "api", "pypi", "app", "1", "api", "pypi", "lib", "1"
        )
        # The result must be correct immediately, without re-importing: both
        # endpoints leave the catalog and stop producing impact records.
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM components").fetchone()[0],
            0,
        )
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM dependencies").fetchone()[0],
            0,
        )
        summary = self.catalog.summary()
        self.assertEqual(summary.components, 0)
        self.assertEqual(summary.affected_components, 0)
        report = self.catalog.risk_report()
        self.assertEqual(report["impact_count"], 0)
        self.assertEqual(report["unhandled_component_count"], 0)

    def test_remove_dependency_deletes_only_the_unsupported_endpoint(self) -> None:
        # src1 withdraws app and the edge; lib is still declared by src2.
        self.catalog.import_sbom(
            "api",
            "src1",
            sbom(
                [
                    component("a", "pkg:pypi/app@1"),
                    component("b", "pkg:pypi/lib@1"),
                ],
                [{"ref": "a", "dependsOn": ["b"]}],
            ),
        )
        self.catalog.import_sbom(
            "api", "src2", sbom([component("b", "pkg:pypi/lib@1")])
        )
        self.catalog.add_dependency("api", "pypi", "app", "1", "api", "pypi", "lib", "1")
        self.catalog.import_sbom("api", "src1", sbom([component("b", "pkg:pypi/lib@1")]))
        self.catalog.add_vulnerability("CVE-1", "lib", "high")
        self.catalog.remove_dependency(
            "api", "pypi", "app", "1", "api", "pypi", "lib", "1"
        )
        names = sorted(
            r["name"]
            for r in self.catalog.connection.execute("SELECT name FROM components")
        )
        self.assertEqual(names, ["lib"])
        summary = self.catalog.summary()
        self.assertEqual(summary.components, 1)
        # The surviving library still has its direct vulnerability impact.
        self.assertEqual(summary.affected_components, 1)
        (record,) = self.catalog.impact()
        self.assertEqual(record["component"]["name"], "lib")
        self.assertTrue(record["direct"])

    def test_remove_dependency_keeps_endpoint_of_another_manual_edge(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [
                    component("a", "pkg:pypi/app@1"),
                    component("b", "pkg:pypi/lib@1"),
                    component("c", "pkg:pypi/other@1"),
                ],
                [
                    {"ref": "a", "dependsOn": ["b"]},
                    {"ref": "c", "dependsOn": ["b"]},
                ],
            ),
        )
        self.catalog.add_dependency("api", "pypi", "app", "1", "api", "pypi", "lib", "1")
        self.catalog.add_dependency(
            "api", "pypi", "other", "1", "api", "pypi", "lib", "1"
        )
        self.catalog.add_vulnerability("CVE-1", "lib", "high")
        self.catalog.import_sbom("api", "src", sbom([]))
        self.catalog.remove_dependency(
            "api", "pypi", "app", "1", "api", "pypi", "lib", "1"
        )
        # app has no basis left and leaves; lib/other are still joined by the
        # other manual relationship, and the dependency path stays queryable.
        names = sorted(
            r["name"]
            for r in self.catalog.connection.execute("SELECT name FROM components")
        )
        self.assertEqual(names, ["lib", "other"])
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM dependencies").fetchone()[0],
            1,
        )
        by_name = {r["component"]["name"]: r for r in self.catalog.impact()}
        self.assertEqual(set(by_name), {"lib", "other"})
        self.assertEqual(
            [node["name"] for node in by_name["other"]["path"]], ["other", "lib"]
        )

    def test_remove_dependency_respects_full_component_identity(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [
                    component("a", "pkg:pypi/app@1"),
                    component("b", "pkg:pypi/lib@1"),
                ],
                [{"ref": "a", "dependsOn": ["b"]}],
            ),
        )
        # A different version of the same-named library is declared by src2.
        self.catalog.import_sbom(
            "api", "src2", sbom([component("b2", "pkg:pypi/lib@2")])
        )
        # A different service has its own same-named components and edge.
        self.catalog.import_sbom(
            "other",
            "src",
            sbom(
                [
                    component("x", "pkg:pypi/app@1"),
                    component("y", "pkg:pypi/lib@1"),
                ],
                [{"ref": "x", "dependsOn": ["y"]}],
            ),
        )
        self.catalog.add_dependency("api", "pypi", "app", "1", "api", "pypi", "lib", "1")
        self.catalog.add_dependency(
            "other", "pypi", "app", "1", "other", "pypi", "lib", "1"
        )
        self.catalog.import_sbom("api", "src", sbom([]))
        self.catalog.import_sbom("other", "src", sbom([]))
        self.catalog.remove_dependency(
            "api", "pypi", "app", "1", "api", "pypi", "lib", "1"
        )
        api_rows = sorted(
            (r["name"], r["version"])
            for r in self.catalog.connection.execute(
                "SELECT name, version FROM components WHERE service = 'api'"
            )
        )
        other_rows = sorted(
            (r["name"], r["version"])
            for r in self.catalog.connection.execute(
                "SELECT name, version FROM components WHERE service = 'other'"
            )
        )
        # lib@1 leaves with the removed edge; lib@2 and the other service stay.
        self.assertEqual(api_rows, [("lib", "2")])
        self.assertEqual(other_rows, [("app", "1"), ("lib", "1")])

    def test_manual_component_endpoint_survives_relation_removal(self) -> None:
        self.catalog.add_component("api", "pypi", "manual", "1")
        self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [
                    component("a", "pkg:pypi/app@1"),
                    component("b", "pkg:pypi/lib@1"),
                ],
                [{"ref": "a", "dependsOn": ["b"]}],
            ),
        )
        self.catalog.add_dependency(
            "api", "pypi", "manual", "1", "api", "pypi", "app", "1"
        )
        self.catalog.import_sbom("api", "src", sbom([]))
        self.catalog.remove_dependency(
            "api", "pypi", "manual", "1", "api", "pypi", "app", "1"
        )
        names = sorted(
            r["name"]
            for r in self.catalog.connection.execute("SELECT name FROM components")
        )
        # The manually registered component is retained on its own registration.
        self.assertEqual(names, ["manual"])

    def test_remove_dependency_missing_endpoints_is_lenient(self) -> None:
        self.catalog.import_sbom(
            "api", "src", sbom([component("a", "pkg:pypi/solo@1")])
        )
        # Neither endpoint existing, or only one, still succeeds and changes
        # nothing; unrelated components are not cleaned up by the operation.
        self.catalog.remove_dependency(
            "api", "pypi", "ghost", "1", "api", "pypi", "phantom", "1"
        )
        self.catalog.remove_dependency(
            "api", "pypi", "solo", "1", "api", "pypi", "phantom", "1"
        )
        names = [
            r["name"]
            for r in self.catalog.connection.execute("SELECT name FROM components")
        ]
        self.assertEqual(names, ["solo"])
        with self.assertRaises(ValueError):
            self.catalog.remove_dependency(
                "api", "pypi", "solo", "1", "api", "pypi", " ", "1"
            )
        names = [
            r["name"]
            for r in self.catalog.connection.execute("SELECT name FROM components")
        ]
        self.assertEqual(names, ["solo"])

    def test_source_unique_within_service(self) -> None:
        self.catalog.import_sbom(
            "api", "src", sbom([component("a", "pkg:pypi/foo@1")])
        )
        # Same service+source replaces, not duplicates.
        self.catalog.import_sbom(
            "api", "src", sbom([component("b", "pkg:pypi/bar@1")])
        )
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM sources").fetchone()[0],
            1,
        )
        # Same source name, different service is allowed.
        self.catalog.import_sbom(
            "other", "src", sbom([component("c", "pkg:pypi/baz@1")])
        )
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM sources").fetchone()[0],
            2,
        )

    def test_impact_and_summary_reflect_import_immediately(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [
                    component("a", "pkg:pypi/foo@1"),
                    component("b", "pkg:pypi/bar@1"),
                ],
                [{"ref": "a", "dependsOn": ["b"]}],
            ),
        )
        self.catalog.add_vulnerability("CVE-1", "bar", "high")
        summary = self.catalog.summary()
        self.assertEqual(summary.components, 2)
        self.assertEqual(summary.affected_components, 2)
        records = self.catalog.impact()
        self.assertEqual(len(records), 2)


class ImportPersistenceTests(unittest.TestCase):
    def test_ownership_persists_across_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory, "catalog.db")
            catalog = Catalog(database)
            catalog.import_sbom(
                "api",
                "src",
                sbom([component("a", "pkg:pypi/foo@1")]),
            )
            catalog.close()

            reopened = Catalog(database)
            reopened.import_sbom("api", "src", sbom([]))
            self.assertEqual(
                reopened.connection.execute("SELECT COUNT(*) FROM components").fetchone()[0],
                0,
            )
            reopened.close()

    def test_manual_flag_migrates_from_existing_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory, "catalog.db")
            catalog = Catalog(database)
            catalog.add_component("api", "pypi", "legacy", "1.0.0")
            catalog.close()

            reopened = Catalog(database)
            reopened.import_sbom(
                "api",
                "src",
                sbom([component("a", "pkg:pypi/foo@1")]),
            )
            reopened.import_sbom("api", "src", sbom([]))
            names = [
                r["name"]
                for r in reopened.connection.execute(
                    "SELECT name FROM components WHERE service = 'api'"
                )
            ]
            self.assertEqual(names, ["legacy"])
            reopened.close()


class ImportDeterminismTests(unittest.TestCase):
    def test_ref_names_and_order_do_not_change_impact(self) -> None:
        document_a = sbom(
            [
                component("zzz", "pkg:pypi/foo@1"),
                component("aaa", "pkg:pypi/bar@1"),
                component("mmm", "pkg:pypi/baz@1"),
            ],
            [
                {"ref": "zzz", "dependsOn": ["aaa"]},
                {"ref": "aaa", "dependsOn": ["mmm"]},
            ],
        )
        document_b = sbom(
            [
                component("1", "pkg:pypi/baz@1"),
                component("2", "pkg:pypi/foo@1"),
                component("3", "pkg:pypi/bar@1"),
            ],
            [
                {"ref": "2", "dependsOn": ["3"]},
                {"ref": "3", "dependsOn": ["1"]},
            ],
        )
        catalog_a = Catalog()
        catalog_b = Catalog()
        catalog_a.import_sbom("api", "src", document_a)
        catalog_b.import_sbom("api", "src", document_b)
        catalog_a.add_vulnerability("CVE-1", "baz", "high")
        catalog_b.add_vulnerability("CVE-1", "baz", "high")
        self.assertEqual(catalog_a.impact(), catalog_b.impact())
        catalog_a.close()
        catalog_b.close()


class ImportCliTests(unittest.TestCase):
    def test_import_sbom_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            path = Path(directory, "sbom.json")
            path.write_text(
                json.dumps(
                    sbom(
                        [
                            component("a", "pkg:pypi/foo@1"),
                            component("b", "pkg:pypi/bar@1"),
                        ],
                        [{"ref": "a", "dependsOn": ["b"]}],
                    )
                )
            )
            self.assertEqual(
                main(["--database", database, "import-sbom", "api", "src", str(path)]),
                0,
            )

    def test_missing_file_returns_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            self.assertEqual(
                main(
                    [
                        "--database",
                        database,
                        "import-sbom",
                        "api",
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
                main(["--database", database, "import-sbom", "api", "src", str(path)]),
                1,
            )

    def test_validation_error_returns_nonzero_and_preserves_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            good = Path(directory, "good.json")
            good.write_text(
                json.dumps(sbom([component("a", "pkg:pypi/foo@1")]))
            )
            bad = Path(directory, "bad.json")
            bad.write_text(
                json.dumps(
                    sbom(
                        [component("x", "pkg:pypi/new@1")],
                        [{"ref": "x", "dependsOn": ["ghost"]}],
                    )
                )
            )
            self.assertEqual(
                main(["--database", database, "import-sbom", "api", "src", str(good)]),
                0,
            )
            self.assertEqual(
                main(["--database", database, "import-sbom", "api", "src", str(bad)]),
                1,
            )
            catalog = Catalog(database)
            self.assertEqual(
                catalog.connection.execute("SELECT COUNT(*) FROM components").fetchone()[0],
                1,
            )
            catalog.close()


if __name__ == "__main__":
    unittest.main()
