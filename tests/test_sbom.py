import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
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

    def test_percent_encoding_hex_case_insensitive(self) -> None:
        self.assertEqual(
            parse_purl("pkg:pypi/my%2dpkg@1%2e0"), ("pypi", "my-pkg", "1.0")
        )
        self.assertEqual(
            parse_purl("pkg:pypi/my%2dpkg@1%2E0"), ("pypi", "my-pkg", "1.0")
        )

    def test_percent_encoding_decoded_once(self) -> None:
        # %25 restores a literal percent sign that must not be decoded again.
        self.assertEqual(
            parse_purl("pkg:pypi/a%2525b@1"), ("pypi", "a%25b", "1")
        )
        self.assertEqual(
            parse_purl("pkg:pypi/100%25@1%2E0"), ("pypi", "100%", "1.0")
        )

    def test_illegal_percent_escapes_rejected(self) -> None:
        for bad in (
            "pkg:pypi/foo%bar@1",
            "pkg:pypi/foo%A@1",
            "pkg:pypi/foo%GG@1",
            "pkg:pypi/foo%ff@1",
            "pkg:pypi/foo%E4%B8@1",
            "pkg:pypi/foo@1%",
            "pkg:pypi/foo@1%2",
            "pkg:pypi/foo@%GG",
            "pkg:npm/%40sc%GG/pkg@1.0",
            "pkg:npm/%GGscope/pkg@1.0",
            "pkg:%70%79pi/foo@1%FF",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    parse_purl(bad)

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

    def test_bad_percent_escape_names_component_location_and_bomref(self) -> None:
        for bad_purl in (
            "pkg:pypi/foo%bar@1",
            "pkg:pypi/foo%ff@1",
            "pkg:pypi/foo@1%E4%B8",
            "pkg:npm/%GGscope/pkg@1",
        ):
            with self.subTest(bad_purl=bad_purl):
                catalog = Catalog()
                with self.assertRaises(ValueError) as caught:
                    catalog.import_sbom(
                        "api",
                        "src",
                        sbom([component("comp-7", bad_purl)]),
                    )
                message = str(caught.exception)
                self.assertIn("components[0]", message)
                self.assertIn("comp-7", message)
                catalog.close()

    def test_corrupt_purl_fails_whole_import_without_earlier_components(self) -> None:
        # A valid component listed first must not survive a later bad purl.
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                sbom(
                    [
                        component("good", "pkg:pypi/foo@1"),
                        component("bad", "pkg:pypi/bar%ff@1"),
                    ]
                ),
            )
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM components"
            ).fetchone()[0],
            0,
        )

    def test_corrupt_replacement_keeps_previous_source_declaration(self) -> None:
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
        self.catalog.import_sbom(
            "api", "other", sbom([component("c", "pkg:pypi/baz@1")])
        )
        self.catalog.add_component("api", "pypi", "manual", "1")
        self.catalog.add_vulnerability("CVE-1", "bar", "high")

        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                sbom(
                    [
                        component("a2", "pkg:pypi/newpkg@1"),
                        component("bad", "pkg:pypi/broken%E4%B8@1"),
                    ]
                ),
            )

        # The replaced source keeps its original components and dependency.
        rows = self.catalog.connection.execute(
            """
            SELECT c.name, cs.source_id IS NOT NULL AS owned
            FROM components c
            LEFT JOIN sources s ON s.service = 'api' AND s.name = 'src'
            LEFT JOIN component_sources cs
                ON cs.component_id = c.id AND cs.source_id = s.id
            WHERE c.service = 'api'
            ORDER BY c.name
            """
        ).fetchall()
        self.assertEqual(
            [(r["name"], r["owned"]) for r in rows],
            [("bar", 1), ("baz", 0), ("foo", 1), ("manual", 0)],
        )
        edges = self.catalog.connection.execute(
            """
            SELECT d1.name AS dependent, d2.name AS dependency
            FROM dependencies
            JOIN components d1 ON dependent_id = d1.id
            JOIN components d2 ON dependency_id = d2.id
            """
        ).fetchall()
        self.assertEqual(
            [(r["dependent"], r["dependency"]) for r in edges],
            [("foo", "bar")],
        )
        # Queries and the risk report still reflect the pre-import data.
        records = self.catalog.impact()
        self.assertEqual(len(records), 2)
        report = self.catalog.risk_report()
        self.assertEqual(report["impact_count"], 2)
        self.assertEqual(report["unhandled_component_count"], 2)
        self.assertEqual(
            sorted(item["component"]["name"] for item in report["impacts"]),
            ["bar", "foo"],
        )

    def test_other_sources_survive_corrupt_import(self) -> None:
        self.catalog.import_sbom(
            "api", "other", sbom([component("c", "pkg:pypi/baz@1")])
        )
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                sbom([component("bad", "pkg:pypi/broken%GG@1")]),
            )
        names = [
            r["name"]
            for r in self.catalog.connection.execute(
                "SELECT name FROM components WHERE service = 'api'"
            )
        ]
        self.assertEqual(names, ["baz"])


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


class RemoveDependencyCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def test_removing_last_manual_edge_deletes_orphan_endpoints_immediately(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [
                    component("app", "pkg:pypi/app@1.0"),
                    component("lib", "pkg:pypi/lib@1.0"),
                ],
                [{"ref": "app", "dependsOn": ["lib"]}],
            ),
        )
        self.catalog.add_vulnerability("CVE-1", "lib", "high")
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0", "api", "pypi", "lib", "1.0"
        )
        # The source withdraws the components and the edge; the manual
        # registration is the only thing keeping the pair.
        self.catalog.import_sbom("api", "src", sbom([]))
        self.assertEqual(self.catalog.summary().components, 2)

        self.catalog.remove_dependency(
            "api", "pypi", "app", "1.0", "api", "pypi", "lib", "1.0"
        )
        # No second import is needed: the leftovers leave the catalog now.
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM components"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM dependencies"
            ).fetchone()[0],
            0,
        )
        summary = self.catalog.summary()
        self.assertEqual(summary.components, 0)
        self.assertEqual(summary.affected_components, 0)
        self.assertEqual(self.catalog.impact(), [])
        report = self.catalog.risk_report()
        self.assertEqual(report["impact_count"], 0)
        self.assertEqual(report["unhandled_component_count"], 0)

    def test_endpoint_kept_by_another_source_survives_individually(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [
                    component("app", "pkg:pypi/app@1.0"),
                    component("lib", "pkg:pypi/lib@1.0"),
                ],
                [{"ref": "app", "dependsOn": ["lib"]}],
            ),
        )
        # A second source still declares the library.
        self.catalog.import_sbom(
            "api", "vendor", sbom([component("lib2", "pkg:pypi/lib@1.0")])
        )
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0", "api", "pypi", "lib", "1.0"
        )
        self.catalog.import_sbom("api", "src", sbom([]))
        self.catalog.add_vulnerability("CVE-1", "lib", "high")

        self.catalog.remove_dependency(
            "api", "pypi", "app", "1.0", "api", "pypi", "lib", "1.0"
        )
        names = [
            r["name"]
            for r in self.catalog.connection.execute(
                "SELECT name FROM components WHERE service = 'api'"
            )
        ]
        self.assertEqual(names, ["lib"])
        records = self.catalog.impact()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["component"]["name"], "lib")
        self.assertTrue(records[0]["direct"])
        self.assertEqual(self.catalog.summary().components, 1)

    def test_endpoint_of_another_manual_edge_is_kept(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [
                    component("app", "pkg:pypi/app@1.0"),
                    component("lib", "pkg:pypi/lib@1.0"),
                    component("other", "pkg:pypi/other@1.0"),
                ],
                [{"ref": "app", "dependsOn": ["lib"]}],
            ),
        )
        # other -> app and app -> lib are both manually registered.
        self.catalog.add_dependency(
            "api", "pypi", "other", "1.0", "api", "pypi", "app", "1.0"
        )
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0", "api", "pypi", "lib", "1.0"
        )
        self.catalog.import_sbom("api", "src", sbom([]))

        self.catalog.remove_dependency(
            "api", "pypi", "app", "1.0", "api", "pypi", "lib", "1.0"
        )
        names = sorted(
            r["name"]
            for r in self.catalog.connection.execute(
                "SELECT name FROM components WHERE service = 'api'"
            )
        )
        # lib has nothing left; app is still the target of other -> app.
        self.assertEqual(names, ["app", "other"])
        edges = [
            (r["dependent"], r["dependency"])
            for r in self.catalog.connection.execute(
                """
                SELECT d1.name AS dependent, d2.name AS dependency
                FROM dependencies
                JOIN components d1 ON dependent_id = d1.id
                JOIN components d2 ON dependency_id = d2.id
                """
            )
        ]
        self.assertEqual(edges, [("other", "app")])
        # The remaining dependency path is still queryable end to end.
        self.catalog.add_vulnerability("CVE-1", "app", "high")
        by_name = {r["component"]["name"]: r for r in self.catalog.impact()}
        self.assertEqual(sorted(by_name), ["app", "other"])
        self.assertEqual(
            [node["name"] for node in by_name["other"]["path"]],
            ["other", "app"],
        )

    def test_manual_component_registration_blocks_removal(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [
                    component("app", "pkg:pypi/app@1.0"),
                    component("lib", "pkg:pypi/lib@1.0"),
                ],
                [{"ref": "app", "dependsOn": ["lib"]}],
            ),
        )
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0", "api", "pypi", "lib", "1.0"
        )
        # Explicitly registering the app as a manual component keeps it.
        self.catalog.add_component("api", "pypi", "app", "1.0")
        self.catalog.import_sbom("api", "src", sbom([]))

        self.catalog.remove_dependency(
            "api", "pypi", "app", "1.0", "api", "pypi", "lib", "1.0"
        )
        names = sorted(
            r["name"]
            for r in self.catalog.connection.execute(
                "SELECT name FROM components WHERE service = 'api'"
            )
        )
        self.assertEqual(names, ["app"])

    def test_endpoint_cleanup_is_scoped_by_full_identity(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [
                    component("app", "pkg:pypi/app@1.0"),
                    component("lib", "pkg:pypi/lib@1.0"),
                ],
                [{"ref": "app", "dependsOn": ["lib"]}],
            ),
        )
        # Same package name in another service and another version of the same
        # service must be untouched by the removal.
        self.catalog.import_sbom(
            "other", "src", sbom([component("lib2", "pkg:pypi/lib@1.0")])
        )
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0", "api", "pypi", "lib", "1.0"
        )
        self.catalog.import_sbom(
            "api",
            "src",
            sbom([component("libv2", "pkg:pypi/lib@2.0")]),
        )

        self.catalog.remove_dependency(
            "api", "pypi", "app", "1.0", "api", "pypi", "lib", "1.0"
        )
        identities = sorted(
            (r["service"], r["ecosystem"], r["name"], r["version"])
            for r in self.catalog.connection.execute(
                "SELECT service, ecosystem, name, version FROM components"
            )
        )
        self.assertEqual(
            identities,
            [
                ("api", "pypi", "lib", "2.0"),
                ("other", "pypi", "lib", "1.0"),
            ],
        )

    def test_missing_target_succeeds_and_changes_nothing(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [
                    component("app", "pkg:pypi/app@1.0"),
                    component("lib", "pkg:pypi/lib@1.0"),
                ],
                [{"ref": "app", "dependsOn": ["lib"]}],
            ),
        )
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0", "api", "pypi", "lib", "1.0"
        )
        self.catalog.import_sbom("api", "src", sbom([]))
        before = self.catalog.connection.execute(
            "SELECT service, ecosystem, name, version, manual FROM components "
            "ORDER BY service, name"
        ).fetchall()
        # Neither edge nor endpoints exist for this pair.
        self.catalog.remove_dependency(
            "api", "pypi", "app", "1.0", "api", "pypi", "ghost", "1.0"
        )
        after = self.catalog.connection.execute(
            "SELECT service, ecosystem, name, version, manual FROM components "
            "ORDER BY service, name"
        ).fetchall()
        self.assertEqual([tuple(r) for r in before], [tuple(r) for r in after])
        # The unrelated manual-edge endpoints are not swept.
        self.assertEqual(
            sorted(r["name"] for r in after), ["app", "lib"]
        )

    def test_empty_identity_field_errors_without_changing_data(self) -> None:
        self.catalog.add_component("api", "pypi", "app", "1.0")
        self.catalog.add_component("api", "pypi", "lib", "1.0")
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0", "api", "pypi", "lib", "1.0"
        )
        with self.assertRaises(ValueError):
            self.catalog.remove_dependency(
                "api", "pypi", " ", "1.0", "api", "pypi", "lib", "1.0"
            )
        with self.assertRaises(ValueError):
            self.catalog.remove_dependency(
                "api", "pypi", "app", "1.0", "api", "pypi", "lib", " "
            )
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM dependencies"
            ).fetchone()[0],
            1,
        )
        self.assertEqual(self.catalog.summary().components, 2)

    def test_deleting_components_keeps_vulnerability_and_exemption_data(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            sbom(
                [
                    component("app", "pkg:pypi/app@1.0"),
                    component("lib", "pkg:pypi/lib@1.0"),
                ],
                [{"ref": "app", "dependsOn": ["lib"]}],
            ),
        )
        self.catalog.add_vulnerability("CVE-1", "lib", "high")
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0", "api", "pypi", "lib", "1.0"
        )
        expires_at = datetime.now(timezone.utc) + timedelta(days=10)
        self.catalog.request_exemption(
            "EXM-2026-001",
            "api", "pypi", "lib", "1.0",
            "CVE-1", "lib", None,
            applicant="alice",
            reason="mitigated by egress proxy",
            expires_at=expires_at,
        )
        self.catalog.import_sbom("api", "src", sbom([]))
        self.catalog.remove_dependency(
            "api", "pypi", "app", "1.0", "api", "pypi", "lib", "1.0"
        )
        # The components and impact records are gone.
        self.assertEqual(self.catalog.summary().components, 0)
        self.assertEqual(self.catalog.impact(), [])
        # But the vulnerability observation and the exemption with its history
        # remain queryable by their original ids.
        request = self.catalog.get_exemption("EXM-2026-001")
        self.assertEqual(request["status"], "pending")
        self.assertEqual(
            [event["action"] for event in request["events"]], ["request"]
        )
        observation = self.catalog.connection.execute(
            "SELECT id, component_name, severity FROM vulnerabilities"
        ).fetchone()
        self.assertEqual(
            tuple(observation), ("CVE-1", "lib", "high")
        )


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

    def test_corrupt_percent_escape_returns_nonzero_without_success_stats(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            good = Path(directory, "good.json")
            good.write_text(
                json.dumps(sbom([component("a", "pkg:pypi/foo@1")]))
            )
            bad = Path(directory, "bad.json")
            bad.write_text(
                json.dumps(sbom([component("ref-bad", "pkg:pypi/bar%ff@1")]))
            )
            self.assertEqual(
                main(["--database", database, "import-sbom", "api", "src", str(good)]),
                0,
            )
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = main(
                    ["--database", database, "import-sbom", "api", "src", str(bad)]
                )
            self.assertEqual(status, 1)
            # No success statistics are printed on failure.
            self.assertNotIn("来源组件数", stdout.getvalue())
            # The error names the component location and its bom-ref.
            self.assertIn("components[0]", stderr.getvalue())
            self.assertIn("ref-bad", stderr.getvalue())
            catalog = Catalog(database)
            names = [
                r["name"]
                for r in catalog.connection.execute(
                    "SELECT name FROM components WHERE service = 'api'"
                )
            ]
            self.assertEqual(names, ["foo"])
            catalog.close()


if __name__ == "__main__":
    unittest.main()
