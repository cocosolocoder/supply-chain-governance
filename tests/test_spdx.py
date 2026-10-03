import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard.cli import main


def spdx(packages, relationships=None, spdxid="SPDXRef-DOCUMENT", version="SPDX-2.3"):
    document = {
        "spdxVersion": version,
        "SPDXID": spdxid,
        "name": "test-document",
        "documentNamespace": "https://example.com/test",
        "creationInfo": {"creators": ["Tool: test"]},
        "packages": packages,
    }
    if relationships is not None:
        document["relationships"] = relationships
    return document


def package(spdxid, purl, **extra):
    entry = {
        "SPDXID": spdxid,
        "name": spdxid,
        "externalRefs": [
            {
                "referenceType": "purl",
                "referenceLocator": purl,
                "referenceCategory": "PACKAGE-MANAGER",
            }
        ],
    }
    entry.update(extra)
    return entry


def no_purl_package(spdxid, **extra):
    entry = {"SPDXID": spdxid, "name": spdxid}
    entry.update(extra)
    return entry


def relationship(element, relationship_type, related):
    return {
        "spdxElementId": element,
        "relationshipType": relationship_type,
        "relatedSpdxElement": related,
    }


def cdx(components, dependencies=None):
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": components,
    }
    if dependencies is not None:
        document["dependencies"] = dependencies
    return document


def cdx_component(ref, purl):
    return {"bom-ref": ref, "purl": purl}


class SpdxImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def test_basic_import_registers_components_and_edges(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [
                    package("SPDXRef-a", "pkg:pypi/foo@1"),
                    package("SPDXRef-b", "pkg:pypi/bar@2"),
                ],
                [relationship("SPDXRef-a", "DEPENDS_ON", "SPDXRef-b")],
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

    def test_dependency_of_is_reversed(self) -> None:
        # A DEPENDENCY_OF B means B depends on A.
        self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [
                    package("SPDXRef-a", "pkg:pypi/foo@1"),
                    package("SPDXRef-b", "pkg:pypi/bar@2"),
                ],
                [relationship("SPDXRef-a", "DEPENDENCY_OF", "SPDXRef-b")],
            ),
        )
        self.catalog.add_vulnerability("CVE-1", "foo", "high")
        # bar depends on foo, so bar is affected too.
        self.assertEqual(self.catalog.summary().affected_components, 2)
        records = self.catalog.impact(
            service="api", ecosystem="pypi", name="bar", version="2"
        )
        self.assertEqual(len(records), 1)
        self.assertEqual([node["name"] for node in records[0]["path"]], ["bar", "foo"])

    def test_npm_scope_and_percent_decoding(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx([package("SPDXRef-a", "pkg:npm/%40scope/pkg@1%2E0%2E0")]),
        )
        self.assertEqual(result.source_components, 1)
        row = self.catalog.connection.execute(
            "SELECT name, version FROM components WHERE service = 'api'"
        ).fetchone()
        self.assertEqual((row["name"], row["version"]), ("@scope/pkg", "1.0.0"))

    def test_purl_picked_from_other_external_refs(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [
                    package(
                        "SPDXRef-a",
                        "pkg:pypi/foo@1",
                        externalRefs=[
                            {
                                "referenceType": "website",
                                "referenceLocator": "https://example.com",
                            },
                            {
                                "referenceType": "purl",
                                "referenceLocator": "pkg:pypi/foo@1",
                            },
                        ],
                    )
                ]
            ),
        )
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM components"
            ).fetchone()[0],
            1,
        )

    def test_version_info_must_match_purl(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                spdx([package("SPDXRef-a", "pkg:pypi/foo@1.0.0", versionInfo="2.0.0")]),
            )

    def test_version_info_matching_accepted(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx([package("SPDXRef-a", "pkg:pypi/foo@1.0.0", versionInfo="1.0.0")]),
        )
        self.assertEqual(result.source_components, 1)

    def test_version_info_empty_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                spdx([package("SPDXRef-a", "pkg:pypi/foo@1.0.0", versionInfo="")]),
            )

    def test_display_name_not_identity(self) -> None:
        # The purl decides identity; name is ignored for matching.
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [
                    package("SPDXRef-a", "pkg:pypi/foo@1", name="pretty-name"),
                    package("SPDXRef-b", "pkg:pypi/foo@1", name="other-name"),
                ]
            ),
        )
        self.assertEqual(result.source_components, 1)
        names = [
            r["name"]
            for r in self.catalog.connection.execute("SELECT name FROM components")
        ]
        self.assertEqual(names, ["foo"])

    def test_same_identity_different_spdxids_merge(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [
                    package("SPDXRef-a", "pkg:pypi/foo@1"),
                    package("SPDXRef-b", "pkg:pypi/foo@1"),
                    package("SPDXRef-c", "pkg:pypi/bar@1"),
                ],
                [
                    relationship("SPDXRef-a", "DEPENDS_ON", "SPDXRef-c"),
                    relationship("SPDXRef-b", "DEPENDS_ON", "SPDXRef-c"),
                ],
            ),
        )
        self.assertEqual(result.source_components, 2)
        self.assertEqual(result.added_components, 2)
        self.assertEqual(result.added_dependencies, 1)

    def test_equivalent_relationship_directions_count_once(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [
                    package("SPDXRef-a", "pkg:pypi/foo@1"),
                    package("SPDXRef-b", "pkg:pypi/bar@1"),
                ],
                [
                    relationship("SPDXRef-a", "DEPENDS_ON", "SPDXRef-b"),
                    relationship("SPDXRef-b", "DEPENDENCY_OF", "SPDXRef-a"),
                    relationship("SPDXRef-a", "DEPENDS_ON", "SPDXRef-b"),
                ],
            ),
        )
        self.assertEqual(result.added_dependencies, 1)

    def test_cycles_between_packages_allowed(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [
                    package("SPDXRef-a", "pkg:pypi/foo@1"),
                    package("SPDXRef-b", "pkg:pypi/bar@1"),
                ],
                [
                    relationship("SPDXRef-a", "DEPENDS_ON", "SPDXRef-b"),
                    relationship("SPDXRef-b", "DEPENDS_ON", "SPDXRef-a"),
                ],
            ),
        )
        self.assertEqual(result.added_dependencies, 2)

    def test_relationships_default_to_empty(self) -> None:
        result = self.catalog.import_sbom(
            "api", "src", spdx([package("SPDXRef-a", "pkg:pypi/foo@1")])
        )
        self.assertEqual(result.added_dependencies, 0)

    def test_describes_and_other_relations_ignored(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [package("SPDXRef-a", "pkg:pypi/foo@1")],
                [
                    relationship("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-a"),
                    relationship("SPDXRef-a", "CONTAINS", "SPDXRef-ghost"),
                    relationship("SPDXRef-ghost", "PATCH_FOR", "SPDXRef-a"),
                ],
            ),
        )
        self.assertEqual(result.added_dependencies, 0)
        # The document itself is never a component.
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM components WHERE name LIKE '%DOCUMENT%'"
            ).fetchone()[0],
            0,
        )

    def test_empty_packages_clears_source(self) -> None:
        self.catalog.import_sbom(
            "api", "src", spdx([package("SPDXRef-a", "pkg:pypi/foo@1")])
        )
        result = self.catalog.import_sbom("api", "src", spdx([]))
        self.assertEqual(result.source_components, 0)
        self.assertEqual(result.deleted_components, 1)

    def test_reimport_identical_is_idempotent(self) -> None:
        document = spdx(
            [
                package("SPDXRef-a", "pkg:pypi/foo@1"),
                package("SPDXRef-b", "pkg:pypi/bar@1"),
            ],
            [relationship("SPDXRef-a", "DEPENDS_ON", "SPDXRef-b")],
        )
        first = self.catalog.import_sbom("api", "src", document)
        second = self.catalog.import_sbom("api", "src", document)
        self.assertEqual(second.added_components, 0)
        self.assertEqual(second.deleted_components, 0)
        self.assertEqual(second.added_dependencies, 0)
        self.assertEqual(second.deleted_dependencies, 0)
        self.assertEqual(second.source_components, first.source_components)

    def test_order_does_not_change_result(self) -> None:
        document_a = spdx(
            [
                package("SPDXRef-z", "pkg:pypi/foo@1"),
                package("SPDXRef-y", "pkg:pypi/bar@1"),
                package("SPDXRef-x", "pkg:pypi/baz@1"),
            ],
            [
                relationship("SPDXRef-z", "DEPENDS_ON", "SPDXRef-y"),
                relationship("SPDXRef-y", "DEPENDS_ON", "SPDXRef-x"),
            ],
        )
        document_b = spdx(
            [
                package("SPDXRef-1", "pkg:pypi/baz@1"),
                package("SPDXRef-2", "pkg:pypi/foo@1"),
                package("SPDXRef-3", "pkg:pypi/bar@1"),
            ],
            # Relationships may point at packages declared later on.
            [
                relationship("SPDXRef-3", "DEPENDS_ON", "SPDXRef-1"),
                relationship("SPDXRef-2", "DEPENDS_ON", "SPDXRef-3"),
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


class SpdxValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def _reject(self, document):
        with self.assertRaises(ValueError):
            self.catalog.import_sbom("api", "src", document)

    def test_spdx_version(self) -> None:
        self._reject(spdx([], version="SPDX-2.2"))
        self._reject({"SPDXID": "SPDXRef-DOCUMENT", "packages": []})

    def test_packages_required_and_array(self) -> None:
        self._reject({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"})
        self._reject(
            {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": "nope"}
        )

    def test_document_spdxid_required(self) -> None:
        self._reject({"spdxVersion": "SPDX-2.3", "packages": []})
        self._reject({"spdxVersion": "SPDX-2.3", "SPDXID": "", "packages": []})
        self._reject({"spdxVersion": "SPDX-2.3", "SPDXID": 123, "packages": []})

    def test_package_spdxid_rules(self) -> None:
        self._reject(spdx([no_purl_package("")]))
        self._reject(spdx([{"name": "x", "externalRefs": []}]))
        self._reject(
            spdx(
                [
                    package("SPDXRef-a", "pkg:pypi/foo@1"),
                    package("SPDXRef-a", "pkg:pypi/bar@1"),
                ]
            )
        )
        self._reject(
            spdx(
                [package("SPDXRef-DOCUMENT", "pkg:pypi/foo@1")],
                spdxid="SPDXRef-DOCUMENT",
            )
        )

    def test_missing_purl_rejected(self) -> None:
        self._reject(spdx([no_purl_package("SPDXRef-a")]))
        self._reject(
            spdx(
                [
                    package(
                        "SPDXRef-a",
                        "pkg:pypi/foo@1",
                        externalRefs=[
                            {"referenceType": "website", "referenceLocator": "x"}
                        ],
                    )
                ]
            )
        )
        self._reject(spdx([package("SPDXRef-a", "pkg:pypi/foo@1", externalRefs=[])]))
        self._reject(
            spdx([package("SPDXRef-a", "pkg:pypi/foo@1", externalRefs="nope")])
        )

    def test_bad_purl_rejected(self) -> None:
        self._reject(spdx([package("SPDXRef-a", "pkg:maven/foo@1")]))
        self._reject(spdx([package("SPDXRef-a", "pkg:pypi/foo")]))
        self._reject(spdx([package("SPDXRef-a", "not-a-purl")]))

    def test_conflicting_purls_rejected(self) -> None:
        self._reject(
            spdx(
                [
                    package(
                        "SPDXRef-a",
                        "pkg:pypi/foo@1",
                        externalRefs=[
                            {"referenceType": "purl", "referenceLocator": "pkg:pypi/foo@1"},
                            {"referenceType": "purl", "referenceLocator": "pkg:npm/foo@1"},
                        ],
                    )
                ]
            )
        )

    def test_duplicate_purl_same_identity_allowed(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [
                    package(
                        "SPDXRef-a",
                        "pkg:pypi/foo@1",
                        externalRefs=[
                            {"referenceType": "purl", "referenceLocator": "pkg:pypi/foo@1"},
                            {
                                "referenceType": "purl",
                                "referenceLocator": "pkg:pypi/foo@1?arch=x86",
                            },
                        ],
                    )
                ]
            ),
        )
        self.assertEqual(result.source_components, 1)

    def test_percent_encoding_restored_once(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx([package("SPDXRef-a", "pkg:pypi/lib%2Dcore@1%2E0")]),
        )
        self.assertEqual(result.source_components, 1)
        row = self.catalog.connection.execute(
            "SELECT name, version FROM components WHERE service = 'api'"
        ).fetchone()
        self.assertEqual((row["name"], row["version"]), ("lib-core", "1.0"))

    def test_corrupt_purl_names_package_location_and_spdxid(self) -> None:
        for bad_purl in (
            "pkg:pypi/foo%bar@1",
            "pkg:pypi/foo%ff@1",
            "pkg:pypi/foo@%E4%B8",
            "pkg:npm/%GGscope/pkg@1",
        ):
            with self.subTest(bad_purl=bad_purl):
                catalog = Catalog()
                with self.assertRaises(ValueError) as caught:
                    catalog.import_sbom(
                        "api",
                        "src",
                        spdx([package("SPDXRef-Pkg-9", bad_purl)]),
                    )
                message = str(caught.exception)
                self.assertIn("packages[0]", message)
                self.assertIn("SPDXRef-Pkg-9", message)
                catalog.close()

    def test_one_corrupt_purl_fails_package_even_if_another_valid(self) -> None:
        # The broken reference must not be skipped in favor of the valid one.
        self._reject(
            spdx(
                [
                    package(
                        "SPDXRef-a",
                        "pkg:pypi/foo@1",
                        externalRefs=[
                            {"referenceType": "purl", "referenceLocator": "pkg:pypi/foo@1"},
                            {"referenceType": "purl", "referenceLocator": "pkg:pypi/bar%ff@1"},
                        ],
                    )
                ]
            )
        )
        # Same rule regardless of ref ordering.
        self._reject(
            spdx(
                [
                    package(
                        "SPDXRef-a",
                        "pkg:pypi/foo@1",
                        externalRefs=[
                            {"referenceType": "purl", "referenceLocator": "pkg:pypi/foo%GG@1"},
                            {"referenceType": "purl", "referenceLocator": "pkg:pypi/foo@1"},
                        ],
                    )
                ]
            )
        )

    def test_corrupt_purl_fails_whole_import_without_earlier_packages(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                spdx(
                    [
                        package("SPDXRef-good", "pkg:pypi/foo@1"),
                        package("SPDXRef-bad", "pkg:pypi/bar%ff@1"),
                    ]
                ),
            )
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM components"
            ).fetchone()[0],
            0,
        )

    def test_corrupt_spdx_replacement_keeps_previous_source(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [
                    package("SPDXRef-a", "pkg:pypi/foo@1"),
                    package("SPDXRef-b", "pkg:pypi/bar@1"),
                ],
                [relationship("SPDXRef-a", "DEPENDS_ON", "SPDXRef-b")],
            ),
        )
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                spdx(
                    [
                        package("SPDXRef-new", "pkg:pypi/newpkg@1"),
                        package("SPDXRef-bad", "pkg:pypi/broken%E4%B8@1"),
                    ]
                ),
            )
        rows = self.catalog.connection.execute(
            "SELECT name FROM components WHERE service = 'api' ORDER BY name"
        ).fetchall()
        self.assertEqual([r["name"] for r in rows], ["bar", "foo"])
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

    def test_relationship_validation(self) -> None:
        base = [
            package("SPDXRef-a", "pkg:pypi/foo@1"),
            package("SPDXRef-b", "pkg:pypi/bar@1"),
        ]
        self._reject(
            spdx(base, [relationship("SPDXRef-a", "DEPENDS_ON", "SPDXRef-ghost")])
        )
        # External document references are not local packages.
        self._reject(
            spdx(
                base,
                [
                    relationship(
                        "SPDXRef-a", "DEPENDS_ON", "DocumentRef-other:SPDXRef-x"
                    )
                ],
            )
        )
        self._reject(
            spdx(base, [relationship("SPDXRef-DOCUMENT", "DEPENDS_ON", "SPDXRef-a")])
        )
        self._reject(
            spdx(base, [relationship("SPDXRef-a", "DEPENDENCY_OF", "SPDXRef-DOCUMENT")])
        )
        self._reject(spdx(base, relationships="nope"))
        self._reject(spdx(base, relationships=["nope"]))
        self._reject(spdx(base, [{"relationshipType": "DEPENDS_ON"}]))

    def test_self_dependency_rejected(self) -> None:
        # Direct self reference.
        self._reject(
            spdx(
                [package("SPDXRef-a", "pkg:pypi/foo@1")],
                [relationship("SPDXRef-a", "DEPENDS_ON", "SPDXRef-a")],
            )
        )
        # Self dependency produced by identity merging.
        self._reject(
            spdx(
                [
                    package("SPDXRef-a", "pkg:pypi/foo@1"),
                    package("SPDXRef-b", "pkg:pypi/foo@1"),
                ],
                [relationship("SPDXRef-a", "DEPENDS_ON", "SPDXRef-b")],
            )
        )

    def test_rejection_leaves_catalog_unchanged(self) -> None:
        self.catalog.import_sbom(
            "api", "src", spdx([package("SPDXRef-a", "pkg:pypi/foo@1")])
        )
        self._reject(
            spdx(
                [package("SPDXRef-x", "pkg:pypi/new@1")],
                [relationship("SPDXRef-x", "DEPENDS_ON", "SPDXRef-ghost")],
            )
        )
        rows = self.catalog.connection.execute(
            "SELECT name FROM components WHERE service = 'api'"
        ).fetchall()
        self.assertEqual([r["name"] for r in rows], ["foo"])


class SpdxReplacementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def test_switching_cyclonedx_to_spdx_replaces(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            cdx(
                [
                    cdx_component("a", "pkg:pypi/foo@1"),
                    cdx_component("b", "pkg:pypi/bar@1"),
                ],
                [{"ref": "a", "dependsOn": ["b"]}],
            ),
        )
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [
                    package("SPDXRef-a", "pkg:pypi/foo@1"),
                    package("SPDXRef-c", "pkg:pypi/baz@1"),
                ],
                [relationship("SPDXRef-a", "DEPENDS_ON", "SPDXRef-c")],
            ),
        )
        self.assertEqual(result.source_components, 2)
        self.assertEqual(result.added_components, 1)
        self.assertEqual(result.deleted_components, 1)
        self.assertEqual(result.added_dependencies, 1)
        self.assertEqual(result.deleted_dependencies, 1)
        names = sorted(
            r["name"]
            for r in self.catalog.connection.execute(
                "SELECT name FROM components WHERE service = 'api'"
            )
        )
        self.assertEqual(names, ["baz", "foo"])
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM sources").fetchone()[0],
            1,
        )

    def test_switching_spdx_back_to_cyclonedx_replaces(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            spdx([package("SPDXRef-a", "pkg:pypi/foo@1")]),
        )
        result = self.catalog.import_sbom(
            "api", "src", cdx([cdx_component("a", "pkg:pypi/bar@1")])
        )
        self.assertEqual(result.source_components, 1)
        self.assertEqual(result.added_components, 1)
        self.assertEqual(result.deleted_components, 1)
        names = [
            r["name"]
            for r in self.catalog.connection.execute(
                "SELECT name FROM components WHERE service = 'api'"
            )
        ]
        self.assertEqual(names, ["bar"])

    def test_other_sources_and_manual_data_survive(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src-a",
            spdx([package("SPDXRef-a", "pkg:pypi/foo@1")]),
        )
        self.catalog.import_sbom(
            "api",
            "src-b",
            spdx([package("SPDXRef-b", "pkg:pypi/bar@1")]),
        )
        self.catalog.add_component("api", "pypi", "manual", "1.0.0")
        self.catalog.add_dependency(
            "api", "pypi", "manual", "1.0.0", "api", "pypi", "bar", "1"
        )
        result = self.catalog.import_sbom("api", "src-a", spdx([]))
        self.assertEqual(result.deleted_components, 1)
        names = sorted(
            r["name"]
            for r in self.catalog.connection.execute(
                "SELECT name FROM components WHERE service = 'api'"
            )
        )
        self.assertEqual(names, ["bar", "manual"])
        # Manual edge survives together with its endpoints.
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM dependencies"
            ).fetchone()[0],
            1,
        )

    def test_impact_reflects_spdx_replacement_immediately(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [
                    package("SPDXRef-a", "pkg:pypi/foo@1"),
                    package("SPDXRef-b", "pkg:pypi/bar@1"),
                ],
                [relationship("SPDXRef-a", "DEPENDS_ON", "SPDXRef-b")],
            ),
        )
        self.catalog.add_vulnerability("CVE-1", "bar", "high")
        self.assertEqual(self.catalog.summary().affected_components, 2)
        # Dropping bar from the source removes the whole impact chain.
        self.catalog.import_sbom(
            "api", "src", spdx([package("SPDXRef-a", "pkg:pypi/foo@1")])
        )
        self.assertEqual(self.catalog.summary().affected_components, 0)

    def test_remove_manual_edge_cleans_endpoints_after_spdx_withdrawal(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [
                    package("SPDXRef-app", "pkg:pypi/app@1"),
                    package("SPDXRef-lib", "pkg:pypi/lib@1"),
                ],
                [relationship("SPDXRef-app", "DEPENDS_ON", "SPDXRef-lib")],
            ),
        )
        self.catalog.add_vulnerability("CVE-1", "lib", "high")
        self.catalog.add_dependency(
            "api", "pypi", "app", "1", "api", "pypi", "lib", "1"
        )
        self.catalog.import_sbom("api", "src", spdx([]))
        self.assertEqual(self.catalog.summary().components, 2)
        self.catalog.remove_dependency(
            "api", "pypi", "app", "1", "api", "pypi", "lib", "1"
        )
        self.assertEqual(self.catalog.summary().components, 0)
        self.assertEqual(self.catalog.summary().affected_components, 0)
        self.assertEqual(self.catalog.impact(), [])


class SpdxCliTests(unittest.TestCase):
    def test_import_spdx_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            path = Path(directory, "sbom.json")
            path.write_text(
                json.dumps(
                    spdx(
                        [
                            package("SPDXRef-a", "pkg:pypi/foo@1"),
                            package("SPDXRef-b", "pkg:pypi/bar@1"),
                        ],
                        [relationship("SPDXRef-a", "DEPENDS_ON", "SPDXRef-b")],
                    )
                )
            )
            self.assertEqual(
                main(["--database", database, "import-sbom", "api", "src", str(path)]),
                0,
            )
            catalog = Catalog(database)
            self.assertEqual(
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM components"
                ).fetchone()[0],
                2,
            )
            self.assertEqual(
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM dependencies"
                ).fetchone()[0],
                1,
            )
            catalog.close()

    def test_invalid_spdx_returns_nonzero_and_preserves_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            good = Path(directory, "good.json")
            good.write_text(
                json.dumps(spdx([package("SPDXRef-a", "pkg:pypi/foo@1")]))
            )
            bad = Path(directory, "bad.json")
            bad.write_text(
                json.dumps(
                    spdx(
                        [
                            package("SPDXRef-a", "pkg:pypi/foo@1"),
                            no_purl_package("SPDXRef-b"),
                        ]
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
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM components"
                ).fetchone()[0],
                1,
            )
            catalog.close()

    def test_corrupt_percent_escape_returns_nonzero_without_success_stats(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            good = Path(directory, "good.json")
            good.write_text(
                json.dumps(spdx([package("SPDXRef-a", "pkg:pypi/foo@1")]))
            )
            bad = Path(directory, "bad.json")
            bad.write_text(
                json.dumps(spdx([package("SPDXRef-bad", "pkg:pypi/bar%ff@1")]))
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
            self.assertNotIn("来源组件数", stdout.getvalue())
            self.assertIn("packages[0]", stderr.getvalue())
            self.assertIn("SPDXRef-bad", stderr.getvalue())
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
