"""Regression tests for SBOM source replacement when sources share a graph.

Two sources of the same service may independently declare the very same
components and the very same dependency relationship - one document in
CycloneDX, the other in SPDX, with unrelated internal reference ids. Shared
objects are identified by (service, ecosystem, package name, version), so the
catalog must hold a single component per identity and a single relationship
per identity pair, owned by both sources. Replacing one source must never tear
down what the other source (or a manual registration) still declares, and the
import counters must count catalog objects actually removed, not declarations
withdrawn.
"""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard.cli import main

APP = "pkg:pypi/app@1.0.0"
LIB = "pkg:pypi/lib@2.0.0"
CVE = "CVE-2026-9001"


def cdx(components, dependencies=None):
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": components,
    }
    if dependencies is not None:
        document["dependencies"] = dependencies
    return document


def cc(ref, purl):
    return {"bom-ref": ref, "purl": purl}


def spdx(packages, relationships=None, spdxid="SPDXRef-DOCUMENT"):
    document = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": spdxid,
        "name": "test-document",
        "documentNamespace": "https://example.com/test",
        "creationInfo": {"creators": ["Tool: test"]},
        "packages": packages,
    }
    if relationships is not None:
        document["relationships"] = relationships
    return document


def pk(spdxid, purl):
    return {
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


def rel(element, relationship_type, related):
    return {
        "spdxElementId": element,
        "relationshipType": relationship_type,
        "relatedSpdxElement": related,
    }


# Source A declares the graph in CycloneDX; source B declares exactly the same
# graph in SPDX using deliberately different internal reference identifiers.
def source_a_document():
    return cdx(
        [cc("build/app", APP), cc("build/lib", LIB)],
        [{"ref": "build/app", "dependsOn": ["build/lib"]}],
    )


def source_b_document():
    return spdx(
        [pk("SPDXRef-Portal-App", APP), pk("SPDXRef-Library-v2", LIB)],
        [rel("SPDXRef-Portal-App", "DEPENDS_ON", "SPDXRef-Library-v2")],
    )


class SharedSourceRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()
        # The vulnerability directly hits the library; the application is only
        # affected through the shared app -> lib relationship.
        self.catalog.add_vulnerability(CVE, "lib", "high")

    def tearDown(self) -> None:
        self.catalog.close()

    def _declare_shared_graph(self):
        first = self.catalog.import_sbom("api", "cyclonedx-build", source_a_document())
        second = self.catalog.import_sbom("api", "spdx-audit", source_b_document())
        return first, second

    def _component_count(self, service="api"):
        return self.catalog.connection.execute(
            "SELECT COUNT(*) FROM components WHERE service = ?", (service,)
        ).fetchone()[0]

    def _dependency_count(self, service="api"):
        return self.catalog.connection.execute(
            """
            SELECT COUNT(*) FROM dependencies d
            JOIN components c ON d.dependent_id = c.id
            WHERE c.service = ?
            """,
            (service,),
        ).fetchone()[0]

    def _impact_by_name(self, service="api"):
        return {record["component"]["name"]: record for record in
                self.catalog.impact(service=service)}

    def _assert_shared_impact_intact(self):
        # Library: direct hit. Application: indirect hit through the one edge.
        records = self._impact_by_name()
        self.assertEqual(sorted(records), ["app", "lib"])
        self.assertTrue(records["lib"]["direct"])
        self.assertEqual(
            [node["name"] for node in records["lib"]["path"]], ["lib"]
        )
        self.assertFalse(records["app"]["direct"])
        self.assertEqual(
            [node["name"] for node in records["app"]["path"]], ["app", "lib"]
        )

    def test_two_formats_share_one_component_per_identity_and_one_edge(self) -> None:
        first, second = self._declare_shared_graph()
        # The second source adds and removes nothing: it shares both components
        # and the relationship already declared by the first source.
        self.assertEqual(
            (first.source_components, first.added_components, first.deleted_components,
             first.added_dependencies, first.deleted_dependencies),
            (2, 2, 0, 1, 0),
        )
        self.assertEqual(
            (second.source_components, second.added_components, second.deleted_components,
             second.added_dependencies, second.deleted_dependencies),
            (2, 0, 0, 0, 0),
        )
        # One app, one library, one relationship - despite two declarations and
        # unrelated internal reference ids.
        self.assertEqual(self._component_count(), 2)
        self.assertEqual(self._dependency_count(), 1)
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM component_sources"
            ).fetchone()[0],
            4,
        )
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM dependency_sources"
            ).fetchone()[0],
            2,
        )
        identities = sorted(
            (r["ecosystem"], r["name"], r["version"])
            for r in self.catalog.connection.execute(
                "SELECT ecosystem, name, version FROM components WHERE service = 'api'"
            )
        )
        self.assertEqual(
            identities, [("pypi", "app", "1.0.0"), ("pypi", "lib", "2.0.0")]
        )
        self._assert_shared_impact_intact()

    def test_empty_replacement_of_one_source_keeps_the_shared_graph(self) -> None:
        self._declare_shared_graph()
        # User replaces source A with an empty manifest; B still declares both
        # components, the edge and therefore the application's risk.
        result = self.catalog.import_sbom(
            "api", "cyclonedx-build", cdx([])
        )
        self.assertEqual(result.source_components, 0)
        self.assertEqual(result.added_components, 0)
        self.assertEqual(result.deleted_components, 0)
        self.assertEqual(result.added_dependencies, 0)
        self.assertEqual(result.deleted_dependencies, 0)
        self.assertEqual(self._component_count(), 2)
        self.assertEqual(self._dependency_count(), 1)
        # B is now the sole owner; A's withdrawn declaration is not a deletion.
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM component_sources"
            ).fetchone()[0],
            2,
        )
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM dependency_sources"
            ).fetchone()[0],
            1,
        )
        owner = self.catalog.connection.execute(
            """
            SELECT s.name FROM dependency_sources ds
            JOIN sources s ON s.id = ds.source_id
            """
        ).fetchall()
        self.assertEqual([r["name"] for r in owner], ["spdx-audit"])
        self._assert_shared_impact_intact()
        self.assertEqual(self.catalog.summary().affected_components, 2)

    def test_components_only_replacement_removes_exactly_the_edge(self) -> None:
        self._declare_shared_graph()
        self.catalog.import_sbom("api", "cyclonedx-build", cdx([]))
        # B now ships the two components without the dependency.
        result = self.catalog.import_sbom(
            "api",
            "spdx-audit",
            spdx(
                [pk("SPDXRef-Portal-App", APP), pk("SPDXRef-Library-v2", LIB)]
            ),
        )
        self.assertEqual(result.source_components, 2)
        self.assertEqual(result.added_components, 0)
        self.assertEqual(result.deleted_components, 0)
        self.assertEqual(result.added_dependencies, 0)
        # Exactly the one relationship actually leaves the catalog; the earlier
        # withdrawal by A must not be counted as a deletion.
        self.assertEqual(result.deleted_dependencies, 1)
        self.assertEqual(self._component_count(), 2)
        self.assertEqual(self._dependency_count(), 0)
        # The library is still directly hit; the application no longer inherits
        # the hit through this relationship.
        records = self._impact_by_name()
        self.assertEqual(sorted(records), ["lib"])
        self.assertTrue(records["lib"]["direct"])
        self.assertEqual(self.catalog.summary().affected_components, 1)

    def test_manual_edge_outlives_both_sources_withdrawing_it(self) -> None:
        self._declare_shared_graph()
        # The same relationship is additionally registered by hand.
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "lib", "2.0.0"
        )
        # Both sources replace their declarations with component-only manifests.
        for source, document in (
            ("cyclonedx-build",
             cdx([cc("build/app", APP), cc("build/lib", LIB)])),
            ("spdx-audit",
             spdx([pk("SPDXRef-Portal-App", APP),
                   pk("SPDXRef-Library-v2", LIB)])),
        ):
            result = self.catalog.import_sbom("api", source, document)
            self.assertEqual(result.deleted_dependencies, 0)
            self.assertEqual(result.deleted_components, 0)

        # No source declares the edge anymore, but the manual registration does.
        self.assertEqual(self._component_count(), 2)
        self.assertEqual(self._dependency_count(), 1)
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT manual FROM dependencies"
            ).fetchone()[0],
            1,
        )
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM dependency_sources"
            ).fetchone()[0],
            0,
        )
        self._assert_shared_impact_intact()

        # Clearing both sources entirely still cannot revoke the manual edge,
        # and its endpoints are kept precisely because that edge needs them.
        for source, empty in (
            ("cyclonedx-build", cdx([])),
            ("spdx-audit", spdx([])),
        ):
            result = self.catalog.import_sbom("api", source, empty)
            self.assertEqual(result.deleted_components, 0)
            self.assertEqual(result.deleted_dependencies, 0)
        self.assertEqual(self._component_count(), 2)
        self.assertEqual(self._dependency_count(), 1)
        self._assert_shared_impact_intact()

    def test_bad_endpoint_replacement_fails_without_touching_shared_state(self) -> None:
        self._declare_shared_graph()

        def assert_unchanged_after_failure(source, document, ghost):
            with self.assertRaises(ValueError) as caught:
                self.catalog.import_sbom("api", source, document)
            self.assertIn(ghost, str(caught.exception))
            # Components, the relationship and both sources' ownership rows all
            # remain - no state where only components were refreshed.
            self.assertEqual(self._component_count(), 2)
            self.assertEqual(self._dependency_count(), 1)
            self.assertEqual(
                self.catalog.connection.execute(
                    "SELECT COUNT(*) FROM component_sources"
                ).fetchone()[0],
                4,
            )
            self.assertEqual(
                self.catalog.connection.execute(
                    "SELECT COUNT(*) FROM dependency_sources"
                ).fetchone()[0],
                2,
            )
            self._assert_shared_impact_intact()

        # CycloneDX side points at an unknown bom-ref.
        assert_unchanged_after_failure(
            "cyclonedx-build",
            cdx(
                [cc("build/app", APP)],
                [{"ref": "build/app", "dependsOn": ["ghost-ref"]}],
            ),
            "ghost-ref",
        )
        # SPDX side points at an unknown SPDXID.
        assert_unchanged_after_failure(
            "spdx-audit",
            spdx(
                [pk("SPDXRef-Portal-App", APP)],
                [rel("SPDXRef-Portal-App", "DEPENDS_ON", "SPDXRef-ghost")],
            ),
            "SPDXRef-ghost",
        )
        # The failed attempts left A's ownership intact: re-importing its exact
        # declaration adds and removes nothing.
        result = self.catalog.import_sbom(
            "api", "cyclonedx-build", source_a_document()
        )
        self.assertEqual(result.source_components, 2)
        self.assertEqual(result.added_components, 0)
        self.assertEqual(result.deleted_components, 0)
        self.assertEqual(result.added_dependencies, 0)
        self.assertEqual(result.deleted_dependencies, 0)

    def test_other_service_with_same_source_and_identities_is_isolated(self) -> None:
        self._declare_shared_graph()
        # A different service uses the same source name and the same package
        # names/versions, with its own app -> lib edge.
        self.catalog.import_sbom(
            "worker",
            "cyclonedx-build",
            cdx(
                [cc("w/app", APP), cc("w/lib", LIB)],
                [{"ref": "w/app", "dependsOn": ["w/lib"]}],
            ),
        )
        # Clear and then edge-strip source A in service api.
        self.catalog.import_sbom("api", "cyclonedx-build", cdx([]))
        self.catalog.import_sbom(
            "api",
            "spdx-audit",
            spdx([pk("SPDXRef-Portal-App", APP), pk("SPDXRef-Library-v2", LIB)]),
        )
        # Service api: components kept by B, its edge is gone.
        self.assertEqual(self._component_count("api"), 2)
        self.assertEqual(self._dependency_count("api"), 0)
        # Service worker: catalog and risk results untouched.
        self.assertEqual(self._component_count("worker"), 2)
        self.assertEqual(self._dependency_count("worker"), 1)
        records = {
            record["component"]["name"]: record
            for record in self.catalog.impact(service="worker")
        }
        self.assertEqual(sorted(records), ["app", "lib"])
        self.assertTrue(records["lib"]["direct"])
        self.assertFalse(records["app"]["direct"])
        self.assertEqual(
            [node["name"] for node in records["app"]["path"]], ["app", "lib"]
        )
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM components"
            ).fetchone()[0],
            4,
        )


class SharedSourcePersistenceTests(unittest.TestCase):
    def test_retention_survives_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory, "catalog.db")
            catalog = Catalog(database)
            catalog.add_vulnerability(CVE, "lib", "high")
            catalog.import_sbom("api", "cyclonedx-build", source_a_document())
            catalog.import_sbom("api", "spdx-audit", source_b_document())
            catalog.import_sbom("api", "cyclonedx-build", cdx([]))
            catalog.close()

            reopened = Catalog(database)
            self.assertEqual(
                reopened.connection.execute(
                    "SELECT COUNT(*) FROM components WHERE service = 'api'"
                ).fetchone()[0],
                2,
            )
            self.assertEqual(
                reopened.connection.execute(
                    """
                    SELECT COUNT(*) FROM dependencies d
                    JOIN components c ON d.dependent_id = c.id
                    WHERE c.service = 'api'
                    """
                ).fetchone()[0],
                1,
            )
            records = {
                record["component"]["name"]: record
                for record in reopened.impact(service="api")
            }
            self.assertTrue(records["lib"]["direct"])
            self.assertFalse(records["app"]["direct"])
            self.assertEqual(
                [node["name"] for node in records["app"]["path"]],
                ["app", "lib"],
            )
            reopened.close()


class SharedSourceCliTests(unittest.TestCase):
    def _write(self, directory, name, document):
        path = Path(directory, name)
        path.write_text(json.dumps(document))
        return str(path)

    def test_cli_shared_declaration_survives_empty_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            path_a = self._write(directory, "a.json", source_a_document())
            path_b = self._write(directory, "b.json", source_b_document())
            path_empty = self._write(directory, "empty.json", cdx([]))

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status_a = main(
                    ["--database", database, "import-sbom", "api",
                     "cyclonedx-build", path_a]
                )
                status_b = main(
                    ["--database", database, "import-sbom", "api",
                     "spdx-audit", path_b]
                )
                status_clear = main(
                    ["--database", database, "import-sbom", "api",
                     "cyclonedx-build", path_empty]
                )
            self.assertEqual((status_a, status_b, status_clear), (0, 0, 0))
            printed = output.getvalue()
            self.assertIn("来源组件数: 2", printed)
            self.assertIn("删除组件: 0", printed)
            self.assertIn("删除关系: 0", printed)

            catalog = Catalog(database)
            self.assertEqual(
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM components WHERE service = 'api'"
                ).fetchone()[0],
                2,
            )
            self.assertEqual(
                catalog.connection.execute(
                    """
                    SELECT COUNT(*) FROM dependencies d
                    JOIN components c ON d.dependent_id = c.id
                    WHERE c.service = 'api'
                    """
                ).fetchone()[0],
                1,
            )
            catalog.add_vulnerability(CVE, "lib", "high")
            records = {
                record["component"]["name"]: record
                for record in catalog.impact(service="api")
            }
            self.assertTrue(records["lib"]["direct"])
            self.assertFalse(records["app"]["direct"])
            catalog.close()

    def test_cli_failed_replacement_keeps_shared_declaration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            path_a = self._write(directory, "a.json", source_a_document())
            path_b = self._write(directory, "b.json", source_b_document())
            path_bad = self._write(
                directory,
                "bad.json",
                cdx(
                    [cc("build/app", APP)],
                    [{"ref": "build/app", "dependsOn": ["ghost-ref"]}],
                ),
            )
            for path, source in (
                (path_a, "cyclonedx-build"),
                (path_b, "spdx-audit"),
            ):
                self.assertEqual(
                    main(["--database", database, "import-sbom", "api",
                          source, path]),
                    0,
                )
            self.assertEqual(
                main(["--database", database, "import-sbom", "api",
                      "cyclonedx-build", path_bad]),
                1,
            )
            catalog = Catalog(database)
            self.assertEqual(
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM components WHERE service = 'api'"
                ).fetchone()[0],
                2,
            )
            self.assertEqual(
                catalog.connection.execute(
                    """
                    SELECT COUNT(*) FROM dependencies d
                    JOIN components c ON d.dependent_id = c.id
                    WHERE c.service = 'api'
                    """
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM dependency_sources"
                ).fetchone()[0],
                2,
            )
            catalog.close()


if __name__ == "__main__":
    unittest.main()
