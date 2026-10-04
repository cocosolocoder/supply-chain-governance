"""Regression tests for replacing SBOM sources that share declarations.

Two sources of the same service — one CycloneDX, one SPDX — declare the
same application component depending on the same library component. The
catalog keeps one copy of each component and one relationship, and a
source replacement must only remove what no remaining source (or manual
registration) still declares. Shared objects are matched by service,
ecosystem, package name and version; the document-local reference ids
(bom-ref / SPDXID) may differ between the two sources.
"""

import unittest

from supply_guard.catalog import Catalog


SERVICE = "api"
CDX_SOURCE = "cdx-src"
SPDX_SOURCE = "spdx-src"

APP = ("pypi", "web", "2.0.0")
LIB = ("pypi", "flask", "1.5.0")


def cdx_document(components, dependencies=None):
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


def spdx_document(packages, relationships=None):
    document = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "shared-source-test",
        "documentNamespace": "https://example.com/shared-source-test",
        "creationInfo": {"creators": ["Tool: test"]},
        "packages": packages,
    }
    if relationships is not None:
        document["relationships"] = relationships
    return document


def spdx_package(spdxid, purl):
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


def spdx_depends_on(element, related):
    return {
        "spdxElementId": element,
        "relationshipType": "DEPENDS_ON",
        "relatedSpdxElement": related,
    }


def purl(identity):
    ecosystem, name, version = identity
    return f"pkg:{ecosystem}/{name}@{version}"


def cdx_full():
    """Source 甲: CycloneDX, app depends on lib, refs local to the document."""
    return cdx_document(
        [cdx_component("cdx-app", purl(APP)), cdx_component("cdx-lib", purl(LIB))],
        [{"ref": "cdx-app", "dependsOn": ["cdx-lib"]}],
    )


def spdx_full():
    """Source 乙: SPDX, the same app and lib with different document refs."""
    return spdx_document(
        [spdx_package("SPDXRef-app", purl(APP)), spdx_package("SPDXRef-lib", purl(LIB))],
        [spdx_depends_on("SPDXRef-app", "SPDXRef-lib")],
    )


def spdx_without_relationship():
    """Source 乙 replacement: both components, but no dependency declared."""
    return spdx_document(
        [spdx_package("SPDXRef-app", purl(APP)), spdx_package("SPDXRef-lib", purl(LIB))],
        [],
    )


class SharedSourceDeclarationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def import_both_sources(self) -> None:
        self.catalog.import_sbom(SERVICE, CDX_SOURCE, cdx_full())
        self.catalog.import_sbom(SERVICE, SPDX_SOURCE, spdx_full())
        self.catalog.add_vulnerability("CVE-2026-3001", LIB[1], "high")

    def component_identities(self, service=SERVICE):
        return sorted(
            (row["ecosystem"], row["name"], row["version"])
            for row in self.catalog.connection.execute(
                "SELECT ecosystem, name, version FROM components WHERE service = ?",
                (service,),
            )
        )

    def dependency_pairs(self, service=SERVICE):
        return sorted(
            (row["dependent"], row["dependency"])
            for row in self.catalog.connection.execute(
                """
                SELECT d1.name AS dependent, d2.name AS dependency
                FROM dependencies
                JOIN components d1 ON dependent_id = d1.id
                JOIN components d2 ON dependency_id = d2.id
                WHERE d1.service = ?
                """,
                (service,),
            )
        )

    def impact_by_name(self, service=SERVICE):
        return {
            record["component"]["name"]: record
            for record in self.catalog.impact(service=service)
        }

    def test_shared_declaration_stored_once(self) -> None:
        second = None
        first = self.catalog.import_sbom(SERVICE, CDX_SOURCE, cdx_full())
        second = self.catalog.import_sbom(SERVICE, SPDX_SOURCE, spdx_full())
        self.assertEqual((first.added_components, first.added_dependencies), (2, 1))
        # The SPDX source declares the same identities: nothing is added twice.
        self.assertEqual(second.source_components, 2)
        self.assertEqual(
            (
                second.added_components,
                second.deleted_components,
                second.added_dependencies,
                second.deleted_dependencies,
            ),
            (0, 0, 0, 0),
        )

        self.assertEqual(self.component_identities(), sorted([APP, LIB]))
        self.assertEqual(self.dependency_pairs(), [("web", "flask")])
        # Both sources co-own the shared components and the shared edge.
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

        self.catalog.add_vulnerability("CVE-2026-3001", LIB[1], "high")
        records = self.impact_by_name()
        self.assertEqual(sorted(records), ["flask", "web"])
        self.assertTrue(records["flask"]["direct"])
        self.assertFalse(records["web"]["direct"])
        self.assertEqual(
            [node["name"] for node in records["web"]["path"]], ["web", "flask"]
        )
        summary = self.catalog.summary()
        self.assertEqual(summary.components, 2)
        self.assertEqual(summary.affected_components, 2)
        self.assertEqual(summary.highest_severity, "high")

    def test_empty_replacement_of_one_source_keeps_shared_declaration(self) -> None:
        self.import_both_sources()
        before_impact = self.catalog.impact(service=SERVICE)

        result = self.catalog.import_sbom(SERVICE, CDX_SOURCE, cdx_document([]))

        self.assertEqual(result.source_components, 0)
        self.assertEqual(result.deleted_components, 0)
        self.assertEqual(result.deleted_dependencies, 0)
        # Source 乙 still declares both components and the relationship.
        self.assertEqual(self.component_identities(), sorted([APP, LIB]))
        self.assertEqual(self.dependency_pairs(), [("web", "flask")])
        # The application's dependency path and risk survive intact.
        self.assertEqual(self.catalog.impact(service=SERVICE), before_impact)
        records = self.impact_by_name()
        self.assertFalse(records["web"]["direct"])
        self.assertEqual(
            [node["name"] for node in records["web"]["path"]], ["web", "flask"]
        )
        self.assertEqual(self.catalog.summary().affected_components, 2)

    def test_last_declaration_removal_deletes_relationship_exactly_once(self) -> None:
        self.import_both_sources()
        self.catalog.import_sbom(SERVICE, CDX_SOURCE, cdx_document([]))

        result = self.catalog.import_sbom(
            SERVICE, SPDX_SOURCE, spdx_without_relationship()
        )

        # The components stay declared; only the one relationship leaves, and
        # it is counted once — not once per source that had declared it.
        self.assertEqual(result.source_components, 2)
        self.assertEqual(result.added_components, 0)
        self.assertEqual(result.deleted_components, 0)
        self.assertEqual(result.added_dependencies, 0)
        self.assertEqual(result.deleted_dependencies, 1)

        self.assertEqual(self.component_identities(), sorted([APP, LIB]))
        self.assertEqual(self.dependency_pairs(), [])
        self.assertEqual(self.catalog.summary().components, 2)

        # The library keeps its direct hit; the application is no longer
        # affected through the removed relationship.
        records = self.impact_by_name()
        self.assertEqual(sorted(records), ["flask"])
        self.assertTrue(records["flask"]["direct"])
        summary = self.catalog.summary()
        self.assertEqual(summary.affected_components, 1)
        self.assertEqual(summary.highest_severity, "high")
        report = self.catalog.risk_report(service=SERVICE)
        self.assertEqual(report["impact_count"], 1)
        self.assertEqual(report["unhandled_component_count"], 1)

    def test_manual_registration_survives_source_withdrawal(self) -> None:
        self.import_both_sources()
        self.catalog.add_dependency(
            SERVICE, *APP, SERVICE, *LIB
        )

        # Both sources withdraw the declaration, the manual one remains.
        self.catalog.import_sbom(SERVICE, CDX_SOURCE, cdx_document([]))
        result = self.catalog.import_sbom(
            SERVICE, SPDX_SOURCE, spdx_without_relationship()
        )

        self.assertEqual(result.deleted_components, 0)
        self.assertEqual(result.deleted_dependencies, 0)
        self.assertEqual(self.component_identities(), sorted([APP, LIB]))
        self.assertEqual(self.dependency_pairs(), [("web", "flask")])

        records = self.impact_by_name()
        self.assertEqual(sorted(records), ["flask", "web"])
        self.assertFalse(records["web"]["direct"])
        self.assertEqual(
            [node["name"] for node in records["web"]["path"]], ["web", "flask"]
        )
        self.assertEqual(self.catalog.summary().affected_components, 2)

    def test_invalid_replacement_preserves_shared_state(self) -> None:
        self.import_both_sources()
        before_components = self.component_identities()
        before_dependencies = self.dependency_pairs()
        before_impact = self.catalog.impact(service=SERVICE)
        before_report = self.catalog.risk_report(service=SERVICE)

        bad_documents = [
            cdx_document(
                [cdx_component("cdx-app", purl(APP))],
                [{"ref": "cdx-app", "dependsOn": ["cdx-ghost"]}],
            ),
            spdx_document(
                [spdx_package("SPDXRef-app", purl(APP))],
                [spdx_depends_on("SPDXRef-app", "SPDXRef-ghost")],
            ),
        ]
        for bad in bad_documents:
            with self.subTest(format=bad.get("bomFormat", "SPDX")):
                with self.assertRaises(ValueError):
                    self.catalog.import_sbom(SERVICE, CDX_SOURCE, bad)

        # No partial update: components, the shared relationship and every
        # impact record are exactly what the last good import established.
        self.assertEqual(self.component_identities(), before_components)
        self.assertEqual(self.dependency_pairs(), before_dependencies)
        self.assertEqual(self.catalog.impact(service=SERVICE), before_impact)
        after_report = self.catalog.risk_report(service=SERVICE)
        self.assertEqual(after_report["impacts"], before_report["impacts"])
        self.assertEqual(
            after_report["unhandled_component_count"],
            before_report["unhandled_component_count"],
        )
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM dependency_sources"
            ).fetchone()[0],
            2,
        )

    def test_other_service_with_same_source_and_packages_untouched(self) -> None:
        self.import_both_sources()
        # Another service reuses the same source names and package identities.
        self.catalog.import_sbom("other", CDX_SOURCE, cdx_full())
        self.catalog.import_sbom("other", SPDX_SOURCE, spdx_full())
        other_impact_before = self.catalog.impact(service="other")

        # Run the whole replacement flow on SERVICE: empty 甲, then 乙
        # without the relationship.
        self.catalog.import_sbom(SERVICE, CDX_SOURCE, cdx_document([]))
        self.catalog.import_sbom(SERVICE, SPDX_SOURCE, spdx_without_relationship())

        # SERVICE lost the relationship; "other" is fully intact.
        self.assertEqual(self.dependency_pairs(), [])
        self.assertEqual(sorted(self.impact_by_name()), ["flask"])
        self.assertEqual(self.component_identities("other"), sorted([APP, LIB]))
        self.assertEqual(self.dependency_pairs("other"), [("web", "flask")])
        self.assertEqual(self.catalog.impact(service="other"), other_impact_before)
        records = self.impact_by_name("other")
        self.assertEqual(sorted(records), ["flask", "web"])
        self.assertEqual(
            [node["name"] for node in records["web"]["path"]], ["web", "flask"]
        )


if __name__ == "__main__":
    unittest.main()
