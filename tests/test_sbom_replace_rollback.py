"""Regression tests for SBOM source replacement failing *during* the save.

The existing failure cases all reject bad documents (format, package identity,
dependency references) before a single database write happens. These tests
cover the other half of the contract: a document that has already passed
validation, whose replacement of the source declaration has already started
(previous ownership withdrawn, part of the new declaration already written),
and that then hits a database write error in one of the two save phases -

1. saving components (``INSERT INTO components``);
2. saving dependencies (``INSERT INTO dependencies``).

Such a failure must roll back the whole replacement atomically: the directory
must never be left in a state mixing the old and new manifests. The original
components, dependency relationships and their source declarations all come
back, including:

* objects shared by two sources - one CycloneDX 1.5 document and one SPDX 2.3
  document - which stay jointly declared by both;
* components unique to the replaced source, which must not be lost;
* manually registered components and dependencies, which never move;
* the new manifest's components/relationships, none of which may linger.

The failed operation must surface as an error, never as successful import
statistics. Afterwards, withdrawing the *other* source must still leave the
failed source's old declaration holding every object it owned - a shared
object merely surviving in the directory must not hide lost source attribution.

The shared dependency library carries a real vulnerability hit; the
application is affected only indirectly through it and holds an approved,
unexpired exemption. Summary, impact and risk report queried at the same
evaluation instant, the request content and the full processing history must
be byte-for-byte identical before and after the failed replacement. These
tests guard only the replacement's overall rollback - vulnerability matching,
exemption effectiveness and retention rules are exercised as they stand.
"""

import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard.cli import main

SERVICE = "api"
SOURCE_CDX = "build-cdx"
SOURCE_SPDX = "audit-spdx"
OSV_SOURCE = "nvd"
CVE = "CVE-2026-9001"
EXEMPTION_ID = "EXM-2026-9001"

# Fixed instants keep the exemption term and every report deterministic.
SUBMITTED_AT = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
APPROVED_AT = datetime(2026, 1, 2, 0, 0, tzinfo=timezone.utc)
EXPIRES_AT = "2026-12-31T23:59:59+00:00"
EVAL_AT = "2026-06-01T00:00:00+00:00"

APP = "pkg:pypi/app@1.0.0"
LIB = "pkg:pypi/lib@2.0.0"
TOOLBELT = "pkg:pypi/toolbelt@4.0.0"
NEWRELIC = "pkg:pypi/newrelic@5.0.0"


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


def spdx(packages, relationships=None):
    document = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "replacement-test-document",
        "documentNamespace": "https://example.com/replacement-test",
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


def old_cdx_declaration():
    """The replaced source's original CycloneDX declaration.

    It shares app/lib and the app -> lib relationship with the SPDX source
    and additionally owns the toolbelt component and its edge to lib.
    """
    return cdx(
        [cc("build/app", APP), cc("build/lib", LIB), cc("build/toolbelt", TOOLBELT)],
        [
            {"ref": "build/app", "dependsOn": ["build/lib"]},
            {"ref": "build/toolbelt", "dependsOn": ["build/lib"]},
        ],
    )


def shared_spdx_declaration():
    """The other source: the shared graph only, in SPDX 2.3."""
    return spdx(
        [pk("SPDXRef-Portal-App", APP), pk("SPDXRef-Library-v2", LIB)],
        [rel("SPDXRef-Portal-App", "DEPENDS_ON", "SPDXRef-Library-v2")],
    )


def new_cdx_declaration():
    """A valid replacement that genuinely differs in components and edges.

    Versus the old declaration it keeps app/lib and app -> lib, drops
    toolbelt and its edge, and adds newrelic plus an app -> newrelic edge.
    """
    return cdx(
        [cc("new/app", APP), cc("new/lib", LIB), cc("new/newrelic", NEWRELIC)],
        [
            {"ref": "new/app", "dependsOn": ["new/lib"]},
            {"ref": "new/app", "dependsOn": ["new/newrelic"]},
        ],
    )


def new_spdx_declaration():
    """The same valid replacement content, declared as SPDX 2.3."""
    return spdx(
        [
            pk("SPDXRef-App", APP),
            pk("SPDXRef-Lib", LIB),
            pk("SPDXRef-NewRelic", NEWRELIC),
        ],
        [
            rel("SPDXRef-App", "DEPENDS_ON", "SPDXRef-Lib"),
            rel("SPDXRef-App", "DEPENDS_ON", "SPDXRef-NewRelic"),
        ],
    )


# A write error injected at each save phase. Triggers live inside the same
# database the import writes to, so the failure goes through SQLite exactly
# like a real disk/constraint error: the statement fails, and the surrounding
# replacement transaction must roll back.
COMPONENT_SAVE_FAILURE_TRIGGER = """
CREATE TRIGGER fail_component_save
BEFORE INSERT ON components
WHEN NEW.name = 'newrelic'
 AND (SELECT COUNT(*) FROM components WHERE name = 'newrelic') = 0
BEGIN
    SELECT RAISE(ABORT, 'injected component-save write error');
END
"""

DEPENDENCY_SAVE_FAILURE_TRIGGER = """
CREATE TRIGGER fail_dependency_save
BEFORE INSERT ON dependencies
WHEN EXISTS (SELECT 1 FROM components WHERE name = 'newrelic')
 AND NOT EXISTS (
        SELECT 1 FROM dependencies d
        JOIN components c1 ON c1.id = d.dependent_id
        JOIN components c2 ON c2.id = d.dependency_id
        WHERE c1.name = 'app' AND c2.name = 'newrelic'
     )
BEGIN
    SELECT RAISE(ABORT, 'injected dependency-save write error');
END
"""


def build_catalog(database: str | Path) -> Catalog:
    """Create the pre-replacement scenario shared by every regression case.

    Two SBOM sources of service ``api`` jointly declare the application, the
    dependency library and the app -> lib relationship (one list in
    CycloneDX, one in SPDX). The CycloneDX source alone declares toolbelt
    and toolbelt -> lib. A manually registered ops component is anchored by
    a manual app -> ops dependency. A local OSV source carries a real
    vulnerability that directly hits the pinned library, so the application
    and toolbelt are affected only indirectly; the application's impact
    already has one approved, unexpired exemption.
    """
    catalog = Catalog(database)
    catalog.import_sbom(SERVICE, SOURCE_CDX, old_cdx_declaration())
    catalog.import_sbom(SERVICE, SOURCE_SPDX, shared_spdx_declaration())
    catalog.add_component(SERVICE, "pypi", "ops", "9.9.9")
    catalog.add_dependency(
        SERVICE, "pypi", "app", "1.0.0",
        SERVICE, "pypi", "ops", "9.9.9",
    )
    catalog.import_osv(
        OSV_SOURCE,
        [
            {
                "id": CVE,
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "lib"},
                        "versions": ["2.0.0"],
                    }
                ],
                "database_specific": {"severity": "high"},
            }
        ],
    )
    catalog.request_exemption(
        EXEMPTION_ID,
        SERVICE, "pypi", "app", "1.0.0",
        CVE, "lib", OSV_SOURCE,
        applicant="alice",
        reason="egress proxy mitigates the transitive library exposure",
        expires_at=EXPIRES_AT,
        submitted_at=SUBMITTED_AT,
    )
    catalog.approve_exemption(
        EXEMPTION_ID, handler="bob", note="compensating controls verified",
        decided_at=APPROVED_AT,
    )
    return catalog


def component_rows(catalog: Catalog) -> dict[tuple, int]:
    """Component identities with their manual flag."""
    return {
        (
            str(row["service"]),
            str(row["ecosystem"]),
            str(row["name"]),
            str(row["version"]),
        ): int(row["manual"])
        for row in catalog.connection.execute(
            "SELECT service, ecosystem, name, version, manual FROM components"
        )
    }


def dependency_rows(catalog: Catalog) -> dict[tuple[tuple, tuple], int]:
    """Dependency edges as (dependent identity, dependency identity) -> manual."""
    return {
        (
            (str(row["s1"]), str(row["e1"]), str(row["n1"]), str(row["v1"])),
            (str(row["s2"]), str(row["e2"]), str(row["n2"]), str(row["v2"])),
        ): int(row["manual"])
        for row in catalog.connection.execute(
            """
            SELECT c1.service AS s1, c1.ecosystem AS e1, c1.name AS n1,
                   c1.version AS v1,
                   c2.service AS s2, c2.ecosystem AS e2, c2.name AS n2,
                   c2.version AS v2,
                   d.manual AS manual
            FROM dependencies d
            JOIN components c1 ON c1.id = d.dependent_id
            JOIN components c2 ON c2.id = d.dependency_id
            """
        )
    }


def component_owners(catalog: Catalog) -> dict[str, list[str]]:
    """Source names declaring each component (service-scoped), per component."""
    owners: dict[str, list[str]] = {}
    for row in catalog.connection.execute(
        """
        SELECT c.name AS name, s.name AS source
        FROM component_sources cs
        JOIN components c ON c.id = cs.component_id
        JOIN sources s ON s.id = cs.source_id
        WHERE c.service = ?
        ORDER BY c.name, s.name
        """,
        (SERVICE,),
    ):
        owners.setdefault(str(row["name"]), []).append(str(row["source"]))
    return owners


def dependency_owners(catalog: Catalog) -> dict[tuple[str, str], list[str]]:
    """Source names declaring each relationship, per (dependent, dependency)."""
    owners: dict[tuple[str, str], list[str]] = {}
    for row in catalog.connection.execute(
        """
        SELECT c1.name AS dependent, c2.name AS dependency, s.name AS source
        FROM dependency_sources ds
        JOIN dependencies d ON d.id = ds.dependency_id
        JOIN components c1 ON c1.id = d.dependent_id
        JOIN components c2 ON c2.id = d.dependency_id
        JOIN sources s ON s.id = ds.source_id
        WHERE c1.service = ?
        ORDER BY c1.name, c2.name, s.name
        """,
        (SERVICE,),
    ):
        key = (str(row["dependent"]), str(row["dependency"]))
        owners.setdefault(key, []).append(str(row["source"]))
    return owners


def take_snapshot(catalog: Catalog) -> dict:
    """Everything that a failed replacement must leave untouched."""
    summary = catalog.summary()
    return {
        "components": component_rows(catalog),
        "dependencies": dependency_rows(catalog),
        "component_owners": component_owners(catalog),
        "dependency_owners": dependency_owners(catalog),
        "sources": sorted(
            (str(row["service"]), str(row["name"]))
            for row in catalog.connection.execute(
                "SELECT service, name FROM sources ORDER BY service, name"
            )
        ),
        "summary": (
            summary.components,
            summary.affected_components,
            summary.vulnerabilities,
            summary.highest_severity,
        ),
        "impact": catalog.impact(service=SERVICE),
        "risk_report": catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT),
        "exemption": catalog.get_exemption(EXEMPTION_ID),
    }


APP_ID = (SERVICE, "pypi", "app", "1.0.0")
LIB_ID = (SERVICE, "pypi", "lib", "2.0.0")
TOOLBELT_ID = (SERVICE, "pypi", "toolbelt", "4.0.0")
NEWRELIC_ID = (SERVICE, "pypi", "newrelic", "5.0.0")
OPS_ID = (SERVICE, "pypi", "ops", "9.9.9")


class SbomReplacementSaveFailureRollbackTests(unittest.TestCase):
    """A write error after the replacement started rolls the whole import back."""

    def _assert_snapshot_intact(self, catalog: Catalog, snapshot: dict) -> None:
        current = take_snapshot(catalog)
        self.assertEqual(current, snapshot)

        # The exact expected ownership, made explicit rather than only relying
        # on the before/after equality: shared objects carry both declarations,
        # the replaced source keeps its unique object, manual data has no
        # source row, and nothing from the new manifest survived.
        self.assertEqual(component_rows(catalog), {
            APP_ID: 0,
            LIB_ID: 0,
            TOOLBELT_ID: 0,
            OPS_ID: 1,
        })
        self.assertEqual(dependency_rows(catalog), {
            (APP_ID, LIB_ID): 0,
            (TOOLBELT_ID, LIB_ID): 0,
            (APP_ID, OPS_ID): 1,
        })
        self.assertEqual(component_owners(catalog), {
            "app": [SOURCE_SPDX, SOURCE_CDX],
            "lib": [SOURCE_SPDX, SOURCE_CDX],
            "toolbelt": [SOURCE_CDX],
        })
        self.assertEqual(dependency_owners(catalog), {
            ("app", "lib"): [SOURCE_SPDX, SOURCE_CDX],
            ("toolbelt", "lib"): [SOURCE_CDX],
        })
        self.assertNotIn(NEWRELIC_ID, component_rows(catalog))
        self.assertNotIn((APP_ID, NEWRELIC_ID), dependency_rows(catalog))

    def _assert_report_semantics(self, catalog: Catalog) -> None:
        # The library is hit directly; the application and toolbelt only
        # indirectly, through their edges to lib.
        records = {
            record["component"]["name"]: record
            for record in catalog.impact(service=SERVICE)
        }
        self.assertEqual(sorted(records), ["app", "lib", "toolbelt"])
        self.assertTrue(records["lib"]["direct"])
        self.assertFalse(records["app"]["direct"])
        self.assertFalse(records["toolbelt"]["direct"])
        self.assertEqual(
            [node["name"] for node in records["app"]["path"]],
            ["app", "lib"],
        )
        self.assertEqual(
            [node["name"] for node in records["toolbelt"]["path"]],
            ["toolbelt", "lib"],
        )

        # At the fixed evaluation instant the application's approved,
        # unexpired exemption still covers exactly its indirect record; the
        # library and toolbelt remain unhandled.
        report = catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
        by_component = {
            entry["component"]["name"]: entry for entry in report["impacts"]
        }
        self.assertTrue(by_component["app"]["exempted"])
        self.assertEqual(
            by_component["app"]["exemption_request"], EXEMPTION_ID
        )
        self.assertIsNone(by_component["app"]["not_exempt_reason"])
        self.assertFalse(by_component["lib"]["exempted"])
        self.assertFalse(by_component["toolbelt"]["exempted"])
        self.assertEqual(report["unhandled_component_count"], 2)
        self.assertEqual(report["highest_severity"], "high")

    def _trace_failed_import(self, catalog: Catalog, document: dict) -> list[str]:
        """Run the replacement, recording every SQL statement it executes."""
        statements: list[str] = []
        catalog.connection.set_trace_callback(statements.append)
        try:
            with self.assertRaises(sqlite3.Error) as caught:
                catalog.import_sbom(SERVICE, SOURCE_CDX, document)
        finally:
            catalog.connection.set_trace_callback(None)
        # A save-stage database error, not a document validation ValueError:
        # the document already passed validation.
        self.assertNotIsInstance(caught.exception, ValueError)
        self.assertEqual(type(caught.exception), sqlite3.IntegrityError)
        return statements

    def _run_failure_scenario(self, document: dict, trigger: str, phase: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)
            snapshot = take_snapshot(catalog)
            self._assert_report_semantics(catalog)

            catalog.connection.execute(trigger)
            statements = self._trace_failed_import(catalog, document)

            normalized = [statement.strip() for statement in statements]

            # The replacement really had started: this source's previous
            # ownership was withdrawn inside the transaction...
            self.assertTrue(
                any(s.startswith("DELETE FROM component_sources") for s in normalized),
                f"{phase}: component ownership withdrawal never ran",
            )
            self.assertTrue(
                any(s.startswith("DELETE FROM dependency_sources") for s in normalized),
                f"{phase}: dependency ownership withdrawal never ran",
            )
            # ...and part of the new declaration had already been written
            # before the error (re-registration of retained shared objects,
            # at minimum).
            self.assertTrue(
                any(
                    s.startswith(
                        ("INSERT INTO component_sources",
                         "INSERT OR IGNORE INTO component_sources")
                    )
                    for s in normalized
                ),
                f"{phase}: no replacement data was written before the error",
            )

            if phase == "component-save":
                # Failure while saving components: the new component INSERT
                # was attempted and the dependency-save phase never ran.
                self.assertTrue(
                    any(s.startswith("INSERT INTO components") for s in normalized)
                )
                self.assertFalse(
                    any(s.startswith("INSERT INTO dependencies") for s in normalized)
                )
            else:
                # Failure while saving dependencies: every new component had
                # already been saved, then the new edge INSERT failed.
                self.assertTrue(
                    any(s.startswith("INSERT INTO components") for s in normalized)
                )
                self.assertTrue(
                    any(s.startswith("INSERT INTO dependencies") for s in normalized)
                )

            # The whole partial replacement was rolled back, never committed.
            self.assertIn("ROLLBACK", normalized)
            self.assertNotIn("COMMIT", normalized)

            # Same connection: old state survives, no new state lingers, no
            # success statistics exist (the call raised instead of returning).
            self._assert_snapshot_intact(catalog, snapshot)
            self._assert_report_semantics(catalog)

            catalog.connection.execute("DROP TRIGGER IF EXISTS fail_component_save")
            catalog.connection.execute("DROP TRIGGER IF EXISTS fail_dependency_save")
            catalog.close()

            # Durable rollback: reopening the file shows the identical state.
            reopened = Catalog(database)
            self._assert_snapshot_intact(reopened, snapshot)
            self._assert_report_semantics(reopened)

            # Now withdraw the *other* (SPDX) source normally. The failed
            # replacement's old declaration must still own every object it
            # ever did: the shared objects survive with source attribution
            # intact, and toolbelt - unique to the failed source - is kept.
            result = reopened.import_sbom(SERVICE, SOURCE_SPDX, spdx([]))
            self.assertEqual(result.source_components, 0)
            self.assertEqual(result.added_components, 0)
            self.assertEqual(result.deleted_components, 0)
            self.assertEqual(result.added_dependencies, 0)
            self.assertEqual(result.deleted_dependencies, 0)
            self.assertEqual(component_owners(reopened), {
                "app": [SOURCE_CDX],
                "lib": [SOURCE_CDX],
                "toolbelt": [SOURCE_CDX],
            })
            self.assertEqual(dependency_owners(reopened), {
                ("app", "lib"): [SOURCE_CDX],
                ("toolbelt", "lib"): [SOURCE_CDX],
            })
            self.assertEqual(component_rows(reopened), snapshot["components"])
            self.assertEqual(dependency_rows(reopened), snapshot["dependencies"])
            # Risk, the indirect paths and the exemption are unchanged.
            self.assertEqual(
                reopened.impact(service=SERVICE), snapshot["impact"]
            )
            self.assertEqual(
                reopened.risk_report(service=SERVICE, evaluated_at=EVAL_AT),
                snapshot["risk_report"],
            )

            # Re-importing the failed source's original declaration is a pure
            # no-op: its old components and relationships are still exactly
            # its own, proving the failed attempt lost it no attribution.
            re_import = reopened.import_sbom(
                SERVICE, SOURCE_CDX, old_cdx_declaration()
            )
            self.assertEqual(re_import.source_components, 3)
            self.assertEqual(re_import.added_components, 0)
            self.assertEqual(re_import.deleted_components, 0)
            self.assertEqual(re_import.added_dependencies, 0)
            self.assertEqual(re_import.deleted_dependencies, 0)
            self.assertEqual(
                reopened.get_exemption(EXEMPTION_ID), snapshot["exemption"]
            )
            reopened.close()

    def test_component_save_failure_rolls_back_both_new_manifest_formats(self) -> None:
        for label, document in (
            ("CycloneDX 1.5 new manifest", new_cdx_declaration()),
            ("SPDX 2.3 new manifest", new_spdx_declaration()),
        ):
            with self.subTest(new_manifest=label):
                self._run_failure_scenario(
                    document,
                    COMPONENT_SAVE_FAILURE_TRIGGER,
                    "component-save",
                )

    def test_dependency_save_failure_rolls_back_both_new_manifest_formats(self) -> None:
        for label, document in (
            ("CycloneDX 1.5 new manifest", new_cdx_declaration()),
            ("SPDX 2.3 new manifest", new_spdx_declaration()),
        ):
            with self.subTest(new_manifest=label):
                self._run_failure_scenario(
                    document,
                    DEPENDENCY_SAVE_FAILURE_TRIGGER,
                    "dependency-save",
                )


class SbomReplacementValidationFailureContrastTests(unittest.TestCase):
    """Validation failures must not be mistaken for save-failure coverage.

    A bad document rejects before the database transaction begins, so no
    statement runs at all; the save-failure scenarios by contrast prove
    partial writes happened and were rolled back.
    """

    def test_invalid_documents_fail_before_any_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)
            snapshot = take_snapshot(catalog)

            invalid_cdx = cdx(
                [cc("new/app", APP)],
                [{"ref": "new/app", "dependsOn": ["ghost-ref"]}],
            )
            invalid_spdx = spdx(
                [pk("SPDXRef-App", APP)],
                [rel("SPDXRef-App", "DEPENDS_ON", "SPDXRef-ghost")],
            )
            for label, document, offending in (
                ("CycloneDX 1.5", invalid_cdx, "ghost-ref"),
                ("SPDX 2.3", invalid_spdx, "SPDXRef-ghost"),
            ):
                with self.subTest(new_manifest=label):
                    statements: list[str] = []
                    catalog.connection.set_trace_callback(statements.append)
                    try:
                        with self.assertRaises(ValueError) as caught:
                            catalog.import_sbom(SERVICE, SOURCE_CDX, document)
                    finally:
                        catalog.connection.set_trace_callback(None)
                    self.assertIn(offending, str(caught.exception))
                    self.assertFalse(
                        [s for s in statements if s.strip()],
                        "validation must reject the document before any SQL runs",
                    )
                    self.assertEqual(take_snapshot(catalog), snapshot)
            catalog.close()


class SbomReplacementSuccessPreservedTests(unittest.TestCase):
    """The existing entry point and successful replacement result stay intact."""

    def _successful_replacement(self, document: dict) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)

            result = catalog.import_sbom(SERVICE, SOURCE_CDX, document)
            # New list differs for real: newrelic and its edge arrive,
            # toolbelt and its edge actually leave the catalog.
            self.assertEqual(result.source_components, 3)
            self.assertEqual(result.added_components, 1)
            self.assertEqual(result.deleted_components, 1)
            self.assertEqual(result.added_dependencies, 1)
            self.assertEqual(result.deleted_dependencies, 1)

            self.assertEqual(component_rows(catalog), {
                APP_ID: 0,
                LIB_ID: 0,
                NEWRELIC_ID: 0,
                OPS_ID: 1,
            })
            self.assertEqual(dependency_rows(catalog), {
                (APP_ID, LIB_ID): 0,
                (APP_ID, NEWRELIC_ID): 0,
                (APP_ID, OPS_ID): 1,
            })
            self.assertEqual(component_owners(catalog), {
                "app": [SOURCE_SPDX, SOURCE_CDX],
                "lib": [SOURCE_SPDX, SOURCE_CDX],
                "newrelic": [SOURCE_CDX],
            })
            self.assertEqual(dependency_owners(catalog), {
                ("app", "lib"): [SOURCE_SPDX, SOURCE_CDX],
                ("app", "newrelic"): [SOURCE_CDX],
            })

            # The SPDX source still shares app/lib and their edge; toolbelt's
            # disappearance removes its indirect impact, while the
            # application keeps its indirect path through lib and the
            # exemption.
            records = {
                record["component"]["name"]: record
                for record in catalog.impact(service=SERVICE)
            }
            self.assertEqual(sorted(records), ["app", "lib"])
            self.assertFalse(records["app"]["direct"])
            self.assertEqual(
                [node["name"] for node in records["app"]["path"]],
                ["app", "lib"],
            )
            report = catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
            by_component = {
                entry["component"]["name"]: entry for entry in report["impacts"]
            }
            self.assertTrue(by_component["app"]["exempted"])
            self.assertEqual(
                by_component["app"]["exemption_request"], EXEMPTION_ID
            )
            self.assertFalse(by_component["lib"]["exempted"])
            self.assertEqual(report["unhandled_component_count"], 1)
            catalog.close()

    def test_successful_cyclonedx_replacement_result_is_unchanged(self) -> None:
        self._successful_replacement(new_cdx_declaration())

    def test_successful_spdx_replacement_result_is_unchanged(self) -> None:
        self._successful_replacement(new_spdx_declaration())

    def test_cli_entry_point_reports_success_statistics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            setup_database = str(Path(directory, "catalog.db"))
            setup = build_catalog(setup_database)
            setup.close()
            document_path = Path(directory, "new.json")
            document_path.write_text(json.dumps(new_cdx_declaration()))

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main([
                    "--database", setup_database,
                    "import-sbom", SERVICE, SOURCE_CDX, str(document_path),
                ])
            self.assertEqual(status, 0)
            printed = output.getvalue()
            self.assertIn("来源组件数: 3", printed)
            self.assertIn("新增组件: 1", printed)
            self.assertIn("删除组件: 1", printed)
            self.assertIn("新增关系: 1", printed)
            self.assertIn("删除关系: 1", printed)

            catalog = Catalog(setup_database)
            self.assertIn(NEWRELIC_ID, component_rows(catalog))
            self.assertNotIn(TOOLBELT_ID, component_rows(catalog))
            catalog.close()


if __name__ == "__main__":
    unittest.main()
