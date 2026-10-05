"""Regression tests for source replacement failing *during the save*.

The existing failure cases reject malformed documents (bad format, package
identity or dependency reference) before a single row is written, so the
pre-write validation path is well covered. These tests cover the other half:
a document that is fully valid and has already started replacing the source
declaration - old ownership withdrawn, part of the new declaration written -
when a database write error interrupts the import, either while components are
being saved or while dependencies are being saved. The interrupted import
must roll back as a whole: a failed import can never leave the directory in a
half-old/half-new state, and it must never report success statistics.

The catalog is shared by two sources of one service, one CycloneDX 1.5 and one
SPDX 2.3, declaring the same application, library and their relationship. The
replaced source additionally declares a component of its own, the other source
declares one too, and the catalog also keeps hand-registered data. The library
has a real OSV hit; the application is affected only indirectly and holds an
approved, unexpired exemption, so reports before and after the failed import
can be compared at the same evaluation instant. Both supported document
formats run the whole scenario (the replacement even arrives in the other
source's format).
"""

import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard import cli as cli_module

SERVICE = "api"
TARGET_SOURCE = "build"
OTHER_SOURCE = "audit"
OSV_SOURCE = "nvd"

APP = "pkg:pypi/app@1.0.0"
LIB = "pkg:pypi/lib@2.0.0"
OLD_ONLY = "pkg:pypi/oldonly@3.0.0"
OTHER_ONLY = "pkg:pypi/bonly@1.2.0"
NEW_LIB = "pkg:pypi/newlib@4.0.0"
MANUAL_COMP = "pkg:pypi/manual-lib@5.0"
CVE = "CVE-2026-9001"
EXEMPTION_ID = "EXM-2026-001"
SUBMITTED_AT = datetime(2026, 3, 1, tzinfo=timezone.utc)
DECIDED_AT = datetime(2026, 3, 2, tzinfo=timezone.utc)
EXPIRES_AT = "2026-12-31T23:59:59+00:00"
EVALUATED_AT = "2026-06-01T00:00:00+00:00"

PURLS = {
    "app": APP,
    "lib": LIB,
    "oldonly": OLD_ONLY,
    "bonly": OTHER_ONLY,
    "newlib": NEW_LIB,
    "manual-lib": MANUAL_COMP,
}

# Replaced source before the attempt: shared app/lib graph plus its own
# oldonly component and an edge to it.
OLD_BUILD_SPEC = {
    "components": ["app", "lib", "oldonly"],
    "edges": [("app", "lib"), ("app", "oldonly")],
}
# The other source: same shared app/lib graph and its own bonly component.
OTHER_SOURCE_SPEC = {
    "components": ["app", "lib", "bonly"],
    "edges": [("app", "lib"), ("app", "bonly")],
}
# The valid replacement really differs, both in components and relationships:
# newlib and app -> newlib are added, oldonly stays as a component but the
# app -> oldonly relationship is withdrawn.
NEW_BUILD_SPEC = {
    "components": ["app", "lib", "oldonly", "newlib"],
    "edges": [("app", "lib"), ("app", "newlib")],
}
# An empty manifest withdraws every declaration of one source.
EMPTY_SPEC = {"components": [], "edges": []}


def cdx_document(keys, edges, prefix):
    components = [
        {"bom-ref": f"{prefix}/{key}", "purl": PURLS[key]} for key in keys
    ]
    depends_on: dict[str, list[str]] = {}
    for dependent, dependency in edges:
        depends_on.setdefault(dependent, []).append(f"{prefix}/{dependency}")
    dependencies = [
        {"ref": f"{prefix}/{dependent}", "dependsOn": targets}
        for dependent, targets in sorted(depends_on.items())
    ]
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": components,
    }
    if dependencies:
        document["dependencies"] = dependencies
    return document


def spdx_document(keys, edges, prefix):
    def spdx_id(key):
        return f"SPDXRef-{prefix}-{key}"

    document = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": f"SPDXRef-DOCUMENT-{prefix}",
        "name": f"document-{prefix}",
        "documentNamespace": f"https://example.com/{prefix}",
        "creationInfo": {"creators": ["Tool: test"]},
        "packages": [
            {
                "SPDXID": spdx_id(key),
                "name": key,
                "externalRefs": [
                    {
                        "referenceType": "purl",
                        "referenceLocator": PURLS[key],
                        "referenceCategory": "PACKAGE-MANAGER",
                    }
                ],
            }
            for key in keys
        ],
        "relationships": [
            {
                "spdxElementId": spdx_id(dependent),
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": spdx_id(dependency),
            }
            for dependent, dependency in edges
        ],
    }
    return document


def make_document(fmt, spec, prefix):
    if fmt == "cyclonedx":
        return cdx_document(spec["components"], spec["edges"], prefix)
    if fmt == "spdx":
        return spdx_document(spec["components"], spec["edges"], prefix)
    raise ValueError(fmt)


def osv_file_record():
    return [
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
    ]


class FaultingConnection:
    """Connection proxy failing write statements matching a predicate.

    Installed in place of ``catalog.connection`` while one import runs. The
    catalog keeps using ``with self.connection:`` and ``execute`` exactly as
    against a real sqlite connection; every other attribute delegates. When
    the predicate matches, the in-flight (still uncommitted) state is sampled
    before a ``sqlite3.OperationalError`` is raised, so a test can prove the
    failure happened after part of *this* replacement had been written.
    """

    def __init__(self, real, predicate):
        self._real = real
        self._predicate = predicate
        self.faulted: list[dict] = []

    def execute(self, sql, params=()):
        if self._predicate is not None and self._predicate(sql):
            self.faulted.append(self._sample_partial_write(sql))
            raise sqlite3.OperationalError("simulated media failure during write")
        return self._real.execute(sql, params)

    def _sample_partial_write(self, sql):
        source_id = self._real.execute(
            "SELECT id FROM sources WHERE service = ? AND name = ?",
            (SERVICE, TARGET_SOURCE),
        ).fetchone()[0]
        return {
            "statement": sql.strip().splitlines()[0],
            "target_component_declarations": self._real.execute(
                "SELECT COUNT(*) FROM component_sources WHERE source_id = ?",
                (source_id,),
            ).fetchone()[0],
            "target_dependency_declarations": self._real.execute(
                "SELECT COUNT(*) FROM dependency_sources WHERE source_id = ?",
                (source_id,),
            ).fetchone()[0],
            "new_component_present": self._real.execute(
                "SELECT COUNT(*) FROM components "
                "WHERE service = ? AND ecosystem = 'pypi' AND name = 'newlib'",
                (SERVICE,),
            ).fetchone()[0],
        }

    def __enter__(self):
        self._real.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        return self._real.__exit__(exc_type, exc, tb)

    def __getattr__(self, name):
        return getattr(self._real, name)


def fails_on_component_insert(sql):
    return sql.lstrip().startswith("INSERT INTO components")


def fails_on_dependency_insert(sql):
    return sql.lstrip().startswith("INSERT INTO dependencies")


class _SaveFailureRollbackScenario:
    """Whole scenario for one document format of the replaced source.

    ``ORIGIN_FORMAT`` is the replaced source's original format; the other
    source uses the other format, and the replacement document deliberately
    arrives in that other format too, so the guarantee is proven per incoming
    format as well as across a format switch.
    """

    ORIGIN_FORMAT = None

    def setUp(self):
        self.catalog = Catalog()
        other_format = "spdx" if self.ORIGIN_FORMAT == "cyclonedx" else "cyclonedx"
        # Two sources of the same service, one per supported format, sharing
        # the application, the library and their relationship.
        self.catalog.import_sbom(
            SERVICE,
            TARGET_SOURCE,
            make_document(self.ORIGIN_FORMAT, OLD_BUILD_SPEC, "build"),
        )
        self.catalog.import_sbom(
            SERVICE,
            OTHER_SOURCE,
            make_document(other_format, OTHER_SOURCE_SPEC, "audit"),
        )
        # Hand-registered data that no source declares: a component kept alive
        # by a manual relationship anchored on the shared application.
        self.catalog.add_component(SERVICE, "pypi", "manual-lib", "5.0")
        self.catalog.add_dependency(
            SERVICE, "pypi", "app", "1.0.0",
            SERVICE, "pypi", "manual-lib", "5.0",
        )
        # A real OSV hit on the library; the application is only affected
        # indirectly through the shared app -> lib relationship.
        self.catalog.import_osv(OSV_SOURCE, osv_file_record())
        # An approved exemption that is still in force at the evaluation time.
        self.catalog.request_exemption(
            EXEMPTION_ID,
            SERVICE, "pypi", "app", "1.0.0",
            CVE, "lib", OSV_SOURCE,
            applicant="alice",
            reason="upstream fix backported; egress filtered",
            expires_at=EXPIRES_AT,
            submitted_at=SUBMITTED_AT,
        )
        self.catalog.approve_exemption(
            EXEMPTION_ID, "bob", "controls verified", decided_at=DECIDED_AT
        )
        self.replacement_document = make_document(
            other_format, NEW_BUILD_SPEC, "build-new"
        )

    def tearDown(self):
        self.catalog.close()

    # -- catalog state probes -------------------------------------------

    def _component_names(self):
        return sorted(
            row[0]
            for row in self.catalog.connection.execute(
                "SELECT name FROM components WHERE service = ? ORDER BY name",
                (SERVICE,),
            )
        )

    def _edge_pairs(self):
        rows = self.catalog.connection.execute(
            """
            SELECT c1.name, c2.name
            FROM dependencies d
            JOIN components c1 ON c1.id = d.dependent_id
            JOIN components c2 ON c2.id = d.dependency_id
            ORDER BY c1.name, c2.name
            """
        )
        return sorted((row[0], row[1]) for row in rows)

    def _component_owners(self):
        owners: dict[str, list[str]] = {}
        rows = self.catalog.connection.execute(
            """
            SELECT c.name, s.name
            FROM component_sources cs
            JOIN components c ON c.id = cs.component_id
            JOIN sources s ON s.id = cs.source_id
            ORDER BY c.name, s.name
            """
        )
        for name, source in rows:
            owners.setdefault(name, []).append(source)
        return owners

    def _edge_owners(self):
        owners: dict[tuple, list[str]] = {}
        rows = self.catalog.connection.execute(
            """
            SELECT c1.name, c2.name, s.name
            FROM dependency_sources ds
            JOIN dependencies d ON d.id = ds.dependency_id
            JOIN components c1 ON c1.id = d.dependent_id
            JOIN components c2 ON c2.id = d.dependency_id
            JOIN sources s ON s.id = ds.source_id
            ORDER BY c1.name, c2.name, s.name
            """
        )
        for first, second, source in rows:
            owners.setdefault((first, second), []).append(source)
        return owners

    def _manual_components(self):
        return sorted(
            row[0]
            for row in self.catalog.connection.execute(
                "SELECT name FROM components WHERE manual = 1 ORDER BY name"
            )
        )

    def _manual_edges(self):
        rows = self.catalog.connection.execute(
            """
            SELECT c1.name, c2.name
            FROM dependencies d
            JOIN components c1 ON c1.id = d.dependent_id
            JOIN components c2 ON c2.id = d.dependency_id
            WHERE d.manual = 1
            ORDER BY c1.name, c2.name
            """
        )
        return sorted((row[0], row[1]) for row in rows)

    # -- expected pre-failure state -------------------------------------

    EXPECTED_COMPONENTS = ["app", "bonly", "lib", "manual-lib", "oldonly"]
    EXPECTED_EDGES = sorted(
        [("app", "bonly"), ("app", "lib"), ("app", "manual-lib"),
         ("app", "oldonly")]
    )
    EXPECTED_COMPONENT_OWNERS = {
        "app": [OTHER_SOURCE, TARGET_SOURCE],
        "lib": [OTHER_SOURCE, TARGET_SOURCE],
        "oldonly": [TARGET_SOURCE],
        "bonly": [OTHER_SOURCE],
    }
    EXPECTED_EDGE_OWNERS = {
        ("app", "lib"): [OTHER_SOURCE, TARGET_SOURCE],
        ("app", "oldonly"): [TARGET_SOURCE],
        ("app", "bonly"): [OTHER_SOURCE],
    }

    def _assert_old_catalog_intact(self):
        # All original components and relationships are present...
        self.assertEqual(self._component_names(), self.EXPECTED_COMPONENTS)
        self.assertEqual(self._edge_pairs(), self.EXPECTED_EDGES)
        # ...with exactly their original source declarations...
        self.assertEqual(self._component_owners(), self.EXPECTED_COMPONENT_OWNERS)
        self.assertEqual(self._edge_owners(), self.EXPECTED_EDGE_OWNERS)
        # ...the hand-registered data is still manual...
        self.assertEqual(self._manual_components(), ["manual-lib"])
        self.assertEqual(self._manual_edges(), [("app", "manual-lib")])
        # ...and nothing of the new manifest lingered.
        self.assertNotIn("newlib", self._component_names())
        self.assertNotIn(("app", "newlib"), self._edge_pairs())
        # app/lib declared by both sources, oldonly only by the replaced
        # source, bonly only by the other source = 6 ownership rows; the
        # manual app -> manual-lib edge carries no source, so the three
        # declared edges (app->lib twice) = 4 rows.
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM component_sources"
            ).fetchone()[0],
            6,
        )
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM dependency_sources"
            ).fetchone()[0],
            4,
        )

    def _report_snapshot(self):
        return {
            "summary": asdict(self.catalog.summary()),
            "impact": self.catalog.impact(service=SERVICE),
            "risk_report": self.catalog.risk_report(
                service=SERVICE, evaluated_at=EVALUATED_AT
            ),
            "exemption": self.catalog.get_exemption(EXEMPTION_ID),
        }

    def _assert_exemption_still_applied(self):
        # The library is hit directly; the application's indirect record stays
        # covered by the very same approved exemption at the same instant.
        report = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVALUATED_AT
        )
        impacts = {
            (entry["component"]["name"]): entry
            for entry in report["impacts"]
        }
        self.assertEqual(sorted(impacts), ["app", "lib"])
        self.assertTrue(impacts["lib"]["direct"])
        self.assertFalse(impacts["lib"]["exempted"])
        self.assertFalse(impacts["app"]["direct"])
        self.assertEqual(
            [node["name"] for node in impacts["app"]["path"]], ["app", "lib"]
        )
        self.assertTrue(impacts["app"]["exempted"])
        self.assertEqual(impacts["app"]["exemption_request"], EXEMPTION_ID)
        self.assertEqual(report["unhandled_component_count"], 1)
        self.assertEqual(report["highest_severity"], "high")

    def _run_failed_replace(self, predicate):
        proxy = FaultingConnection(self.catalog.connection, predicate)
        self.catalog.connection = proxy
        try:
            with self.assertRaises(sqlite3.Error) as caught:
                self.catalog.import_sbom(
                    SERVICE, TARGET_SOURCE, self.replacement_document
                )
            # A database failure surfaces, never a successful ImportResult.
            self.assertIn("simulated media failure", str(caught.exception))
        finally:
            real = proxy._real
            proxy._predicate = None
            self.catalog.connection = real
        return proxy.faulted

    # -- the actual regression tests ------------------------------------

    def test_component_save_failure_after_partial_write_rolls_back(self):
        shots = self._run_failed_replace(fails_on_component_insert)
        # The failure really was a save-phase failure: replacing had started,
        # old ownership had been withdrawn and part of this replacement was
        # already written inside the open transaction...
        self.assertTrue(shots)
        self.assertTrue(
            any(shot["target_component_declarations"] >= 1 for shot in shots),
            shots,
        )
        self.assertTrue(
            all(shot["statement"].startswith("INSERT INTO components")
                for shot in shots),
            shots,
        )
        # ...yet after the error no mixed state remains.
        self._assert_old_catalog_intact()

    def test_dependency_save_failure_after_partial_write_rolls_back(self):
        shots = self._run_failed_replace(fails_on_dependency_insert)
        # Component saving for this replacement had already finished (all four
        # target components declared, the brand-new component inserted) and at
        # least one dependency declaration was written when the edge insert
        # failed - partial data of this replacement existed at failure time.
        self.assertTrue(shots)
        self.assertTrue(
            any(
                shot["target_component_declarations"] == 4
                and shot["new_component_present"] == 1
                and shot["target_dependency_declarations"] >= 1
                for shot in shots
            ),
            shots,
        )
        self.assertTrue(
            all(shot["statement"].startswith("INSERT INTO dependencies")
                for shot in shots),
            shots,
        )
        # The rollback restores the whole old declaration, including the
        # withdrawn app -> oldonly edge the new list no longer declares.
        self._assert_old_catalog_intact()

    def test_failed_save_leaves_reports_and_exemption_identical(self):
        before = self._report_snapshot()
        for predicate in (
            fails_on_component_insert,
            fails_on_dependency_insert,
        ):
            with self.subTest(predicate=predicate):
                self._run_failed_replace(predicate)
                after = self._report_snapshot()
                # Same evaluation instant: component counts, impact paths and
                # exemption results reproduce byte-for-byte, including the
                # request content and its full processing history.
                self.assertEqual(after, before)
                self._assert_exemption_still_applied()

    def test_failed_replace_does_not_block_the_existing_entry_point(self):
        self._run_failed_replace(fails_on_dependency_insert)
        # The old declaration is still live: re-importing its exact content
        # through the existing entry point adds and removes nothing, and the
        # normal successful result keeps its usual shape.
        result = self.catalog.import_sbom(
            SERVICE,
            TARGET_SOURCE,
            make_document(self.ORIGIN_FORMAT, OLD_BUILD_SPEC, "build"),
        )
        self.assertEqual(result.source_components, 3)
        self.assertEqual(result.added_components, 0)
        self.assertEqual(result.deleted_components, 0)
        self.assertEqual(result.added_dependencies, 0)
        self.assertEqual(result.deleted_dependencies, 0)
        self._assert_old_catalog_intact()

    def test_withdrawing_other_source_after_failure_keeps_old_declaration(self):
        # Reports before the failed replacement - impact must survive both the
        # failed save and the later withdrawal of the other source.
        impact_before = self.catalog.impact(service=SERVICE)
        # The interrupted replacement must not have loosened ownership even
        # transiently: the failed source's old declaration still owns the
        # shared app/lib, its unique oldonly component and both edges.
        self._run_failed_replace(fails_on_dependency_insert)
        self._assert_old_catalog_intact()

        # A normal withdrawal of the *other* source then succeeds...
        other_format = "spdx" if self.ORIGIN_FORMAT == "cyclonedx" else "cyclonedx"
        result = self.catalog.import_sbom(
            SERVICE, OTHER_SOURCE,
            make_document(other_format, EMPTY_SPEC, "empty"),
        )
        self.assertEqual(result.source_components, 0)
        # ...removing exactly what only that source used to declare: bonly and
        # the app -> bonly edge actually leave the catalog.
        self.assertEqual(result.added_components, 0)
        self.assertEqual(result.deleted_components, 1)
        self.assertEqual(result.added_dependencies, 0)
        self.assertEqual(result.deleted_dependencies, 1)

        # Shared objects are still present - and not as orphans: the failed
        # source's surviving old declaration is now their sole owner, so the
        # shared components/edge lingering in the catalog cannot hide a lost
        # source attribution.
        self.assertEqual(
            self._component_names(),
            ["app", "lib", "manual-lib", "oldonly"],
        )
        self.assertEqual(
            self._edge_pairs(),
            sorted([("app", "lib"), ("app", "manual-lib"), ("app", "oldonly")]),
        )
        self.assertEqual(
            self._component_owners(),
            {
                "app": [TARGET_SOURCE],
                "lib": [TARGET_SOURCE],
                "oldonly": [TARGET_SOURCE],
            },
        )
        self.assertEqual(
            self._edge_owners(),
            {
                ("app", "lib"): [TARGET_SOURCE],
                ("app", "oldonly"): [TARGET_SOURCE],
            },
        )
        # Hand-registered data is untouched by either operation.
        self.assertEqual(self._manual_components(), ["manual-lib"])
        self.assertEqual(self._manual_edges(), [("app", "manual-lib")])

        # The old app -> lib edge keeps the application indirectly impacted
        # and the exemption in force; the failed replacement and the other
        # source's normal withdrawal changed neither vulnerability matching
        # nor exemption application.
        self.assertEqual(self.catalog.impact(service=SERVICE), impact_before)
        self._assert_exemption_still_applied()
        self.assertEqual(self.catalog.summary().affected_components, 2)


class CycloneDXReplacedSourceRollbackTests(
    _SaveFailureRollbackScenario, unittest.TestCase
):
    # Replaced source is CycloneDX 1.5; the other source and the replacement
    # document are SPDX 2.3.
    ORIGIN_FORMAT = "cyclonedx"


class SPDXReplacedSourceRollbackTests(
    _SaveFailureRollbackScenario, unittest.TestCase
):
    # Replaced source is SPDX 2.3; the other source and the replacement
    # document are CycloneDX 1.5.
    ORIGIN_FORMAT = "spdx"


class SourceReplacementRollbackCliTests(unittest.TestCase):
    """The CLI entry point must report failure, not import statistics."""

    def _write(self, directory, name, document):
        path = Path(directory, name)
        path.write_text(json.dumps(document))
        return str(path)

    def test_cli_save_failure_returns_error_and_keeps_old_declaration(self):
        for new_format in ("cyclonedx", "spdx"):
            with self.subTest(new_format=new_format):
                with tempfile.TemporaryDirectory() as directory:
                    database = str(Path(directory, "catalog.db"))
                    # Same two-formats-one-service setup, seeded directly.
                    seeder = Catalog(database)
                    seeder.import_sbom(
                        SERVICE, TARGET_SOURCE,
                        make_document("cyclonedx", OLD_BUILD_SPEC, "build"),
                    )
                    seeder.import_sbom(
                        SERVICE, OTHER_SOURCE,
                        make_document("spdx", OTHER_SOURCE_SPEC, "audit"),
                    )
                    seeder.close()
                    new_path = self._write(
                        directory,
                        f"new-{new_format}.json",
                        make_document(new_format, NEW_BUILD_SPEC, "build-new"),
                    )

                    class FaultingCatalog(Catalog):
                        def __init__(self, db=":memory:"):
                            super().__init__(db)
                            self.connection = FaultingConnection(
                                self.connection, fails_on_dependency_insert
                            )

                    original_catalog = cli_module.Catalog
                    cli_module.Catalog = FaultingCatalog
                    stdout = io.StringIO()
                    try:
                        with contextlib.redirect_stdout(stdout):
                            # The entry point surfaces a save-phase database
                            # failure as a failure (it propagates, so the
                            # process exits non-zero) rather than returning the
                            # usual success status and statistics.
                            with self.assertRaises(sqlite3.Error):
                                cli_module.main(
                                    ["--database", database, "import-sbom",
                                     SERVICE, TARGET_SOURCE, new_path]
                                )
                    finally:
                        cli_module.Catalog = original_catalog

                    # No successful import statistics may be reported.
                    self.assertNotIn("来源组件数", stdout.getvalue())

                    reopened = Catalog(database)
                    try:
                        self.assertEqual(
                            sorted(
                                row[0]
                                for row in reopened.connection.execute(
                                    "SELECT name FROM components "
                                    "WHERE service = ? ORDER BY name",
                                    (SERVICE,),
                                )
                            ),
                            ["app", "bonly", "lib", "oldonly"],
                        )
                        rows = reopened.connection.execute(
                            """
                            SELECT c1.name, c2.name
                            FROM dependencies d
                            JOIN components c1 ON c1.id = d.dependent_id
                            JOIN components c2 ON c2.id = d.dependency_id
                            ORDER BY c1.name, c2.name
                            """
                        )
                        self.assertEqual(
                            sorted((row[0], row[1]) for row in rows),
                            sorted([("app", "bonly"), ("app", "lib"),
                                    ("app", "oldonly")]),
                        )
                        self.assertEqual(
                            reopened.connection.execute(
                                "SELECT COUNT(*) FROM component_sources"
                            ).fetchone()[0],
                            6,
                        )
                        self.assertEqual(
                            reopened.connection.execute(
                                "SELECT COUNT(*) FROM dependency_sources"
                            ).fetchone()[0],
                            4,
                        )
                    finally:
                        reopened.close()


if __name__ == "__main__":
    unittest.main()
