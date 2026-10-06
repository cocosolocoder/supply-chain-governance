"""Regression tests for manual-dependency revocation failing *during* the save.

``remove_dependency`` only revokes the target relationship's *manual*
registration and then reapplies the one retention rule, scoped to exactly that
edge and its two endpoints. A relationship still declared by an SBOM source
stays (and keeps participating in impact analysis); once the last basis is
gone the edge leaves and each endpoint is judged independently. The existing
tests cover the normal cleanup (edge and unneeded endpoints leave, an endpoint
another source still declares stays) and the input/leniency rules (empty
fields rejected; nonexistent target or relationship succeeds without writes).

These tests cover the other half of the contract: an existing, valid target
whose manual revocation has already started, and that then hits a database
write error in one of the operation's two save phases -

1. revoking the manual registration (``UPDATE dependencies SET manual = 0``);
2. cleaning up the endpoints (``DELETE FROM components``) *after* the
   relationship has already left the catalog inside the same transaction
   (``DELETE FROM dependencies`` already ran).

The scenario is the one the rule exists for: an SBOM once declared
app -> lib, the user registered the very same relationship by hand, and the
SBOM has since withdrawn its declaration, so the manual registration is the
only thing still holding the edge and (through the manual-edge anchor) its two
endpoints in the catalog. The library carries a real vulnerability, so the
application is affected only indirectly and that indirect impact holds an
approved, unexpired exemption.

A failure in either save phase must fail the whole revocation atomically and
restore the pre-operation catalog:

* the call raises a database error, never a successful no-op;
* the relationship's manual registration is not lost - the edge is still
  ``manual = 1`` and its two endpoints keep their full
  (service, ecosystem, name, version) identity;
* no manual information and no source declaration is partially cleaned - the
  other-version components/relationship of the same service, the same-named
  components/relationship of another service, and every source ownership row
  stay exactly as they were;
* summary (component count, affected components, vulnerability count, highest
  severity), the direct/indirect impact records with their dependency paths,
  and the risk report at the same evaluation instant (exemption linkage,
  unhandled-component count, highest severity) are byte-for-byte identical;
* existing vulnerability data, the exemption request and its full processing
  history never change.

A contrast class shows empty fields and nonexistent targets/relationships
reach no save statement at all, so they cannot be mistaken for the
mid-save failures above (which demonstrably wrote and then rolled back). A
final class keeps the fault-free behavior: when the last retention basis
disappears the edge and the endpoints it alone anchored leave immediately, an
endpoint another source still declares survives on its own, a relationship an
SBOM still declares survives the revocation of its manual flag, and successful
component cleanup never deletes vulnerability data or exemption history.
"""

import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from supply_guard.catalog import Catalog, format_timestamp
from supply_guard.cli import main

SERVICE = "api"
OTHER_SERVICE = "worker"
SOURCE = "build"
LEGACY_SOURCE = "legacy"
SECOND_SOURCE = "audit"
OSV_SOURCE = "nvd"
CVE = "CVE-2026-7001"
EXEMPTION_ID = "EXM-2026-7001"

APPLICANT = "alice"
APPROVER = "bob"
REQUEST_REASON = "egress proxy mitigates the transitive library exposure"
APPROVAL_NOTE = "compensating controls verified"

# Fixed instants keep the exemption term and every report deterministic.
SUBMITTED_AT = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
APPROVED_AT = datetime(2026, 1, 2, 0, 0, tzinfo=timezone.utc)
EXPIRES_AT = "2026-12-31T23:59:59+00:00"
EVAL_AT = "2026-06-01T00:00:00+00:00"

APP_PURL = "pkg:pypi/app@1.0.0"
LIB_PURL = "pkg:pypi/lib@2.0.0"
LEGACY_PURL = "pkg:pypi/legacyapp@0.9.0"
LIB_OLD_PURL = "pkg:pypi/lib@1.0.0"

APP_ID = (SERVICE, "pypi", "app", "1.0.0")
LIB_ID = (SERVICE, "pypi", "lib", "2.0.0")
LEGACY_ID = (SERVICE, "pypi", "legacyapp", "0.9.0")
LIB_OLD_ID = (SERVICE, "pypi", "lib", "1.0.0")
WORKER_APP_ID = (OTHER_SERVICE, "pypi", "app", "1.0.0")
WORKER_LIB_ID = (OTHER_SERVICE, "pypi", "lib", "2.0.0")


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


def initial_declaration():
    """The SBOM's original declaration: app -> lib in service api."""
    return cdx(
        [cc("build/app", APP_PURL), cc("build/lib", LIB_PURL)],
        [{"ref": "build/app", "dependsOn": ["build/lib"]}],
    )


def legacy_declaration():
    """Other versions in the SAME service, with their own relationship."""
    return cdx(
        [cc("legacy/app", LEGACY_PURL), cc("legacy/lib", LIB_OLD_PURL)],
        [{"ref": "legacy/app", "dependsOn": ["legacy/lib"]}],
    )


def worker_declaration():
    """Same-named components/relationship in a DIFFERENT service."""
    return cdx(
        [cc("worker/app", APP_PURL), cc("worker/lib", LIB_PURL)],
        [{"ref": "worker/app", "dependsOn": ["worker/lib"]}],
    )


def lib_only_declaration():
    """A second source that declares the api library component, no edge."""
    return cdx([cc("audit/lib", LIB_PURL)])


def osv_records():
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


# Write errors injected at each revocation save phase. The triggers live in the
# same database the revocation writes to, so the failure goes through SQLite
# exactly like a real disk/constraint error: the statement fails and the
# surrounding revocation transaction must roll back.

# Phase 1: persisting the manual-flag revocation itself is rejected. The WHEN
# clause restricts the fault to a row actually leaving manual registration
# (the UPDATE remove_dependency issues), so reads and every unrelated
# statement are unaffected. The relationship never leaves and endpoint
# cleanup is never reached in this phase.
RELATION_REVOCATION_FAILURE_TRIGGER = """
CREATE TRIGGER fail_manual_revocation
BEFORE UPDATE ON dependencies
WHEN NEW.manual = 0 AND OLD.manual = 1
BEGIN
    SELECT RAISE(ABORT, 'injected relationship-revocation write error');
END
"""

# Phase 2: the manual UPDATE and the edge DELETE have both already run inside
# the transaction (the relationship is gone), and cleaning up the now
# unanchored endpoints is rejected. The NOT EXISTS guard makes the trigger
# fire precisely for that post-edge-deletion DELETE: within the same
# transaction the trigger's subquery already observes the deleted edge. A
# DELETE on another service's components never enters this WHEN clause.
ENDPOINT_CLEANUP_FAILURE_TRIGGER = """
CREATE TRIGGER fail_endpoint_cleanup
BEFORE DELETE ON components
WHEN OLD.service = 'api'
 AND OLD.name IN ('app', 'lib')
 AND OLD.version IN ('1.0.0', '2.0.0')
 AND NOT EXISTS (
        SELECT 1 FROM dependencies d
        JOIN components c1 ON c1.id = d.dependent_id
        JOIN components c2 ON c2.id = d.dependency_id
        WHERE c1.service = 'api' AND c2.service = 'api'
          AND c1.name = 'app' AND c2.name = 'lib'
          AND c1.version = '1.0.0' AND c2.version = '2.0.0'
     )
BEGIN
    SELECT RAISE(ABORT, 'injected endpoint-cleanup write error');
END
"""


def build_catalog(database: str | Path) -> Catalog:
    """Create the pre-revocation scenario shared by every regression case.

    In service ``api`` the ``build`` SBOM once declared app 1.0.0 -> lib
    2.0.0; the user then registered that very relationship by hand, and the
    SBOM has since withdrawn its declaration, so the manual registration is
    the sole basis keeping the edge and its two endpoints. A ``legacy``
    source still declares other versions (legacyapp 0.9.0 -> lib 1.0.0) in
    the same service. Another service ``worker`` owns same-named app/lib
    components with their own edge. A local OSV source directly hits the
    pinned lib 2.0.0 (high), so the api application is affected only
    indirectly; that indirect impact already has one approved, unexpired
    exemption.
    """
    catalog = Catalog(database)
    catalog.import_sbom(SERVICE, SOURCE, initial_declaration())
    catalog.add_dependency(
        SERVICE, "pypi", "app", "1.0.0",
        SERVICE, "pypi", "lib", "2.0.0",
    )
    # The SBOM withdraws its declaration; the manual edge alone must hold.
    catalog.import_sbom(SERVICE, SOURCE, cdx([]))
    catalog.import_sbom(SERVICE, LEGACY_SOURCE, legacy_declaration())
    catalog.import_sbom(OTHER_SERVICE, SOURCE, worker_declaration())
    catalog.import_osv(OSV_SOURCE, osv_records())
    catalog.request_exemption(
        EXEMPTION_ID,
        SERVICE, "pypi", "app", "1.0.0",
        CVE, "lib", OSV_SOURCE,
        applicant=APPLICANT,
        reason=REQUEST_REASON,
        expires_at=EXPIRES_AT,
        submitted_at=SUBMITTED_AT,
    )
    catalog.approve_exemption(
        EXEMPTION_ID, handler=APPROVER, note=APPROVAL_NOTE,
        decided_at=APPROVED_AT,
    )
    return catalog


def component_rows(catalog: Catalog) -> dict[tuple, int]:
    """Every component identity with its manual flag."""
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
    """Every dependency edge as (dependent identity, dependency identity)."""
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


def component_owners(catalog: Catalog) -> list[tuple]:
    """Every component source declaration, as full identity + source name."""
    return [
        (
            str(row["service"]), str(row["ecosystem"]),
            str(row["name"]), str(row["version"]), str(row["source"]),
        )
        for row in catalog.connection.execute(
            """
            SELECT c.service AS service, c.ecosystem AS ecosystem, c.name AS name,
                   c.version AS version, s.name AS source
            FROM component_sources cs
            JOIN components c ON c.id = cs.component_id
            JOIN sources s ON s.id = cs.source_id
            ORDER BY c.service, c.name, c.version, s.name
            """
        )
    ]


def dependency_owners(catalog: Catalog) -> list[tuple]:
    """Every relationship source declaration, full identities + source name."""
    return [
        (
            str(row["s1"]), str(row["n1"]), str(row["v1"]),
            str(row["n2"]), str(row["v2"]), str(row["source"]),
        )
        for row in catalog.connection.execute(
            """
            SELECT c1.service AS s1, c1.name AS n1, c1.version AS v1,
                   c2.name AS n2, c2.version AS v2, s.name AS source
            FROM dependency_sources ds
            JOIN dependencies d ON d.id = ds.dependency_id
            JOIN components c1 ON c1.id = d.dependent_id
            JOIN components c2 ON c2.id = d.dependency_id
            JOIN sources s ON s.id = ds.source_id
            ORDER BY c1.service, c1.name, c2.name, s.name
            """
        )
    ]


def source_rows(catalog: Catalog) -> list[tuple]:
    return [
        (str(row["service"]), str(row["name"]))
        for row in catalog.connection.execute(
            "SELECT service, name FROM sources ORDER BY service, name"
        )
    ]


def osv_rows(catalog: Catalog) -> list[tuple]:
    """OSV vulnerability data with its conditions parsed, for raw comparison."""
    return [
        (
            str(row["source"]), str(row["id"]), str(row["package_name"]),
            str(row["severity"]), int(row["severity_default"]),
            None if row["withdrawn"] is None else str(row["withdrawn"]),
            json.loads(row["conditions"]),
        )
        for row in catalog.connection.execute(
            """
            SELECT source, id, package_name, severity, severity_default,
                   withdrawn, conditions
            FROM osv_vulnerabilities
            ORDER BY source, id, package_name
            """
        )
    ]


def manual_vulnerability_rows(catalog: Catalog) -> list[tuple]:
    return [
        (str(row["id"]), str(row["component_name"]), str(row["severity"]))
        for row in catalog.connection.execute(
            "SELECT id, component_name, severity FROM vulnerabilities "
            "ORDER BY id, component_name"
        )
    ]


def exemption_event_rows(catalog: Catalog) -> list[tuple]:
    return [
        (
            str(row["request_id"]), int(row["seq"]), str(row["occurred_at"]),
            str(row["actor"]), str(row["action"]), str(row["reason"]),
            None if row["from_status"] is None else str(row["from_status"]),
            str(row["to_status"]),
        )
        for row in catalog.connection.execute(
            """
            SELECT request_id, seq, occurred_at, actor, action, reason,
                   from_status, to_status
            FROM exemption_events
            ORDER BY request_id, seq
            """
        )
    ]


def take_snapshot(catalog: Catalog) -> dict:
    """Everything a failed revocation must leave byte-for-byte untouched."""
    summary = catalog.summary()
    return {
        "components": component_rows(catalog),
        "dependencies": dependency_rows(catalog),
        "component_owners": component_owners(catalog),
        "dependency_owners": dependency_owners(catalog),
        "sources": source_rows(catalog),
        "osv_rows": osv_rows(catalog),
        "manual_vulnerabilities": manual_vulnerability_rows(catalog),
        "exemption_events": exemption_event_rows(catalog),
        "summary": (
            summary.components,
            summary.affected_components,
            summary.vulnerabilities,
            summary.highest_severity,
        ),
        "impact_all": catalog.impact(),
        "impact_api": catalog.impact(service=SERVICE),
        "impact_worker": catalog.impact(service=OTHER_SERVICE),
        "risk_all": catalog.risk_report(evaluated_at=EVAL_AT),
        "risk_api": catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT),
        "risk_worker": catalog.risk_report(
            service=OTHER_SERVICE, evaluated_at=EVAL_AT
        ),
        "exemption": catalog.get_exemption(EXEMPTION_ID),
    }


# The exact pre-operation directory state, made explicit so the before/after
# equality never hides a wrong expectation.
EXPECTED_COMPONENTS = {
    APP_ID: 0,
    LIB_ID: 0,
    LEGACY_ID: 0,
    LIB_OLD_ID: 0,
    WORKER_APP_ID: 0,
    WORKER_LIB_ID: 0,
}
EXPECTED_DEPENDENCIES = {
    # The target edge: manually registered, declared by no remaining source.
    (APP_ID, LIB_ID): 1,
    # Other-version edge in the same service, source-declared.
    (LEGACY_ID, LIB_OLD_ID): 0,
    # Same-named edge in another service, source-declared.
    (WORKER_APP_ID, WORKER_LIB_ID): 0,
}
EXPECTED_COMPONENT_OWNERS = [
    (SERVICE, "pypi", "legacyapp", "0.9.0", LEGACY_SOURCE),
    (SERVICE, "pypi", "lib", "1.0.0", LEGACY_SOURCE),
    (OTHER_SERVICE, "pypi", "app", "1.0.0", SOURCE),
    (OTHER_SERVICE, "pypi", "lib", "2.0.0", SOURCE),
]
EXPECTED_DEPENDENCY_OWNERS = [
    (SERVICE, "legacyapp", "0.9.0", "lib", "1.0.0", LEGACY_SOURCE),
    (OTHER_SERVICE, "app", "1.0.0", "lib", "2.0.0", SOURCE),
]
EXPECTED_SOURCES = [
    (SERVICE, SOURCE),
    (SERVICE, LEGACY_SOURCE),
    (OTHER_SERVICE, SOURCE),
]
EXPECTED_OSV_ROWS = [
    (
        OSV_SOURCE, CVE, "lib", "high", 0, None,
        [{"type": "explicit", "version": "2.0.0"}],
    ),
]
EXPECTED_EVENTS = [
    (
        EXEMPTION_ID, 1, format_timestamp(SUBMITTED_AT),
        APPLICANT, "request", REQUEST_REASON, None, "pending",
    ),
    (
        EXEMPTION_ID, 2, format_timestamp(APPROVED_AT),
        APPROVER, "approve", APPROVAL_NOTE, "pending", "approved",
    ),
]


class _RevocationStateAssertions:
    """Post-failure contract checks shared by the rollback test classes."""

    def _assert_catalog_state_pristine(self, catalog: Catalog) -> None:
        # The target relationship's manual registration survived, and both
        # target endpoints keep their full identity - never a partial cleanup.
        self.assertEqual(component_rows(catalog), EXPECTED_COMPONENTS)
        self.assertEqual(dependency_rows(catalog), EXPECTED_DEPENDENCIES)
        self.assertEqual(dependency_rows(catalog)[(APP_ID, LIB_ID)], 1)

        # Every source declaration is exactly as before: the withdrawn target
        # edge has none, the other-version and other-service data keeps theirs.
        self.assertEqual(component_owners(catalog), EXPECTED_COMPONENT_OWNERS)
        self.assertEqual(dependency_owners(catalog), EXPECTED_DEPENDENCY_OWNERS)
        self.assertEqual(source_rows(catalog), EXPECTED_SOURCES)
        self.assertEqual(
            catalog.connection.execute(
                "SELECT COUNT(*) FROM component_sources"
            ).fetchone()[0],
            4,
        )
        self.assertEqual(
            catalog.connection.execute(
                "SELECT COUNT(*) FROM dependency_sources"
            ).fetchone()[0],
            2,
        )

        # Vulnerability data and exemption processing history are untouched.
        self.assertEqual(osv_rows(catalog), EXPECTED_OSV_ROWS)
        self.assertEqual(manual_vulnerability_rows(catalog), [])
        self.assertEqual(exemption_event_rows(catalog), EXPECTED_EVENTS)

    def _assert_snapshot_intact(self, catalog: Catalog, snapshot: dict) -> None:
        self.assertEqual(take_snapshot(catalog), snapshot)
        self._assert_catalog_state_pristine(catalog)

    def _assert_impact_and_report_semantics(self, catalog: Catalog) -> None:
        # Library 2.0.0 is hit directly in both services; each service's
        # application is affected only indirectly through its own edge. The
        # other-version lib 1.0.0 and legacyapp do not match ==2.0.0.
        records = {
            (record["component"]["service"], record["component"]["name"]):
            record
            for record in catalog.impact()
        }
        self.assertEqual(
            sorted(records),
            [
                (SERVICE, "app"), (SERVICE, "lib"),
                (OTHER_SERVICE, "app"), (OTHER_SERVICE, "lib"),
            ],
        )
        api_app = records[(SERVICE, "app")]
        api_lib = records[(SERVICE, "lib")]
        worker_app = records[(OTHER_SERVICE, "app")]
        worker_lib = records[(OTHER_SERVICE, "lib")]

        self.assertTrue(api_lib["direct"])
        self.assertFalse(api_app["direct"])
        self.assertEqual(
            [(node["service"], node["name"]) for node in api_app["path"]],
            [(SERVICE, "app"), (SERVICE, "lib")],
        )
        self.assertEqual(api_app["vulnerability"], CVE)
        self.assertEqual(api_app["matched_name"], "lib")
        self.assertEqual(api_app["source"], OSV_SOURCE)
        self.assertEqual(api_app["severity"], "high")
        self.assertEqual(api_app["severity_basis"], "declared")
        self.assertEqual(api_app["matched_conditions"], ["==2.0.0"])
        self.assertTrue(worker_lib["direct"])
        self.assertFalse(worker_app["direct"])
        self.assertEqual(
            [(node["service"], node["name"]) for node in worker_app["path"]],
            [(OTHER_SERVICE, "app"), (OTHER_SERVICE, "lib")],
        )

        summary = catalog.summary()
        self.assertEqual(
            (
                summary.components, summary.affected_components,
                summary.vulnerabilities, summary.highest_severity,
            ),
            (6, 4, 1, "high"),
        )

        # At the fixed evaluation instant the api application's approved,
        # unexpired exemption still covers exactly its indirect record; the
        # directly hit library stays unhandled.
        api_report = catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
        api_by_name = {
            entry["component"]["name"]: entry for entry in api_report["impacts"]
        }
        self.assertEqual(sorted(api_by_name), ["app", "lib"])
        self.assertTrue(api_by_name["app"]["exempted"])
        self.assertEqual(api_by_name["app"]["exemption_request"], EXEMPTION_ID)
        self.assertIsNone(api_by_name["app"]["not_exempt_reason"])
        self.assertFalse(api_by_name["app"]["direct"])
        self.assertFalse(api_by_name["lib"]["exempted"])
        self.assertTrue(api_by_name["lib"]["direct"])
        self.assertIsNone(api_by_name["lib"]["exemption_request"])
        self.assertEqual(api_report["impact_count"], 2)
        self.assertEqual(api_report["unhandled_component_count"], 1)
        self.assertEqual(api_report["highest_severity"], "high")

        # Another service neither shares the exemption nor loses its own risk.
        worker_report = catalog.risk_report(
            service=OTHER_SERVICE, evaluated_at=EVAL_AT
        )
        self.assertEqual(worker_report["impact_count"], 2)
        self.assertEqual(worker_report["unhandled_component_count"], 2)
        self.assertEqual(worker_report["highest_severity"], "high")
        self.assertFalse(
            any(entry["exempted"] for entry in worker_report["impacts"])
        )

        # Directory-wide: four records, three unhandled components (the api
        # application's indirect hit is the one exempted record), high on top.
        full_report = catalog.risk_report(evaluated_at=EVAL_AT)
        self.assertEqual(full_report["impact_count"], 4)
        self.assertEqual(full_report["unhandled_component_count"], 3)
        self.assertEqual(full_report["highest_severity"], "high")
        exempted = [
            (entry["component"]["service"], entry["component"]["name"])
            for entry in full_report["impacts"]
            if entry["exempted"]
        ]
        self.assertEqual(exempted, [(SERVICE, "app")])

        # The exemption request and its complete history stay exactly intact.
        record = catalog.get_exemption(EXEMPTION_ID)
        self.assertEqual(record["status"], "approved")
        self.assertEqual(record["scope"], {
            "service": SERVICE,
            "ecosystem": "pypi",
            "name": "app",
            "version": "1.0.0",
            "vulnerability": CVE,
            "matched_name": "lib",
            "source": OSV_SOURCE,
        })
        self.assertEqual(record["applicant"], APPLICANT)
        self.assertEqual(record["reason"], REQUEST_REASON)
        self.assertEqual(record["approver"], APPROVER)
        self.assertEqual(record["decision_note"], APPROVAL_NOTE)
        self.assertEqual(record["approved_severity"], "high")
        self.assertEqual(
            [event["action"] for event in record["events"]],
            ["request", "approve"],
        )
        self.assertEqual(
            [event["seq"] for event in record["events"]], [1, 2]
        )


class RemoveDependencySaveFailureRollbackTests(
    _RevocationStateAssertions, unittest.TestCase
):
    """A write error in either save phase fails the revocation atomically."""

    def _run_failure_scenario(self, phase: str, trigger: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)
            snapshot = take_snapshot(catalog)
            self._assert_catalog_state_pristine(catalog)
            self._assert_impact_and_report_semantics(catalog)

            catalog.connection.execute(trigger)

            statements: list[str] = []
            catalog.connection.set_trace_callback(statements.append)
            try:
                with self.assertRaises(sqlite3.Error) as caught:
                    catalog.remove_dependency(
                        SERVICE, "pypi", "app", "1.0.0",
                        SERVICE, "pypi", "lib", "2.0.0",
                    )
            finally:
                catalog.connection.set_trace_callback(None)
            # A save-stage database error, not an input ValueError: the target
            # relationship exists and the revocation reached the write.
            self.assertNotIsInstance(caught.exception, ValueError)
            self.assertEqual(type(caught.exception), sqlite3.IntegrityError)
            self.assertIn("injected", str(caught.exception))

            normalized = [statement.strip() for statement in statements]
            # Phase 1's manual-flag UPDATE is attempted in every scenario.
            self.assertTrue(
                any(
                    s.startswith("UPDATE dependencies")
                    and "manual = 0" in s
                    for s in normalized
                ),
                f"{phase}: the manual registration revocation never ran",
            )

            if phase == "relationship-removal":
                # The UPDATE itself was rejected: the relationship never left,
                # so endpoint cleanup was never reached.
                self.assertFalse(
                    any(s.startswith("DELETE FROM dependencies")
                        for s in normalized)
                )
                self.assertFalse(
                    any(s.startswith("DELETE FROM components")
                        for s in normalized)
                )
            else:
                # The UPDATE ran, the edge was deleted inside the transaction,
                # and then the endpoint cleanup DELETE was attempted and
                # failed - the failure is genuinely mid-cleanup.
                self.assertTrue(
                    any(s.startswith("DELETE FROM dependencies")
                        for s in normalized),
                    f"{phase}: the relationship removal never ran",
                )
                self.assertTrue(
                    any(s.startswith("DELETE FROM components")
                        for s in normalized),
                    f"{phase}: endpoint cleanup was never attempted",
                )

            # The whole partial revocation rolled back and was never committed.
            self.assertIn("ROLLBACK", normalized)
            self.assertNotIn("COMMIT", normalized)

            # Same connection immediately after the failure: no half-open
            # transaction and the pre-operation catalog reads back whole.
            self.assertFalse(catalog.connection.in_transaction)
            self._assert_snapshot_intact(catalog, snapshot)
            self._assert_impact_and_report_semantics(catalog)

            catalog.connection.execute("DROP TRIGGER IF EXISTS fail_manual_revocation")
            catalog.connection.execute("DROP TRIGGER IF EXISTS fail_endpoint_cleanup")
            catalog.close()

            # Durable rollback: reopening the file shows the identical state.
            reopened = Catalog(database)
            self._assert_snapshot_intact(reopened, snapshot)
            self._assert_impact_and_report_semantics(reopened)

            # With the fault gone the very same revocation succeeds: the
            # failed attempt neither wedged the operation nor lost the manual
            # registration it was trying to revoke.
            reopened.remove_dependency(
                SERVICE, "pypi", "app", "1.0.0",
                SERVICE, "pypi", "lib", "2.0.0",
            )
            self._assert_full_cleanup_outcome(reopened, snapshot)
            reopened.close()

    def _assert_full_cleanup_outcome(
        self, catalog: Catalog, snapshot: dict
    ) -> None:
        # The target edge and the two endpoints it alone anchored leave.
        self.assertEqual(component_rows(catalog), {
            LEGACY_ID: 0,
            LIB_OLD_ID: 0,
            WORKER_APP_ID: 0,
            WORKER_LIB_ID: 0,
        })
        self.assertEqual(dependency_rows(catalog), {
            (LEGACY_ID, LIB_OLD_ID): 0,
            (WORKER_APP_ID, WORKER_LIB_ID): 0,
        })
        self.assertNotIn((APP_ID, LIB_ID), dependency_rows(catalog))
        self.assertNotIn(APP_ID, component_rows(catalog))
        self.assertNotIn(LIB_ID, component_rows(catalog))
        # Other-version and other-service data is untouched.
        self.assertEqual(component_owners(catalog), EXPECTED_COMPONENT_OWNERS)
        self.assertEqual(dependency_owners(catalog), EXPECTED_DEPENDENCY_OWNERS)
        self.assertEqual(source_rows(catalog), EXPECTED_SOURCES)

        # Only the worker service keeps affected components now; its report is
        # byte-for-byte what it was before the failed/successful revocation,
        # and the api service has no impacts left.
        summary = catalog.summary()
        self.assertEqual(
            (
                summary.components, summary.affected_components,
                summary.vulnerabilities, summary.highest_severity,
            ),
            (4, 2, 1, "high"),
        )
        self.assertEqual(
            catalog.impact(service=OTHER_SERVICE), snapshot["impact_worker"]
        )
        self.assertEqual(catalog.impact(service=SERVICE), [])
        api_report = catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
        self.assertEqual(api_report["impact_count"], 0)
        self.assertEqual(api_report["unhandled_component_count"], 0)
        self.assertIsNone(api_report["highest_severity"])
        self.assertEqual(
            catalog.risk_report(service=OTHER_SERVICE, evaluated_at=EVAL_AT),
            snapshot["risk_worker"],
        )

        # Successful component cleanup never deletes vulnerability source data
        # or exemption requests and their processing history.
        self.assertEqual(osv_rows(catalog), EXPECTED_OSV_ROWS)
        self.assertEqual(manual_vulnerability_rows(catalog), [])
        self.assertEqual(exemption_event_rows(catalog), EXPECTED_EVENTS)
        self.assertEqual(
            catalog.get_exemption(EXEMPTION_ID), snapshot["exemption"]
        )

    def test_relationship_revocation_write_failure_rolls_back(self) -> None:
        self._run_failure_scenario(
            "relationship-removal", RELATION_REVOCATION_FAILURE_TRIGGER
        )

    def test_endpoint_cleanup_write_failure_after_edge_left_rolls_back(self) -> None:
        self._run_failure_scenario(
            "endpoint-cleanup", ENDPOINT_CLEANUP_FAILURE_TRIGGER
        )


class LenientAndValidationContrastTests(unittest.TestCase):
    """Empty/nonexistent targets reach no save - they are not save failures.

    The rollback scenarios above target a real relationship and prove writes
    ran before the error. These cases return before any write statement at
    all, so a lenient no-op or an input rejection can never masquerade as the
    mid-save failure guarantee.
    """

    def test_nonexistent_targets_and_blank_fields_run_no_write_statements(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)
            snapshot = take_snapshot(catalog)

            def write_statements_of(action):
                statements: list[str] = []
                catalog.connection.set_trace_callback(statements.append)
                try:
                    action()
                finally:
                    catalog.connection.set_trace_callback(None)
                return [
                    s.strip()
                    for s in statements
                    if s.strip().startswith(
                        ("INSERT", "UPDATE", "DELETE", "BEGIN", "COMMIT")
                    )
                ]

            # A relationship whose dependent endpoint does not exist.
            self.assertEqual(
                write_statements_of(lambda: catalog.remove_dependency(
                    SERVICE, "pypi", "ghost", "1.0.0",
                    SERVICE, "pypi", "lib", "2.0.0",
                )),
                [],
            )
            # Two existing endpoints with no relationship between them.
            self.assertEqual(
                write_statements_of(lambda: catalog.remove_dependency(
                    SERVICE, "pypi", "app", "1.0.0",
                    SERVICE, "pypi", "legacyapp", "0.9.0",
                )),
                [],
            )
            # An empty identity field rejects, also before any write.
            def blank_field():
                catalog.remove_dependency(
                    SERVICE, "pypi", "app", "1.0.0",
                    SERVICE, "pypi", "lib", " ",
                )

            self.assertEqual(
                write_statements_of(lambda: self.assertRaises(
                    ValueError, blank_field
                )),
                [],
            )
            with self.assertRaises(ValueError):
                blank_field()

            # Every no-op/rejection left the complete catalog untouched.
            self.assertEqual(take_snapshot(catalog), snapshot)
            catalog.close()


class RemoveDependencySuccessPreservedTests(
    _RevocationStateAssertions, unittest.TestCase
):
    """The fault-free revocation behavior stays exactly as specified."""

    def test_last_basis_gone_removes_edge_and_unneeded_endpoints_immediately(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)
            snapshot = take_snapshot(catalog)

            catalog.remove_dependency(
                SERVICE, "pypi", "app", "1.0.0",
                SERVICE, "pypi", "lib", "2.0.0",
            )

            # Target edge and both endpoints leave; queries reflect it at once.
            self.assertEqual(component_rows(catalog), {
                LEGACY_ID: 0,
                LIB_OLD_ID: 0,
                WORKER_APP_ID: 0,
                WORKER_LIB_ID: 0,
            })
            self.assertEqual(dependency_rows(catalog), {
                (LEGACY_ID, LIB_OLD_ID): 0,
                (WORKER_APP_ID, WORKER_LIB_ID): 0,
            })
            summary = catalog.summary()
            self.assertEqual(
                (
                    summary.components, summary.affected_components,
                    summary.vulnerabilities, summary.highest_severity,
                ),
                (4, 2, 1, "high"),
            )
            records = {
                (r["component"]["service"], r["component"]["name"])
                for r in catalog.impact()
            }
            self.assertEqual(
                records,
                {(OTHER_SERVICE, "app"), (OTHER_SERVICE, "lib")},
            )
            self.assertEqual(catalog.impact(service=SERVICE), [])

            # Vulnerability data and exemption history survive the component
            # deletion and stay queryable by their original ids.
            self.assertEqual(osv_rows(catalog), EXPECTED_OSV_ROWS)
            self.assertEqual(exemption_event_rows(catalog), EXPECTED_EVENTS)
            self.assertEqual(
                catalog.get_exemption(EXEMPTION_ID), snapshot["exemption"]
            )
            catalog.close()

    def test_endpoint_still_declared_by_another_source_is_retained_alone(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)
            # A second source still declares the api library component only.
            catalog.import_sbom(SERVICE, SECOND_SOURCE, lib_only_declaration())

            catalog.remove_dependency(
                SERVICE, "pypi", "app", "1.0.0",
                SERVICE, "pypi", "lib", "2.0.0",
            )

            # The edge leaves and the application leaves with it; the library
            # is independently retained by its remaining source declaration.
            self.assertNotIn((APP_ID, LIB_ID), dependency_rows(catalog))
            self.assertNotIn(APP_ID, component_rows(catalog))
            self.assertEqual(component_rows(catalog)[LIB_ID], 0)
            self.assertEqual(component_owners(catalog), [
                (SERVICE, "pypi", "legacyapp", "0.9.0", LEGACY_SOURCE),
                (SERVICE, "pypi", "lib", "1.0.0", LEGACY_SOURCE),
                (SERVICE, "pypi", "lib", "2.0.0", "audit"),
                (OTHER_SERVICE, "pypi", "app", "1.0.0", "build"),
                (OTHER_SERVICE, "pypi", "lib", "2.0.0", "build"),
            ])

            # The retained library keeps its direct hit; the application that
            # anchored the indirect hit no longer participates.
            records = {
                (r["component"]["service"], r["component"]["name"]): r
                for r in catalog.impact()
            }
            self.assertEqual(
                sorted(records),
                [
                    (SERVICE, "lib"),
                    (OTHER_SERVICE, "app"), (OTHER_SERVICE, "lib"),
                ],
            )
            self.assertTrue(records[(SERVICE, "lib")]["direct"])
            api_report = catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
            self.assertEqual(
                [entry["component"]["name"] for entry in api_report["impacts"]],
                ["lib"],
            )
            self.assertEqual(api_report["impact_count"], 1)
            self.assertEqual(api_report["unhandled_component_count"], 1)
            self.assertEqual(api_report["highest_severity"], "high")
            # The application's exemption history is still queryable even
            # though its impact disappeared with the component.
            self.assertEqual(
                catalog.get_exemption(EXEMPTION_ID)["status"], "approved"
            )
            catalog.close()

    def test_relationship_still_source_declared_survives_manual_revocation(self) -> None:
        # Here the SBOM has NOT withdrawn: revoking the manual registration
        # must leave the source-declared relationship and both endpoints in
        # place, with impacts unchanged - normal revocation behavior.
        catalog = Catalog()
        catalog.import_sbom(SERVICE, SOURCE, initial_declaration())
        catalog.add_dependency(
            SERVICE, "pypi", "app", "1.0.0",
            SERVICE, "pypi", "lib", "2.0.0",
        )
        catalog.import_osv(OSV_SOURCE, osv_records())

        catalog.remove_dependency(
            SERVICE, "pypi", "app", "1.0.0",
            SERVICE, "pypi", "lib", "2.0.0",
        )

        self.assertEqual(component_rows(catalog), {APP_ID: 0, LIB_ID: 0})
        self.assertEqual(dependency_rows(catalog), {(APP_ID, LIB_ID): 0})
        self.assertEqual(
            catalog.connection.execute(
                "SELECT COUNT(*) FROM dependency_sources"
            ).fetchone()[0],
            1,
        )
        records = {
            record["component"]["name"]: record for record in catalog.impact()
        }
        self.assertEqual(sorted(records), ["app", "lib"])
        self.assertTrue(records["lib"]["direct"])
        self.assertFalse(records["app"]["direct"])
        self.assertEqual(
            [node["name"] for node in records["app"]["path"]],
            ["app", "lib"],
        )
        self.assertEqual(catalog.summary().affected_components, 2)

        # Revoking again is the documented lenient no-op, not a cleanup.
        catalog.remove_dependency(
            SERVICE, "pypi", "app", "1.0.0",
            SERVICE, "pypi", "lib", "2.0.0",
        )
        self.assertEqual(dependency_rows(catalog), {(APP_ID, LIB_ID): 0})
        self.assertEqual(component_rows(catalog), {APP_ID: 0, LIB_ID: 0})
        catalog.close()

    def test_cli_remove_dependency_still_reports_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            setup = build_catalog(database)
            setup.close()

            output = io.StringIO()
            with redirect_stdout(output):
                status = main([
                    "--database", database,
                    "remove-dependency",
                    SERVICE, "pypi", "app", "1.0.0",
                    SERVICE, "pypi", "lib", "2.0.0",
                ])
            self.assertEqual(status, 0)
            self.assertIn("dependency removed", output.getvalue())

            catalog = Catalog(database)
            self.assertNotIn(APP_ID, component_rows(catalog))
            self.assertNotIn(LIB_ID, component_rows(catalog))
            self.assertNotIn((APP_ID, LIB_ID), dependency_rows(catalog))
            # Other-version and other-service data is still present.
            self.assertEqual(
                component_rows(catalog),
                {
                    LEGACY_ID: 0,
                    LIB_OLD_ID: 0,
                    WORKER_APP_ID: 0,
                    WORKER_LIB_ID: 0,
                },
            )
            self.assertEqual(
                catalog.get_exemption(EXEMPTION_ID)["status"], "approved"
            )
            catalog.close()


if __name__ == "__main__":
    unittest.main()
