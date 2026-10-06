"""Regression tests for revoking a manual dependency failing *during* the save.

``remove_dependency`` first revokes the target relationship's manual
registration (``UPDATE dependencies SET manual = 0``) and then reapplies the
single retention rule, scoped to exactly that edge and its two endpoints:

1. the relationship leaves when no SBOM source still declares it
   (``DELETE FROM dependencies``);
2. each endpoint is then judged on its own and leaves when it has no manual
   registration, no remaining source declaration and no surviving manual
   relationship (``DELETE FROM components``).

The existing tests cover the fault-free cleanup and input validation (empty
identity fields, non-existent targets). These tests cover the remaining
condition: a *valid* target whose revocation has already started saving and
that then hits a database write error in one of the two write phases -

1. the database rejects the relationship revocation itself
   (the ``UPDATE dependencies`` write);
2. the relationship has already been removed and the database only rejects
   the write while the endpoints are being cleaned up
   (the ``DELETE FROM components`` write).

A failure in either phase must fail the whole operation atomically and
restore the catalog to exactly what it was before the call. The scenario is
the one the contract names: an SBOM once declared that the application
depends on a vulnerable library, the same relationship was then manually
registered, and the SBOM has since withdrawn its declaration - so the
manual registration is the *only* thing still holding the relationship and
its two endpoints. The library's vulnerability still hits it directly and
the application indirectly through the manual edge, and the application's
indirect impact already carries an approved, unexpired exemption.

After either failed revocation:

* the call raises a database error, never a silent success;
* the relationship's manual registration is not lost - the edge is still
  ``manual = 1``;
* both endpoints keep their full identity (service, ecosystem, name,
  version), their manual flags, and the (already withdrawn) source
  declarations are not partially swept;
* summary, impact and the risk report at the same evaluation instant are
  byte-for-byte identical to before the call: component count, affected
  components, vulnerability count, highest risk, the direct/indirect hits
  and their dependency paths, the exemption link, the unhandled-component
  count and the highest severity;
* the imported vulnerability data, the exemption request and its full
  processing history are unchanged;
* the same-name component in another service (which the vulnerability also
  hits directly), other versions of the same components in this service,
  and their own manual relationship are completely untouched.

Two fault-free controls finish the contract: when the last retention basis
really disappears the relationship and both unneeded endpoints leave the
catalog and every query reflects that immediately; when one endpoint is
still declared by another source it is retained independently while the
other end and the edge leave. Successful component cleanup still never
deletes vulnerability data or exemption history.
"""

import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from supply_guard.catalog import Catalog

SERVICE = "api"
OTHER_SERVICE = "billing"
SBOM_SOURCE = "build"
OTHER_SBOM_SOURCE = "audit"
OSV_SOURCE = "nvd"
CVE = "CVE-2026-7001"
EXEMPTION_ID = "EXM-2026-7001"

# Fixed instants keep the exemption term and every report deterministic.
SUBMITTED_AT = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
APPROVED_AT = datetime(2026, 1, 2, 0, 0, tzinfo=timezone.utc)
EXPIRES_AT = "2026-12-31T23:59:59+00:00"
EVAL_AT = "2026-06-01T00:00:00+00:00"

# Full component identities; the retention decision must use all four fields.
APP1 = (SERVICE, "pypi", "app", "1.0.0")
LIB2 = (SERVICE, "pypi", "lib", "2.0.0")
APP2 = (SERVICE, "pypi", "app", "2.0.0")
LIB1 = (SERVICE, "pypi", "lib", "1.0.0")
LIB3 = (SERVICE, "pypi", "lib", "3.0.0")
# A same-name, same-version component in a *different* service, which must
# never be swept by an api-scoped revocation.
BILLING_LIB = (OTHER_SERVICE, "pypi", "lib", "2.0.0")

TARGET_EDGE = (APP1, LIB2)
OTHER_EDGE = (APP2, LIB3)
REMOVE_TARGET_ARGS = APP1 + LIB2


def cdx(components, dependencies=None):
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": components,
    }
    if dependencies is not None:
        document["dependencies"] = dependencies
    return document


def component(ref, purl):
    return {"bom-ref": ref, "purl": purl}


def declared_manifest():
    """The SBOM's original declaration: app 1.0.0 -> lib 2.0.0."""
    return cdx(
        [
            component("build/app", "pkg:pypi/app@1.0.0"),
            component("build/lib", "pkg:pypi/lib@2.0.0"),
        ],
        [{"ref": "build/app", "dependsOn": ["build/lib"]}],
    )


def empty_manifest():
    """The same source withdrawing its whole declaration."""
    return cdx([], [])


def library_only_manifest():
    """Another source declaring only the library component, not the edge."""
    return cdx([component("audit/lib", "pkg:pypi/lib@2.0.0")], [])


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


# Write errors injected at each save phase. The triggers live in the same
# database the revocation writes to, so the failure goes through SQLite
# exactly like a real disk/constraint error: the statement fails and the
# surrounding revocation transaction must roll back.

# Phase 1: the database rejects the very first write of the revocation -
# clearing the relationship's manual registration. The WHEN clause restricts
# the fault to a row genuinely losing its manual flag (1 -> 0), so reads and
# unrelated statements are unaffected.
RELATIONSHIP_SAVE_FAILURE_TRIGGER = """
CREATE TRIGGER fail_relationship_revoke
BEFORE UPDATE OF manual ON dependencies
WHEN NEW.manual = 0 AND OLD.manual = 1
BEGIN
    SELECT RAISE(ABORT, 'injected relationship-save write error');
END
"""

# Phase 2: the relationship has already been deleted inside the transaction
# when the endpoint cleanup write is rejected. The trigger fires only for a
# component being swept after losing its *last* basis - no manual edge
# anchors it anymore - so a candidate the retention rule merely scans and
# keeps can never trigger it, and the failure proves the edge removal really
# ran before the endpoint phase failed.
ENDPOINT_CLEANUP_FAILURE_TRIGGER = """
CREATE TRIGGER fail_endpoint_cleanup
BEFORE DELETE ON components
WHEN NOT EXISTS (
        SELECT 1 FROM dependencies d
        WHERE d.manual = 1
          AND (d.dependent_id = OLD.id OR d.dependency_id = OLD.id)
     )
BEGIN
    SELECT RAISE(ABORT, 'injected endpoint-cleanup write error');
END
"""


def build_catalog(database: str | Path) -> Catalog:
    """Create the pre-revocation scenario shared by every regression case.

    The ``build`` SBOM source declares app 1.0.0, lib 2.0.0 and the
    app -> lib relationship; the same relationship is then manually
    registered on top of the declaration. A local OSV source rates the
    pinned library vulnerability high, so the library is hit directly and
    the application indirectly through the edge; the application's indirect
    impact already holds one approved, unexpired exemption.

    The same directory also carries everything the scoped revocation must
    never touch: the same-name/same-version library in the ``billing``
    service (also directly hit by the vulnerability), other versions of app
    and lib in ``api`` (1.0.0/3.0.0), and their own manual relationship
    app 2.0.0 -> lib 3.0.0.
    """
    catalog = Catalog(database)
    catalog.import_sbom(SERVICE, SBOM_SOURCE, declared_manifest())
    # Manual registration of the very relationship the SBOM declared.
    catalog.add_dependency(*(APP1 + LIB2))
    catalog.import_osv(OSV_SOURCE, osv_records())
    catalog.request_exemption(
        EXEMPTION_ID,
        *APP1,
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
    # Same-name component in another service.
    catalog.add_component(*BILLING_LIB)
    # Other versions in the same service and their own relationship.
    catalog.add_component(*APP2)
    catalog.add_component(*LIB1)
    catalog.add_component(*LIB3)
    catalog.add_dependency(*(APP2 + LIB3))
    return catalog


def withdraw_sbom_declaration(catalog: Catalog) -> None:
    """The SBOM source withdraws app/lib and the edge, leaving only manual."""
    catalog.import_sbom(SERVICE, SBOM_SOURCE, empty_manifest())


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


def component_owners(catalog: Catalog, service: str = SERVICE) -> dict[str, list[str]]:
    """Source names declaring each component in the given service."""
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
        (service,),
    ):
        owners.setdefault(str(row["name"]), []).append(str(row["source"]))
    return owners


def dependency_owners(catalog: Catalog, service: str = SERVICE) -> dict:
    """Source names declaring each relationship in the given service."""
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
        (service,),
    ):
        key = (str(row["dependent"]), str(row["dependency"]))
        owners.setdefault(key, []).append(str(row["source"]))
    return owners


def raw_rows(catalog: Catalog, table: str, order: str) -> list[tuple]:
    """Every stored row of a table, for whole-table before/after equality."""
    return [
        tuple(row)
        for row in catalog.connection.execute(
            f"SELECT * FROM {table} ORDER BY {order}"
        )
    ]


def take_snapshot(catalog: Catalog) -> dict:
    """Everything a failed revocation must leave untouched."""
    summary = catalog.summary()
    return {
        "components": component_rows(catalog),
        "dependencies": dependency_rows(catalog),
        "component_owners": component_owners(catalog),
        "dependency_owners": dependency_owners(catalog),
        "sources": raw_rows(catalog, "sources", "service, name"),
        "summary": (
            summary.components,
            summary.affected_components,
            summary.vulnerabilities,
            summary.highest_severity,
        ),
        "impact_api": catalog.impact(service=SERVICE),
        "impact_all": catalog.impact(),
        "risk_api": catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT),
        "risk_all": catalog.risk_report(evaluated_at=EVAL_AT),
        "osv": raw_rows(
            catalog, "osv_vulnerabilities", "source, id, package_name"
        ),
        "requests": raw_rows(catalog, "exemption_requests", "id"),
        "events": raw_rows(catalog, "exemption_events", "request_id, seq"),
        "exemption": catalog.get_exemption(EXEMPTION_ID),
    }


# The directory the instant before the revocation: the SBOM source has
# withdrawn, so the manual edge is the sole anchor for itself and its two
# endpoints; everything else (other versions, other service) is manual.
EXPECTED_COMPONENTS_AFTER_WITHDRAWAL = {
    APP1: 0,
    LIB2: 0,
    APP2: 1,
    LIB1: 1,
    LIB3: 1,
    BILLING_LIB: 1,
}
EXPECTED_EDGES_AFTER_WITHDRAWAL = {
    TARGET_EDGE: 1,
    OTHER_EDGE: 1,
}


class _RevocationStateAssertions:
    """Post-failure contract checks shared by the two rollback tests."""

    def _assert_business_semantics(self, catalog: Catalog) -> None:
        # The manual edge still keeps both endpoints and the impact flowing
        # through it: six components, three of them affected by the one
        # high vulnerability.
        summary = catalog.summary()
        self.assertEqual(
            (
                summary.components,
                summary.affected_components,
                summary.vulnerabilities,
                summary.highest_severity,
            ),
            (6, 3, 1, "high"),
        )

        # Directory-wide impact: the api library is a direct hit, the api
        # application an indirect hit through app -> lib, and the same-name
        # billing library an independent direct hit in another service.
        records = {
            (
                record["component"]["service"],
                record["component"]["name"],
                record["component"]["version"],
            ): record
            for record in catalog.impact()
        }
        self.assertEqual(
            set(records),
            {
                (SERVICE, "app", "1.0.0"),
                (SERVICE, "lib", "2.0.0"),
                (OTHER_SERVICE, "lib", "2.0.0"),
            },
        )
        indirect = records[(SERVICE, "app", "1.0.0")]
        self.assertFalse(indirect["direct"])
        self.assertEqual(indirect["vulnerability"], CVE)
        self.assertEqual(indirect["source"], OSV_SOURCE)
        self.assertEqual(indirect["severity"], "high")
        self.assertEqual(indirect["matched_conditions"], ["==2.0.0"])
        self.assertEqual(
            [
                (node["service"], node["name"], node["version"])
                for node in indirect["path"]
            ],
            [
                (SERVICE, "app", "1.0.0"),
                (SERVICE, "lib", "2.0.0"),
            ],
        )
        direct_api = records[(SERVICE, "lib", "2.0.0")]
        self.assertTrue(direct_api["direct"])
        self.assertEqual(
            [node["name"] for node in direct_api["path"]], ["lib"]
        )
        direct_billing = records[(OTHER_SERVICE, "lib", "2.0.0")]
        self.assertTrue(direct_billing["direct"])
        self.assertEqual(direct_billing["path"][0]["service"], OTHER_SERVICE)

        # The api-scoped risk report keeps the approved exemption link on
        # exactly the application's indirect record, while the directly hit
        # library stays unhandled.
        report = catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
        self.assertEqual(report["impact_count"], 2)
        self.assertEqual(report["unhandled_component_count"], 1)
        self.assertEqual(report["highest_severity"], "high")
        by_component = {
            (entry["component"]["name"], entry["component"]["version"]): entry
            for entry in report["impacts"]
        }
        app_entry = by_component[("app", "1.0.0")]
        self.assertTrue(app_entry["exempted"])
        self.assertEqual(app_entry["exemption_request"], EXEMPTION_ID)
        self.assertIsNone(app_entry["not_exempt_reason"])
        self.assertFalse(app_entry["direct"])
        lib_entry = by_component[("lib", "2.0.0")]
        self.assertFalse(lib_entry["exempted"])
        self.assertIsNone(lib_entry["exemption_request"])
        self.assertTrue(lib_entry["direct"])

        # Directory-wide, the other service's independent direct hit stays
        # unhandled too: two unhandled components, still high.
        whole = catalog.risk_report(evaluated_at=EVAL_AT)
        self.assertEqual(whole["impact_count"], 3)
        self.assertEqual(whole["unhandled_component_count"], 2)
        self.assertEqual(whole["highest_severity"], "high")

    def _assert_pristine_catalog(
        self, catalog: Catalog, snapshot: dict
    ) -> None:
        # Byte-for-byte equality across every stored table and every query.
        self.assertEqual(take_snapshot(catalog), snapshot)

        # ...and the exact expected state made explicit: the failed
        # revocation neither lost the manual registration nor swept an
        # endpoint, a source attribution or any unrelated entity.
        self.assertEqual(
            component_rows(catalog), EXPECTED_COMPONENTS_AFTER_WITHDRAWAL
        )
        self.assertEqual(
            dependency_rows(catalog), EXPECTED_EDGES_AFTER_WITHDRAWAL
        )
        target_manual = dependency_rows(catalog)[TARGET_EDGE]
        self.assertEqual(target_manual, 1)
        # The source already withdrew before the failed call; that empty
        # attribution must not become a partial *re-*cleanup or reappear.
        self.assertEqual(component_owners(catalog), {})
        self.assertEqual(dependency_owners(catalog), {})

        # Vulnerability data, the request and the full processing history
        # are exactly the rows that existed before the failed revocation.
        self.assertEqual(len(raw_rows(catalog, "osv_vulnerabilities", "id")), 1)
        request = catalog.get_exemption(EXEMPTION_ID)
        self.assertEqual(request["status"], "approved")
        self.assertEqual(request["scope"]["source"], OSV_SOURCE)
        self.assertEqual(
            [event["action"] for event in request["events"]],
            ["request", "approve"],
        )
        self.assertEqual(
            len(raw_rows(catalog, "exemption_events", "id")), 2
        )

        self._assert_business_semantics(catalog)

    def _assert_revoked_catalog(self, catalog: Catalog) -> None:
        """The state after a fault-free retry of the same revocation."""
        # The target edge and both of its endpoints have left; nothing else.
        self.assertEqual(
            component_rows(catalog),
            {APP2: 1, LIB1: 1, LIB3: 1, BILLING_LIB: 1},
        )
        self.assertEqual(dependency_rows(catalog), {OTHER_EDGE: 1})
        self.assertNotIn(APP1, component_rows(catalog))
        self.assertNotIn(LIB2, component_rows(catalog))
        self.assertNotIn(TARGET_EDGE, dependency_rows(catalog))
        self.assertEqual(component_owners(catalog), {})
        self.assertEqual(dependency_owners(catalog), {})

        # Queries reflect the removal immediately: only the other service's
        # same-name library is still hit (its record survives untouched).
        summary = catalog.summary()
        self.assertEqual(
            (
                summary.components,
                summary.affected_components,
                summary.vulnerabilities,
                summary.highest_severity,
            ),
            (4, 1, 1, "high"),
        )
        self.assertEqual(catalog.impact(service=SERVICE), [])
        remaining = catalog.impact()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(
            (
                remaining[0]["component"]["service"],
                remaining[0]["component"]["name"],
                remaining[0]["component"]["version"],
            ),
            (OTHER_SERVICE, "lib", "2.0.0"),
        )
        self.assertTrue(remaining[0]["direct"])

        api_report = catalog.risk_report(
            service=SERVICE, evaluated_at=EVAL_AT
        )
        self.assertEqual(api_report["impact_count"], 0)
        self.assertEqual(api_report["unhandled_component_count"], 0)
        self.assertIsNone(api_report["highest_severity"])
        whole_report = catalog.risk_report(evaluated_at=EVAL_AT)
        self.assertEqual(whole_report["impact_count"], 1)
        self.assertEqual(whole_report["unhandled_component_count"], 1)
        self.assertEqual(whole_report["highest_severity"], "high")

        # Cleaning components up never deletes vulnerability source data or
        # exemption requests/history: the OSV record still hits the billing
        # library, and the approved request for the now-gone api impact is
        # still queryable by its original id with its complete history.
        self.assertEqual(len(raw_rows(catalog, "osv_vulnerabilities", "id")), 1)
        request = catalog.get_exemption(EXEMPTION_ID)
        self.assertEqual(request["status"], "approved")
        self.assertEqual(
            [event["action"] for event in request["events"]],
            ["request", "approve"],
        )


class RemoveDependencySaveFailureRollbackTests(
    _RevocationStateAssertions, unittest.TestCase
):
    """A write error in either save phase fails the revocation atomically."""

    def _run_failure_scenario(self, phase: str, trigger: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)
            withdraw_sbom_declaration(catalog)

            # The target genuinely exists and is the sole remaining anchor:
            # the edge is manual and no source declares it or its ends. This
            # is a valid revocation target mid-save, never an empty or
            # non-existent one.
            self.assertEqual(
                dependency_rows(catalog), EXPECTED_EDGES_AFTER_WITHDRAWAL
            )
            self.assertEqual(component_owners(catalog), {})
            self.assertEqual(dependency_owners(catalog), {})

            snapshot = take_snapshot(catalog)
            self._assert_business_semantics(catalog)

            catalog.connection.execute(trigger)
            statements: list[str] = []
            catalog.connection.set_trace_callback(statements.append)
            try:
                with self.assertRaises(sqlite3.Error) as caught:
                    catalog.remove_dependency(*REMOVE_TARGET_ARGS)
            finally:
                catalog.connection.set_trace_callback(None)
            # A save-stage database error, not an input-validation ValueError:
            # the target was valid and the revocation had started writing.
            self.assertEqual(type(caught.exception), sqlite3.IntegrityError)
            self.assertNotIsInstance(caught.exception, ValueError)
            self.assertIn("write error", str(caught.exception))

            normalized = [statement.strip() for statement in statements]

            # The save really started: the manual revocation UPDATE ran
            # inside a write transaction.
            self.assertTrue(
                any(statement.startswith("BEGIN") for statement in normalized)
            )
            self.assertTrue(
                any(
                    statement.startswith("UPDATE dependencies")
                    for statement in normalized
                ),
                f"{phase}: relationship revocation was never attempted",
            )

            if phase == "relationship-save":
                # The very first write failed: the retention deletes never
                # ran at all.
                self.assertFalse(
                    any(
                        statement.startswith("DELETE FROM dependencies")
                        for statement in normalized
                    )
                )
                self.assertFalse(
                    any(
                        statement.startswith("DELETE FROM components")
                        for statement in normalized
                    )
                )
            else:
                # The relationship was removed first, then the endpoint
                # cleanup write was attempted and failed.
                self.assertTrue(
                    any(
                        statement.startswith("DELETE FROM dependencies")
                        for statement in normalized
                    ),
                    f"{phase}: relationship removal never ran",
                )
                self.assertTrue(
                    any(
                        statement.startswith("DELETE FROM components")
                        for statement in normalized
                    ),
                    f"{phase}: endpoint cleanup was never attempted",
                )

            # The whole partial revocation rolled back and was never
            # committed, and no half-open transaction is left on the
            # connection.
            self.assertIn("ROLLBACK", normalized)
            self.assertNotIn("COMMIT", normalized)
            self.assertFalse(catalog.connection.in_transaction)

            # Same connection: the catalog is exactly as before the call.
            self._assert_pristine_catalog(catalog, snapshot)
            catalog.close()

            # Durable rollback: the injected trigger persists in the schema
            # exactly like a real constraint would, and a reopened database
            # shows the identical state.
            reopened = Catalog(database)
            self._assert_pristine_catalog(reopened, snapshot)

            # With the fault removed, the very same revocation succeeds:
            # the failed attempt neither wedged the catalog nor left a
            # half-saved deletion.
            reopened.connection.execute(
                "DROP TRIGGER IF EXISTS fail_relationship_revoke"
            )
            reopened.connection.execute(
                "DROP TRIGGER IF EXISTS fail_endpoint_cleanup"
            )
            reopened.remove_dependency(*REMOVE_TARGET_ARGS)
            self._assert_revoked_catalog(reopened)
            reopened.close()

            durable = Catalog(database)
            self._assert_revoked_catalog(durable)
            durable.close()

    def test_relationship_save_failure_rolls_back_the_revocation(self) -> None:
        self._run_failure_scenario(
            "relationship-save", RELATIONSHIP_SAVE_FAILURE_TRIGGER
        )

    def test_endpoint_cleanup_failure_rolls_back_the_revocation(self) -> None:
        self._run_failure_scenario(
            "endpoint-cleanup", ENDPOINT_CLEANUP_FAILURE_TRIGGER
        )


class FaultFreeRevocationContrastTests(
    _RevocationStateAssertions, unittest.TestCase
):
    """Controls without an injected fault: the last basis disappearing.

    These contrast with the rollback cases above: when no write fails, the
    relationship and endpoints that genuinely lost every retention basis
    leave the catalog immediately, while an endpoint another source still
    declares is retained independently.
    """

    def test_last_basis_gone_removes_edge_and_both_endpoints(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)
            withdraw_sbom_declaration(catalog)

            # No fault: the revocation completes and queries reflect it on
            # the same connection, with no SBOM re-import in between.
            catalog.remove_dependency(*REMOVE_TARGET_ARGS)
            self._assert_revoked_catalog(catalog)

            # Repeated revocation of the now-gone edge still succeeds
            # without sweeping anything further.
            catalog.remove_dependency(*REMOVE_TARGET_ARGS)
            self._assert_revoked_catalog(catalog)
            catalog.close()

            reopened = Catalog(database)
            self._assert_revoked_catalog(reopened)
            reopened.close()

    def test_endpoint_declared_by_another_source_is_retained_alone(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = Catalog(database)
            # The build source declares app -> lib; a second source declares
            # only the library component. The edge is manually registered as
            # well, then the build source withdraws everything.
            catalog.import_sbom(SERVICE, SBOM_SOURCE, declared_manifest())
            catalog.import_sbom(
                SERVICE, OTHER_SBOM_SOURCE, library_only_manifest()
            )
            catalog.add_dependency(*(APP1 + LIB2))
            catalog.import_osv(OSV_SOURCE, osv_records())
            withdraw_sbom_declaration(catalog)

            # Before revoking, the manual edge still anchors the application
            # (which no source declares anymore); the library is also held
            # by the audit source.
            self.assertEqual(component_rows(catalog), {APP1: 0, LIB2: 0})
            self.assertEqual(dependency_rows(catalog), {TARGET_EDGE: 1})
            self.assertEqual(component_owners(catalog), {
                "lib": [OTHER_SBOM_SOURCE],
            })

            catalog.remove_dependency(*REMOVE_TARGET_ARGS)

            # The edge and the application leave together, but the library
            # is retained independently: it must not follow the other end.
            self.assertEqual(component_rows(catalog), {LIB2: 0})
            self.assertEqual(dependency_rows(catalog), {})
            self.assertEqual(component_owners(catalog), {
                "lib": [OTHER_SBOM_SOURCE],
            })
            self.assertEqual(dependency_owners(catalog), {})

            # Impact reflects it immediately: the direct library hit stays,
            # the application's indirect hit is gone with its component.
            records = catalog.impact(service=SERVICE)
            self.assertEqual(len(records), 1)
            self.assertTrue(records[0]["direct"])
            self.assertEqual(
                (
                    records[0]["component"]["name"],
                    records[0]["component"]["version"],
                ),
                ("lib", "2.0.0"),
            )
            summary = catalog.summary()
            self.assertEqual(
                (
                    summary.components,
                    summary.affected_components,
                    summary.vulnerabilities,
                    summary.highest_severity,
                ),
                (1, 1, 1, "high"),
            )
            report = catalog.risk_report(
                service=SERVICE, evaluated_at=EVAL_AT
            )
            self.assertEqual(report["impact_count"], 1)
            self.assertEqual(report["unhandled_component_count"], 1)
            self.assertEqual(report["highest_severity"], "high")
            # Vulnerability source data is untouched.
            self.assertEqual(
                len(raw_rows(catalog, "osv_vulnerabilities", "id")), 1
            )
            catalog.close()

            reopened = Catalog(database)
            self.assertEqual(component_rows(reopened), {LIB2: 0})
            self.assertEqual(dependency_rows(reopened), {})
            self.assertEqual(component_owners(reopened), {
                "lib": [OTHER_SBOM_SOURCE],
            })
            self.assertEqual(len(reopened.impact(service=SERVICE)), 1)
            reopened.close()


class InvalidTargetContrastTests(unittest.TestCase):
    """Input-validation cases must not be mistaken for save-failure coverage.

    The rollback tests target an existing edge whose revocation reaches the
    write; an empty identity is rejected before any SQL runs, and a target
    that does not exist only performs the existence reads - the write
    transaction, the manual UPDATE and the retention deletes never start.
    """

    def setUp(self) -> None:
        self.catalog = build_catalog(":memory:")
        withdraw_sbom_declaration(self.catalog)
        self.snapshot = take_snapshot(self.catalog)

    def tearDown(self) -> None:
        self.catalog.close()

    def _statements_for(self, call) -> list[str]:
        """Run one call (expected to raise ValueError) and trace its SQL."""
        statements: list[str] = []
        self.catalog.connection.set_trace_callback(statements.append)
        try:
            with self.assertRaises(ValueError):
                call()
        finally:
            self.catalog.connection.set_trace_callback(None)
        return [statement.strip() for statement in statements]

    def test_empty_identity_is_rejected_before_any_statement(self) -> None:
        statements = self._statements_for(lambda: self.catalog.remove_dependency(
            *APP1, SERVICE, "pypi", "lib", " "
        ))
        self.assertFalse(
            [statement for statement in statements if statement],
            "empty identity fields must be rejected before any SQL runs",
        )
        self.assertEqual(take_snapshot(self.catalog), self.snapshot)

    def test_missing_target_and_missing_edge_perform_no_write(self) -> None:
        # A dependency component that does not exist (a lenient success that
        # only reads, so it is traced without expecting an exception).
        statements: list[str] = []
        self.catalog.connection.set_trace_callback(statements.append)
        try:
            self.catalog.remove_dependency(
                *(APP1 + (SERVICE, "pypi", "ghost", "9.9.9"))
            )
            # Both components exist but this relationship does not (the
            # app 2.0.0 -> lib 1.0.0 pair was never registered).
            self.catalog.remove_dependency(*(APP2 + LIB1))
        finally:
            self.catalog.connection.set_trace_callback(None)
        normalized = [statement.strip() for statement in statements]
        self.assertFalse(
            any(statement.startswith("BEGIN") for statement in normalized),
            "a non-existent target must not open a write transaction",
        )
        self.assertFalse(
            any(
                statement.startswith(("UPDATE", "DELETE", "INSERT"))
                for statement in normalized
            ),
            "a non-existent target must not be written",
        )
        self.assertEqual(take_snapshot(self.catalog), self.snapshot)
        # The real target edge is still held by its manual registration.
        self.assertEqual(
            dependency_rows(self.catalog)[TARGET_EDGE], 1
        )


if __name__ == "__main__":
    unittest.main()
