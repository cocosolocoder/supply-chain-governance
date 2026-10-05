"""Regression tests for local OSV source replacement failing *during* the save.

Re-importing an OSV source name replaces that source's previous records
everywhere in the catalog (the source name has no service scope). The existing
failure cases all reject bad input (unreadable/non-JSON file, non-array top
level, unsupported ecosystem, an affected entry without its own version
conditions, a duplicated id) before a single database write happens. These
tests cover the other half of the contract: an input whose **every record is
valid**, whose replacement has already started (the source's previous rows
already deleted, part of the new rows already written), and that then hits a
database write error while the remaining rows are being inserted.

Such a failure must roll the whole replacement back atomically. The target
source must keep exactly the content of its last successful import:

* every original vulnerability id and every (vulnerability, package) row -
  including a record that spans several packages (the import success count is
  the number of such combinations, so a surviving vulnerability id alone does
  not prove its rows survived), and a row that matches no registered
  component;
* each row's version conditions, risk level, declared-vs-default severity
  basis and withdrawn status;
* none of the new content may linger - neither added vulnerabilities nor
  modifications to a shared vulnerability id (changed conditions/rating).

The failed operation must surface as an error, never as a successful import
count. Direct hits and dependency-propagated impacts for the same registered
components must keep the old conditions, severity and paths in both services
the source affects; summary, impact and the risk report at a fixed evaluation
instant stay byte-for-byte identical, including the approved exemption's
linkage, its scope/approved level, the unhandled-component count and the
highest severity; the request content and its full processing history are
untouched. Another source carrying the same vulnerability id, manually
registered vulnerabilities, and the component/dependency lists (which are not
replaced objects at all) are never part of the rollback. A second test class
shows validation rejections run no SQL at all, so the two failure kinds stay
distinguishable; a third keeps the public success behaviors (legal
replacement, ``[]`` clearing the source, CLI success statistics).
"""

import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard.cli import main

API = "api"
WORKER = "worker"
NVD = "nvd"
ALT_SOURCE = "osv-alt"

# Vulnerabilities of the target source's last successful import.
CVE_OLD = "CVE-2026-5001"        # modified by the failed replacement
CVE_DROP = "CVE-2026-5002"       # dropped by the failed replacement
CVE_WITHDRAWN = "CVE-2026-5003"  # withdrawn, dropped by the failed replacement
CVE_UNMATCHED = "CVE-2026-5004"  # matches no component, dropped
CVE_MULTI = "CVE-2026-5005"      # two packages across two services, modified
CVE_NEW = "CVE-2026-5006"        # added vulnerability (the failing row)
CVE_TAIL = "CVE-2026-5007"       # added vulnerability after the failing row
# Vulnerabilities that must never be touched by the rollback.
CVE_ALT = "CVE-2026-7001"        # other source only
CVE_MANUAL = "CVE-2026-9000"     # manually registered

EXEMPTION_ID = "EXM-2026-5001"

SUBMITTED_AT = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
APPROVED_AT = datetime(2026, 1, 2, 0, 0, tzinfo=timezone.utc)
EXPIRES_AT = "2026-12-31T23:59:59+00:00"
EVAL_AT = "2026-06-01T00:00:00+00:00"
WITHDRAWN_AT = "2026-02-01T00:00:00Z"

# The new row whose INSERT the trigger rejects; rows for it are never written,
# and everything queued behind it must never be attempted successfully.
SENTINEL_PACKAGE = "newrelic"


def entry(package, versions=None, ranges=None):
    affected = {"package": {"ecosystem": "PyPI", "name": package}}
    if versions is not None:
        affected["versions"] = versions
    if ranges is not None:
        affected["ranges"] = ranges
    return affected


def interval(introduced, fixed=None, last_affected=None):
    events = [{"introduced": introduced}]
    if fixed is not None:
        events.append({"fixed": fixed})
    if last_affected is not None:
        events.append({"last_affected": last_affected})
    return {"type": "ECOSYSTEM", "events": events}


def osv(identifier, affected, severity=None, withdrawn=None):
    record = {"id": identifier, "affected": affected}
    if severity is not None:
        record["database_specific"] = {"severity": severity}
    if withdrawn is not None:
        record["withdrawn"] = withdrawn
    return record


def explicit(version):
    return {"type": "explicit", "version": version}


def old_nvd_records():
    """The target source's original, fully valid content.

    Six stored (vulnerability, package) rows: a high declared hit carrying
    both an explicit version and an interval, a default-medium hit, a
    withdrawn low record, an unmatched critical record, and one vulnerability
    declared for two packages (one per service).
    """
    return [
        osv(
            CVE_OLD,
            [entry("lib", ["2.0.0"], [interval("1.0", fixed="3.0")])],
            severity="high",
        ),
        osv(CVE_DROP, [entry("redis", ["7.0.0"])]),
        osv(
            CVE_WITHDRAWN,
            [entry("memcache", ["1.0.0"])],
            severity="low",
            withdrawn=WITHDRAWN_AT,
        ),
        osv(CVE_UNMATCHED, [entry("django", ["4.2.0"])], severity="critical"),
        osv(
            CVE_MULTI,
            [entry("alpha", ["1.0.0"]), entry("beta", ["3.0.0"])],
            severity="high",
        ),
    ]


def replacement_nvd_records():
    """A fully valid replacement that fails partway through saving.

    CVE_OLD is modified (2.5.0/critical, interval dropped); CVE_MULTI is
    modified on both packages (9.9.9/low); CVE_DROP/CVE_WITHDRAWN/CVE_UNMATCHED
    are dropped; CVE_NEW is added and its INSERT is where the injected error
    fires, after the three modified rows were already written; CVE_TAIL sits
    behind the failing row and must never land either.
    """
    return [
        osv(CVE_OLD, [entry("lib", ["2.5.0"])], severity="critical"),
        osv(
            CVE_MULTI,
            [entry("alpha", ["9.9.9"]), entry("beta", ["9.9.9"])],
            severity="low",
        ),
        osv(CVE_NEW, [entry(SENTINEL_PACKAGE, ["5.0.0"])]),
        osv(CVE_TAIL, [entry("zebra", ["1.0.0"])]),
    ]


def other_source_records():
    """The other OSV source: the same shared CVE at a different rating, plus
    a vulnerability the replaced source never carried."""
    return [
        osv(CVE_OLD, [entry("lib", ["2.0.0"])], severity="low"),
        osv(CVE_ALT, [entry("requests", ["2.31.0"])], severity="high"),
    ]


# A write error injected in the middle of the row-saving loop. The trigger
# lives in the same database the import writes to, so the failure goes through
# SQLite exactly like a real disk/constraint error: the INSERT aborts and the
# whole replacement transaction must roll back. Fires only on the new
# vulnerability's row, so several valid new rows have already been written.
MID_SAVE_FAILURE_TRIGGER = """
CREATE TRIGGER fail_osv_save
BEFORE INSERT ON osv_vulnerabilities
WHEN NEW.package_name = 'newrelic'
BEGIN
    SELECT RAISE(ABORT, 'injected osv-save write error');
END
"""

# The same kind of failure on the very first new row, before any new row could
# be inserted: deleting the old content alone must already be reversible.
FIRST_ROW_SAVE_FAILURE_TRIGGER = """
CREATE TRIGGER fail_osv_first_save
BEFORE INSERT ON osv_vulnerabilities
WHEN NEW.id = 'CVE-2026-5001' AND NEW.package_name = 'lib'
 AND NEW.severity = 'critical'
BEGIN
    SELECT RAISE(ABORT, 'injected first-row osv-save write error');
END
"""


def build_catalog(database: str | Path) -> Catalog:
    """Create the pre-replacement scenario shared by every regression case.

    Two services share the one global OSV source name. ``api`` has a directly
    hit library (explicit version plus interval, declared high), an
    application depending on it, a default-severity manual observation and one
    package of the two-package vulnerability. ``worker`` has a directly hit
    cache, a component depending on it, the other package of the two-package
    vulnerability, the other source's own hit and a pinned version of the
    withdrawn package. The target source also carries an unmatched record.
    The application's indirect impact through the target source holds one
    approved, unexpired exemption.
    """
    catalog = Catalog(database)

    for identity in (
        (API, "pypi", "app", "1.0.0"),
        (API, "pypi", "lib", "2.0.0"),
        (API, "pypi", "urllib3", "2.2.2"),
        (API, "pypi", "alpha", "1.0.0"),
        (WORKER, "pypi", "redis", "7.0.0"),
        (WORKER, "pypi", "queue", "4.0.0"),
        (WORKER, "pypi", "beta", "3.0.0"),
        (WORKER, "pypi", "requests", "2.31.0"),
        (WORKER, "pypi", "memcache", "1.0.0"),
    ):
        catalog.add_component(*identity)
    catalog.add_dependency(
        API, "pypi", "app", "1.0.0", API, "pypi", "lib", "2.0.0"
    )
    catalog.add_dependency(
        WORKER, "pypi", "queue", "4.0.0", WORKER, "pypi", "redis", "7.0.0"
    )

    catalog.add_vulnerability(CVE_MANUAL, "urllib3", "high")

    catalog.import_osv(NVD, old_nvd_records())
    catalog.import_osv(ALT_SOURCE, other_source_records())

    catalog.request_exemption(
        EXEMPTION_ID,
        API, "pypi", "app", "1.0.0",
        CVE_OLD, "lib", NVD,
        applicant="alice",
        reason="egress proxy mitigates the transitive library exposure",
        expires_at=EXPIRES_AT,
        submitted_at=SUBMITTED_AT,
    )
    catalog.approve_exemption(
        EXEMPTION_ID,
        handler="bob",
        note="compensating controls verified",
        decided_at=APPROVED_AT,
    )
    return catalog


def component_identities(catalog: Catalog) -> list[tuple]:
    return sorted(
        (
            str(row["service"]),
            str(row["ecosystem"]),
            str(row["name"]),
            str(row["version"]),
        )
        for row in catalog.connection.execute(
            "SELECT service, ecosystem, name, version FROM components"
        )
    )


def dependency_pairs(catalog: Catalog) -> list[tuple]:
    return sorted(
        (
            (
                str(row["s1"]), str(row["e1"]), str(row["n1"]), str(row["v1"])
            ),
            (
                str(row["s2"]), str(row["e2"]), str(row["n2"]), str(row["v2"])
            ),
        )
        for row in catalog.connection.execute(
            """
            SELECT c1.service AS s1, c1.ecosystem AS e1, c1.name AS n1,
                   c1.version AS v1,
                   c2.service AS s2, c2.ecosystem AS e2, c2.name AS n2,
                   c2.version AS v2
            FROM dependencies d
            JOIN components c1 ON c1.id = d.dependent_id
            JOIN components c2 ON c2.id = d.dependency_id
            """
        )
    )


def manual_vulnerability_rows(catalog: Catalog) -> list[tuple]:
    return sorted(
        (str(row["id"]), str(row["component_name"]), str(row["severity"]))
        for row in catalog.connection.execute(
            "SELECT id, component_name, severity FROM vulnerabilities"
        )
    )


def osv_rows(catalog: Catalog) -> dict[str, dict[tuple, tuple]]:
    """All OSV rows grouped by source, keyed by (id, package_name)."""
    grouped: dict[str, dict[tuple, tuple]] = {}
    for row in catalog.connection.execute(
        """
        SELECT source, id, package_name, severity, severity_default,
               withdrawn, conditions
        FROM osv_vulnerabilities
        """
    ):
        grouped.setdefault(str(row["source"]), {})[
            (str(row["id"]), str(row["package_name"]))
        ] = (
            str(row["severity"]),
            bool(row["severity_default"]),
            None if row["withdrawn"] is None else str(row["withdrawn"]),
            json.loads(row["conditions"]),
        )
    return grouped


# The exact rows the target source must still hold after a failed replacement.
EXPECTED_OLD_NVD_ROWS = {
    (CVE_OLD, "lib"): (
        "high",
        False,
        None,
        [
            explicit("2.0.0"),
            {"type": "interval", "introduced": "1.0",
             "fixed": "3.0", "last_affected": None},
        ],
    ),
    (CVE_DROP, "redis"): (
        "medium", True, None, [explicit("7.0.0")]
    ),
    (CVE_WITHDRAWN, "memcache"): (
        "low", False, WITHDRAWN_AT, [explicit("1.0.0")]
    ),
    (CVE_UNMATCHED, "django"): (
        "critical", False, None, [explicit("4.2.0")]
    ),
    (CVE_MULTI, "alpha"): (
        "high", False, None, [explicit("1.0.0")]
    ),
    (CVE_MULTI, "beta"): (
        "high", False, None, [explicit("3.0.0")]
    ),
}

EXPECTED_OLD_ALT_ROWS = {
    (CVE_OLD, "lib"): (
        "low", False, None, [explicit("2.0.0")]
    ),
    (CVE_ALT, "requests"): (
        "high", False, None, [explicit("2.31.0")]
    ),
}


def take_snapshot(catalog: Catalog) -> dict:
    """Everything a failed replacement must leave untouched."""
    summary = catalog.summary()
    return {
        "osv_rows": osv_rows(catalog),
        "manual": manual_vulnerability_rows(catalog),
        "components": component_identities(catalog),
        "dependencies": dependency_pairs(catalog),
        "summary": (
            summary.components,
            summary.affected_components,
            summary.vulnerabilities,
            summary.highest_severity,
        ),
        "affected_services": catalog.affected_services(),
        "impact": catalog.impact(),
        "impact_api": catalog.impact(service=API),
        "impact_worker": catalog.impact(service=WORKER),
        "risk_report": catalog.risk_report(evaluated_at=EVAL_AT),
        "risk_report_api": catalog.risk_report(service=API, evaluated_at=EVAL_AT),
        "risk_report_worker": catalog.risk_report(
            service=WORKER, evaluated_at=EVAL_AT
        ),
        "exemption": catalog.get_exemption(EXEMPTION_ID),
        "exemptions": catalog.list_exemptions(),
        "approved_exemptions": catalog.list_exemptions(status="approved"),
    }


def impact_index(records: list[dict]) -> dict[tuple, dict]:
    return {
        (
            record["component"]["service"],
            record["component"]["name"],
            record["source"],
            record["vulnerability"],
        ): record
        for record in records
    }


class OsvReplacementSaveFailureRollbackTests(unittest.TestCase):
    """A write error after the replacement started rolls the whole import back."""

    def _assert_old_rows_exactly(self, catalog: Catalog) -> None:
        rows = osv_rows(catalog)
        self.assertEqual(rows[NVD], EXPECTED_OLD_NVD_ROWS)
        self.assertEqual(rows[ALT_SOURCE], EXPECTED_OLD_ALT_ROWS)
        self.assertEqual(set(rows), {NVD, ALT_SOURCE})

        # The modified and the added rows of the failed replacement are not
        # in the table under any spelling.
        surviving_keys = set(rows[NVD])
        self.assertNotIn((CVE_NEW, SENTINEL_PACKAGE), surviving_keys)
        self.assertNotIn((CVE_TAIL, "zebra"), surviving_keys)
        self.assertEqual(
            rows[NVD][(CVE_OLD, "lib")],
            EXPECTED_OLD_NVD_ROWS[(CVE_OLD, "lib")],
        )
        self.assertEqual(
            rows[NVD][(CVE_MULTI, "alpha")],
            EXPECTED_OLD_NVD_ROWS[(CVE_MULTI, "alpha")],
        )
        self.assertEqual(
            rows[NVD][(CVE_MULTI, "beta")],
            EXPECTED_OLD_NVD_ROWS[(CVE_MULTI, "beta")],
        )
        # The import count is defined per (vulnerability, package): the
        # two-package vulnerability must really keep both rows.
        self.assertEqual(
            sorted(key for key in surviving_keys if key[0] == CVE_MULTI),
            [(CVE_MULTI, "alpha"), (CVE_MULTI, "beta")],
        )

    def _assert_impact_semantics(self, catalog: Catalog) -> None:
        records = impact_index(catalog.impact())

        # Exactly the ten impact records the last successful import produced,
        # in both services the global source name affects.
        self.assertEqual(
            set(records),
            {
                (API, "lib", NVD, CVE_OLD),
                (API, "app", NVD, CVE_OLD),
                (API, "lib", ALT_SOURCE, CVE_OLD),
                (API, "app", ALT_SOURCE, CVE_OLD),
                (API, "urllib3", None, CVE_MANUAL),
                (API, "alpha", NVD, CVE_MULTI),
                (WORKER, "redis", NVD, CVE_DROP),
                (WORKER, "queue", NVD, CVE_DROP),
                (WORKER, "beta", NVD, CVE_MULTI),
                (WORKER, "requests", ALT_SOURCE, CVE_ALT),
            },
        )

        # Direct hit: the old conditions and declared high survive (the
        # failed file carried 2.5.0/critical with no interval).
        lib_nvd = records[(API, "lib", NVD, CVE_OLD)]
        self.assertTrue(lib_nvd["direct"])
        self.assertEqual(lib_nvd["severity"], "high")
        self.assertEqual(lib_nvd["severity_basis"], "declared")
        self.assertEqual(
            lib_nvd["matched_conditions"], ["==2.0.0", ">=1.0,<3.0"]
        )
        self.assertEqual(
            [node["name"] for node in lib_nvd["path"]], ["lib"]
        )

        # Propagated impact keeps the terminal's old conditions/rating and the
        # unchanged path app -> lib.
        app_nvd = records[(API, "app", NVD, CVE_OLD)]
        self.assertFalse(app_nvd["direct"])
        self.assertEqual(app_nvd["severity"], "high")
        self.assertEqual(app_nvd["severity_basis"], "declared")
        self.assertEqual(
            app_nvd["matched_conditions"], ["==2.0.0", ">=1.0,<3.0"]
        )
        self.assertEqual(
            [node["name"] for node in app_nvd["path"]], ["app", "lib"]
        )

        # The other source's same-numbered vulnerability is a separate record
        # with its own (low) rating; it is not part of the rolled-back source.
        lib_alt = records[(API, "lib", ALT_SOURCE, CVE_OLD)]
        app_alt = records[(API, "app", ALT_SOURCE, CVE_OLD)]
        self.assertTrue(lib_alt["direct"])
        self.assertEqual(lib_alt["severity"], "low")
        self.assertEqual(lib_alt["severity_basis"], "declared")
        self.assertEqual(lib_alt["matched_conditions"], ["==2.0.0"])
        self.assertFalse(app_alt["direct"])
        self.assertEqual(app_alt["severity"], "low")
        self.assertEqual(
            [node["name"] for node in app_alt["path"]], ["app", "lib"]
        )

        # Default-severity source hit plus its dependency-propagated impact in
        # the other service keep the old medium/default conditions and path.
        redis = records[(WORKER, "redis", NVD, CVE_DROP)]
        queue = records[(WORKER, "queue", NVD, CVE_DROP)]
        self.assertTrue(redis["direct"])
        self.assertEqual(redis["severity"], "medium")
        self.assertEqual(redis["severity_basis"], "default")
        self.assertEqual(redis["matched_conditions"], ["==7.0.0"])
        self.assertFalse(queue["direct"])
        self.assertEqual(queue["severity"], "medium")
        self.assertEqual(queue["severity_basis"], "default")
        self.assertEqual(
            [node["name"] for node in queue["path"]], ["queue", "redis"]
        )

        # Both packages of the two-package vulnerability, one per service.
        alpha = records[(API, "alpha", NVD, CVE_MULTI)]
        beta = records[(WORKER, "beta", NVD, CVE_MULTI)]
        self.assertTrue(alpha["direct"])
        self.assertEqual(alpha["severity"], "high")
        self.assertEqual(alpha["matched_conditions"], ["==1.0.0"])
        self.assertTrue(beta["direct"])
        self.assertEqual(beta["severity"], "high")
        self.assertEqual(beta["matched_conditions"], ["==3.0.0"])

        # Manually registered vulnerability is untouched.
        urllib3 = records[(API, "urllib3", None, CVE_MANUAL)]
        self.assertTrue(urllib3["direct"])
        self.assertEqual(urllib3["severity"], "high")
        self.assertIsNone(urllib3["severity_basis"])
        self.assertIsNone(urllib3["matched_conditions"])

        # The other source's own vulnerability still hits.
        requests_hit = records[(WORKER, "requests", ALT_SOURCE, CVE_ALT)]
        self.assertTrue(requests_hit["direct"])
        self.assertEqual(requests_hit["severity"], "high")

        # Withdrawn record never participates, even though its row is stored.
        self.assertNotIn((WORKER, "memcache", NVD, CVE_WITHDRAWN), records)
        # Unmatched record has no impact either.
        self.assertNotIn((API, "django", NVD, CVE_UNMATCHED), records)

    def _assert_report_semantics(self, catalog: Catalog) -> None:
        report = catalog.risk_report(evaluated_at=EVAL_AT)
        self.assertEqual(report["impact_count"], 10)
        self.assertEqual(report["unhandled_component_count"], 8)
        self.assertEqual(report["highest_severity"], "high")

        entries = impact_index(report["impacts"])
        # The approved, unexpired exemption still applies to exactly the
        # application's target-source record, at its original approved level.
        app_nvd = entries[(API, "app", NVD, CVE_OLD)]
        self.assertTrue(app_nvd["exempted"])
        self.assertEqual(app_nvd["exemption_request"], EXEMPTION_ID)
        self.assertIsNone(app_nvd["not_exempt_reason"])
        # The same component's other-source record is a different scope and
        # stays unhandled.
        app_alt = entries[(API, "app", ALT_SOURCE, CVE_OLD)]
        self.assertFalse(app_alt["exempted"])
        self.assertIsNone(app_alt["exemption_request"])
        # A directly hit library with no exemption stays unhandled.
        self.assertFalse(entries[(API, "lib", NVD, CVE_OLD)]["exempted"])

        # Service-scoped reports independently reproduce the old state.
        api_report = catalog.risk_report(service=API, evaluated_at=EVAL_AT)
        self.assertEqual(
            {entry["component"]["service"] for entry in api_report["impacts"]},
            {API},
        )
        worker_report = catalog.risk_report(service=WORKER, evaluated_at=EVAL_AT)
        self.assertEqual(
            {
                entry["component"]["service"]
                for entry in worker_report["impacts"]
            },
            {WORKER},
        )
        # The application's exemption leaves the other three api components
        # unhandled; worker has no exemption at all.
        self.assertEqual(api_report["unhandled_component_count"], 4)
        self.assertEqual(worker_report["unhandled_component_count"], 4)

    def _assert_exemption_semantics(self, catalog: Catalog) -> None:
        request = catalog.get_exemption(EXEMPTION_ID)
        self.assertEqual(request["status"], "approved")
        self.assertEqual(request["applicant"], "alice")
        self.assertEqual(
            request["reason"],
            "egress proxy mitigates the transitive library exposure",
        )
        self.assertEqual(request["approver"], "bob")
        self.assertEqual(request["approved_severity"], "high")
        self.assertEqual(request["scope"], {
            "service": API,
            "ecosystem": "pypi",
            "name": "app",
            "version": "1.0.0",
            "vulnerability": CVE_OLD,
            "matched_name": "lib",
            "source": NVD,
        })
        self.assertEqual(
            [
                (
                    event["action"],
                    event["actor"],
                    event["from_status"],
                    event["to_status"],
                )
                for event in request["events"]
            ],
            [
                ("request", "alice", None, "pending"),
                ("approve", "bob", "pending", "approved"),
            ],
        )
        approved = catalog.list_exemptions(status="approved")
        self.assertEqual([item["id"] for item in approved], [EXEMPTION_ID])

    def _trace_failed_import(
        self, catalog: Catalog, use_file: bool, directory: str
    ) -> list[str]:
        if use_file:
            path = Path(directory, "replacement.json")
            path.write_text(json.dumps(replacement_nvd_records()))

        statements: list[str] = []
        catalog.connection.set_trace_callback(statements.append)
        try:
            with self.assertRaises(sqlite3.Error) as caught:
                if use_file:
                    catalog.import_osv_file(NVD, path)
                else:
                    catalog.import_osv(NVD, replacement_nvd_records())
        finally:
            catalog.connection.set_trace_callback(None)

        # A save-stage database error, not a content validation ValueError:
        # every record already passed validation before the transaction.
        self.assertEqual(type(caught.exception), sqlite3.IntegrityError)
        self.assertNotIsInstance(caught.exception, ValueError)
        return [statement.strip() for statement in statements]

    def _assert_partial_save_then_rollback(self, statements: list[str]) -> None:
        # The replacement really had started: the source's previous rows were
        # deleted inside the transaction and new rows were already inserted
        # before the error (the failing row is not the first one).
        self.assertTrue(
            any(s.startswith("DELETE FROM osv_vulnerabilities") for s in statements)
        )
        self.assertTrue(
            any(s.startswith("INSERT INTO osv_vulnerabilities") for s in statements)
        )
        # Everything was rolled back; no success commit exists.
        self.assertIn("ROLLBACK", statements)
        self.assertNotIn("COMMIT", statements)

    def _run_mid_save_failure(self, use_file: bool) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)
            snapshot = take_snapshot(catalog)
            self._assert_old_rows_exactly(catalog)
            self._assert_impact_semantics(catalog)
            self._assert_report_semantics(catalog)
            self._assert_exemption_semantics(catalog)

            catalog.connection.execute(MID_SAVE_FAILURE_TRIGGER)
            statements = self._trace_failed_import(catalog, use_file, directory)
            self._assert_partial_save_then_rollback(statements)

            # Same connection: the whole source is back to its last successful
            # import; no new/modified row lingers; all derived state matches.
            self._assert_old_rows_exactly(catalog)
            self.assertEqual(take_snapshot(catalog), snapshot)
            self._assert_impact_semantics(catalog)
            self._assert_report_semantics(catalog)
            self._assert_exemption_semantics(catalog)
            catalog.close()

            # Durable rollback after reopening the file.
            reopened = Catalog(database)
            self._assert_old_rows_exactly(reopened)
            self.assertEqual(take_snapshot(reopened), snapshot)
            self._assert_impact_semantics(reopened)
            self._assert_report_semantics(reopened)
            self._assert_exemption_semantics(reopened)

            # Re-importing the original content is a pure no-op (still six
            # rows, nothing added or removed): the failed attempt lost the
            # source no attribution, and ordinary writes still work.
            self.assertEqual(reopened.import_osv(NVD, old_nvd_records()), 6)
            self.assertEqual(take_snapshot(reopened), snapshot)

            # Withdrawing the *other* source leaves the failed source's rows
            # and every one of their impacts intact - the rollback did not
            # silently merge the two sources.
            self.assertEqual(reopened.import_osv(ALT_SOURCE, []), 0)
            self.assertEqual(osv_rows(reopened)[NVD], EXPECTED_OLD_NVD_ROWS)
            remaining = impact_index(reopened.impact())
            self.assertIn((API, "lib", NVD, CVE_OLD), remaining)
            self.assertIn((API, "app", NVD, CVE_OLD), remaining)
            self.assertIn((WORKER, "redis", NVD, CVE_DROP), remaining)
            self.assertIn((API, "alpha", NVD, CVE_MULTI), remaining)
            self.assertIn((WORKER, "beta", NVD, CVE_MULTI), remaining)
            self.assertNotIn((WORKER, "requests", ALT_SOURCE, CVE_ALT), remaining)
            self.assertNotIn((API, "lib", ALT_SOURCE, CVE_OLD), remaining)

            # Drop the persisted failure trigger, then the previously failing
            # replacement succeeds normally and really replaces the rows;
            # clearing the source with [] after that works too.
            reopened.connection.execute("DROP TRIGGER IF EXISTS fail_osv_save")
            self.assertEqual(
                reopened.import_osv(NVD, replacement_nvd_records()), 5
            )
            replaced = osv_rows(reopened)[NVD]
            self.assertEqual(
                replaced[(CVE_OLD, "lib")],
                ("critical", False, None, [explicit("2.5.0")]),
            )
            self.assertEqual(
                replaced[(CVE_MULTI, "alpha")],
                ("low", False, None, [explicit("9.9.9")]),
            )
            self.assertIn((CVE_NEW, SENTINEL_PACKAGE), replaced)
            self.assertIn((CVE_TAIL, "zebra"), replaced)
            self.assertNotIn((CVE_DROP, "redis"), replaced)
            self.assertEqual(reopened.import_osv(NVD, []), 0)
            self.assertEqual(osv_rows(reopened).get(NVD, {}), {})
            # The exemption request and history survive the source going away.
            request = reopened.get_exemption(EXEMPTION_ID)
            self.assertEqual(request["status"], "approved")
            self.assertEqual(len(request["events"]), 2)
            reopened.close()

    def test_mid_save_failure_rolls_back_everything(self) -> None:
        self._run_mid_save_failure(use_file=False)

    def test_mid_save_failure_through_file_entry_point(self) -> None:
        self._run_mid_save_failure(use_file=True)

    def test_failure_on_first_new_row_is_also_fully_rolled_back(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)
            snapshot = take_snapshot(catalog)

            catalog.connection.execute(FIRST_ROW_SAVE_FAILURE_TRIGGER)
            statements: list[str] = []
            catalog.connection.set_trace_callback(statements.append)
            try:
                with self.assertRaises(sqlite3.IntegrityError):
                    catalog.import_osv(NVD, replacement_nvd_records())
            finally:
                catalog.connection.set_trace_callback(None)
            statements = [s.strip() for s in statements]
            self.assertTrue(
                any(s.startswith("DELETE FROM osv_vulnerabilities") for s in statements)
            )
            self.assertIn("ROLLBACK", statements)
            self.assertNotIn("COMMIT", statements)

            self._assert_old_rows_exactly(catalog)
            self.assertEqual(take_snapshot(catalog), snapshot)
            catalog.close()

            reopened = Catalog(database)
            self.assertEqual(osv_rows(reopened)[NVD], EXPECTED_OLD_NVD_ROWS)
            self.assertEqual(take_snapshot(reopened), snapshot)
            reopened.close()


class OsvReplacementValidationFailureContrastTests(unittest.TestCase):
    """Validation failures reject before the save transaction even begins.

    These are the existing public failure cases; they must stay distinguishable
    from the injected save-stage failure (a ``ValueError`` with zero SQL
    statements, versus a database error after DELETEs and partial INSERTs that
    a transaction rolls back).
    """

    def _borrowing_record(self):
        return {
            "id": "CVE-2026-5999",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "Foo_Bar"},
                    "versions": ["1.0"],
                },
                {"package": {"ecosystem": "PyPI", "name": "foo-bar"}},
            ],
        }

    def test_invalid_inputs_fail_before_any_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)
            snapshot = take_snapshot(catalog)

            bad_file = Path(directory, "broken.json")
            bad_file.write_text("{not valid json")

            cases = [
                (
                    "entry borrowing sibling conditions",
                    lambda: catalog.import_osv(NVD, [self._borrowing_record()]),
                    "affected[1]",
                ),
                (
                    "unsupported ecosystem",
                    lambda: catalog.import_osv(
                        NVD,
                        [
                            {
                                "id": "CVE-2026-5998",
                                "affected": [
                                    {
                                        "package": {
                                            "ecosystem": "npm",
                                            "name": "foo",
                                        },
                                        "versions": ["1.0"],
                                    }
                                ],
                            }
                        ],
                    ),
                    "npm",
                ),
                (
                    "top level not an array",
                    lambda: catalog.import_osv(NVD, {"id": "CVE-2026-5997"}),
                    "数组",
                ),
                (
                    "blank source name",
                    lambda: catalog.import_osv("  ", []),
                    "不能为空",
                ),
                (
                    "missing file",
                    lambda: catalog.import_osv_file(
                        NVD, Path(directory, "missing.json")
                    ),
                    "无法读取文件",
                ),
                (
                    "invalid json file",
                    lambda: catalog.import_osv_file(NVD, bad_file),
                    "不是有效的 JSON",
                ),
            ]
            for label, attempt, offending in cases:
                with self.subTest(case=label):
                    statements: list[str] = []
                    catalog.connection.set_trace_callback(statements.append)
                    try:
                        with self.assertRaises(ValueError) as caught:
                            attempt()
                    finally:
                        catalog.connection.set_trace_callback(None)
                    self.assertIn(offending, str(caught.exception))
                    self.assertFalse(
                        [s for s in statements if s.strip()],
                        "validation must reject before any SQL runs",
                    )
                    self.assertEqual(take_snapshot(catalog), snapshot)

            self.assertEqual(osv_rows(catalog)[NVD], EXPECTED_OLD_NVD_ROWS)
            catalog.close()

    def test_duplicate_id_rejects_before_any_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            catalog = build_catalog(str(Path(directory, "catalog.db")))
            snapshot = take_snapshot(catalog)
            records = [
                osv("CVE-2026-5888", [entry("foo", ["1.0"])]),
                osv("CVE-2026-5888", [entry("bar", ["2.0"])]),
            ]
            statements: list[str] = []
            catalog.connection.set_trace_callback(statements.append)
            try:
                with self.assertRaises(ValueError) as caught:
                    catalog.import_osv(NVD, records)
            finally:
                catalog.connection.set_trace_callback(None)
            self.assertIn("CVE-2026-5888", str(caught.exception))
            self.assertFalse(
                [s for s in statements if s.strip()],
                "duplicate ids must be rejected before any SQL runs",
            )
            self.assertEqual(take_snapshot(catalog), snapshot)
            catalog.close()


class OsvReplacementSuccessPreservedTests(unittest.TestCase):
    """Legal replacement, empty-array clearing and CLI output stay public."""

    def test_successful_legal_replacement_replaces_and_keeps_other_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            catalog = build_catalog(str(Path(directory, "catalog.db")))
            self.assertEqual(
                catalog.import_osv(NVD, replacement_nvd_records()), 5
            )

            rows = osv_rows(catalog)
            self.assertEqual(set(rows[NVD]), {
                (CVE_OLD, "lib"),
                (CVE_MULTI, "alpha"),
                (CVE_MULTI, "beta"),
                (CVE_NEW, SENTINEL_PACKAGE),
                (CVE_TAIL, "zebra"),
            })
            self.assertEqual(
                rows[NVD][(CVE_OLD, "lib")],
                ("critical", False, None, [explicit("2.5.0")]),
            )
            # Dropped vulnerabilities are gone from this source.
            self.assertNotIn((CVE_DROP, "redis"), rows[NVD])
            self.assertNotIn((CVE_WITHDRAWN, "memcache"), rows[NVD])
            self.assertNotIn((CVE_UNMATCHED, "django"), rows[NVD])
            # Other source and manual observations are untouched.
            self.assertEqual(rows[ALT_SOURCE], EXPECTED_OLD_ALT_ROWS)
            self.assertEqual(
                manual_vulnerability_rows(catalog),
                [(CVE_MANUAL, "urllib3", "high")],
            )

            records = impact_index(catalog.impact())
            # Nothing is pinned to lib 2.5.0, so the target source's CVE_OLD
            # impact disappears; the other source still carries the same id.
            self.assertNotIn((API, "lib", NVD, CVE_OLD), records)
            self.assertNotIn((API, "app", NVD, CVE_OLD), records)
            self.assertIn((API, "lib", ALT_SOURCE, CVE_OLD), records)
            self.assertIn((API, "app", ALT_SOURCE, CVE_OLD), records)
            # The dropped default-medium hit and the two-package old versions
            # are gone; manual and other-source hits remain.
            self.assertNotIn((WORKER, "redis", NVD, CVE_DROP), records)
            self.assertNotIn((WORKER, "queue", NVD, CVE_DROP), records)
            self.assertNotIn((API, "alpha", NVD, CVE_MULTI), records)
            self.assertNotIn((WORKER, "beta", NVD, CVE_MULTI), records)
            self.assertIn((API, "urllib3", None, CVE_MANUAL), records)
            self.assertIn((WORKER, "requests", ALT_SOURCE, CVE_ALT), records)

            # The exemption request outlives the disappearance of its scope's
            # target-source impact; its content and history are not rewritten.
            request = catalog.get_exemption(EXEMPTION_ID)
            self.assertEqual(request["status"], "approved")
            self.assertEqual(request["approved_severity"], "high")
            self.assertEqual(len(request["events"]), 2)
            catalog.close()

    def test_empty_array_clears_only_the_target_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            catalog = build_catalog(str(Path(directory, "catalog.db")))
            self.assertEqual(catalog.import_osv(NVD, []), 0)
            self.assertEqual(osv_rows(catalog).get(NVD, {}), {})
            self.assertEqual(
                osv_rows(catalog)[ALT_SOURCE], EXPECTED_OLD_ALT_ROWS
            )

            records = impact_index(catalog.impact())
            # Every target-source impact is gone, but the other source and the
            # manual observation still keep the components at risk.
            self.assertNotIn((API, "lib", NVD, CVE_OLD), records)
            self.assertNotIn((WORKER, "redis", NVD, CVE_DROP), records)
            self.assertIn((API, "lib", ALT_SOURCE, CVE_OLD), records)
            self.assertIn((API, "app", ALT_SOURCE, CVE_OLD), records)
            self.assertIn((WORKER, "requests", ALT_SOURCE, CVE_ALT), records)
            self.assertIn((API, "urllib3", None, CVE_MANUAL), records)
            # Components and dependencies are not replacement objects.
            self.assertEqual(len(component_identities(catalog)), 9)
            self.assertEqual(len(dependency_pairs(catalog)), 2)
            catalog.close()

    def test_cli_reports_success_count_for_a_valid_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            build_catalog(database).close()
            path = Path(directory, "replacement.json")
            path.write_text(json.dumps(replacement_nvd_records()))

            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(io.StringIO()):
                status = main([
                    "--database", database,
                    "import-osv", NVD, str(path),
                ])
            self.assertEqual(status, 0)
            self.assertIn("导入漏洞记录: 5 条", output.getvalue())

            catalog = Catalog(database)
            self.assertIn(
                (CVE_NEW, SENTINEL_PACKAGE), osv_rows(catalog)[NVD]
            )
            self.assertNotIn((CVE_DROP, "redis"), osv_rows(catalog)[NVD])
            catalog.close()


if __name__ == "__main__":
    unittest.main()
