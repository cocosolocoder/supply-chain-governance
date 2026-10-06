"""Regression tests for an exemption whose impact flips direct -> indirect.

The business case uses two versions of the same PyPI package in one service:
``web 2.0.0`` depends on ``web 1.0.0``. A local OSV source first declares both
versions affected by the same vulnerability at ``high`` severity. In that
state ``web 2.0.0`` is itself a direct hit: its one impact record is
``direct: true`` with a self-only path and the ``==2.0.0`` condition, even
though it can also follow its dependency to another directly hit version -
that reachability must never produce a second, indirect record for the same
(component, vulnerability, source, matched package).

An exemption is then requested for exactly that ``web 2.0.0`` record and
approved while still in force; the ``web 1.0.0`` record stays unexempted.
While the approval is in force the same source is replaced so the
vulnerability only affects ``web 1.0.0``; the vulnerability id, matched
package and high level are unchanged, and the component/dependency graph is
unchanged. ``web 2.0.0`` must keep exactly one impact record, but it now has
to be an indirect hit: the path goes ``2.0.0 -> 1.0.0`` and the matched
conditions explain ``1.0.0`` - the old direct explanation must not linger,
and a stale direct record must not be kept beside the new indirect one.

The exemption scope is the component identity, vulnerability id, matched
package and source only. Neither the direct/indirect flag nor the dependency
path belongs to it, so the approval keeps applying to the record while its
explanation changes: the request scope, the severity captured at approval
time and the full processing history stay exactly as they were, and the
replacement must not append an approval event. The service-scoped query, the
full-component-identity query and the risk report all explain ``web 2.0.0``
identically; with just these two versions and this source the report always
has two impact records, one unhandled component and ``high`` as the highest
unhandled severity. A second source carrying the same vulnerability id and
package name is a different scope and cannot borrow the approval: its
``web 2.0.0`` record stays unexempted and the component counts as unhandled.

The tests exercise only the existing public behavior - the same commands,
JSON structures and exemption rules - including persistence after reopening
the database and the CLI entry points.
"""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard.cli import main

SERVICE = "api"
ECOSYSTEM = "pypi"
PACKAGE = "web"
V2 = "2.0.0"
V1 = "1.0.0"
SOURCE = "nvd"
OTHER_SOURCE = "ghsa"
CVE = "CVE-2026-8001"
EXEMPTION_ID = "EXM-2026-8001"
OTHER_REQUEST_ID = "EXM-2026-8002"

SUBMITTED_AT = datetime(2026, 1, 10, 0, 0, tzinfo=timezone.utc)
APPROVED_AT = datetime(2026, 1, 11, 0, 0, tzinfo=timezone.utc)
EXPIRES_AT = "2030-12-31T23:59:59+00:00"
EVAL_AT = "2026-06-01T00:00:00+00:00"

# The fields that explain an impact; impact records consist of exactly these,
# and the risk report carries the same values plus exemption linkage fields.
EXPLANATION_FIELDS = (
    "component",
    "vulnerability",
    "source",
    "matched_name",
    "severity",
    "severity_basis",
    "direct",
    "matched_conditions",
    "path",
)


def identity(version: str) -> dict:
    return {
        "service": SERVICE,
        "ecosystem": ECOSYSTEM,
        "name": PACKAGE,
        "version": version,
    }


def osv_record(versions: list[str], *, severity: str | None = "high") -> dict:
    record = {
        "id": CVE,
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": PACKAGE},
                "versions": list(versions),
            }
        ],
    }
    if severity is not None:
        record["database_specific"] = {"severity": severity}
    return record


# The source's first declaration: both versions directly hit at declared high.
BOTH_VERSIONS_RECORDS = [osv_record([V1, V2])]
# The replacement declaration: only 1.0.0 stays hit; id/package/severity match.
ONLY_V1_RECORDS = [osv_record([V1])]


def expected_v1_direct() -> dict:
    return {
        "component": identity(V1),
        "vulnerability": CVE,
        "source": SOURCE,
        "matched_name": PACKAGE,
        "severity": "high",
        "severity_basis": "declared",
        "direct": True,
        "matched_conditions": ["==1.0.0"],
        "path": [identity(V1)],
    }


def expected_v2_direct() -> dict:
    return {
        "component": identity(V2),
        "vulnerability": CVE,
        "source": SOURCE,
        "matched_name": PACKAGE,
        "severity": "high",
        "severity_basis": "declared",
        "direct": True,
        "matched_conditions": ["==2.0.0"],
        "path": [identity(V2)],
    }


def expected_v2_indirect() -> dict:
    return {
        "component": identity(V2),
        "vulnerability": CVE,
        "source": SOURCE,
        "matched_name": PACKAGE,
        "severity": "high",
        "severity_basis": "declared",
        "direct": False,
        "matched_conditions": ["==1.0.0"],
        "path": [identity(V2), identity(V1)],
    }


def expected_scope() -> dict:
    return {
        "service": SERVICE,
        "ecosystem": ECOSYSTEM,
        "name": PACKAGE,
        "version": V2,
        "vulnerability": CVE,
        "matched_name": PACKAGE,
        "source": SOURCE,
    }


def build_catalog(database: str | Path = ":memory:") -> Catalog:
    """Two versions of one package, 2.0.0 depending on 1.0.0, source hitting
    both. No exemption is requested yet; individual tests drive the request."""
    catalog = Catalog(database)
    catalog.add_component(SERVICE, ECOSYSTEM, PACKAGE, V2)
    catalog.add_component(SERVICE, ECOSYSTEM, PACKAGE, V1)
    catalog.add_dependency(
        SERVICE, ECOSYSTEM, PACKAGE, V2,
        SERVICE, ECOSYSTEM, PACKAGE, V1,
    )
    catalog.import_osv(SOURCE, BOTH_VERSIONS_RECORDS)
    return catalog


def request_and_approve_v2(catalog: Catalog) -> dict:
    catalog.request_exemption(
        EXEMPTION_ID,
        SERVICE, ECOSYSTEM, PACKAGE, V2,
        CVE, PACKAGE, SOURCE,
        applicant="alice",
        reason="accept the web 2.0.0 exposure for the term",
        expires_at=EXPIRES_AT,
        submitted_at=SUBMITTED_AT,
    )
    return catalog.approve_exemption(
        EXEMPTION_ID,
        handler="bob",
        note="compensating controls verified",
        decided_at=APPROVED_AT,
    )


# Selector sentinel: match records of every source, as opposed to source=None
# which means only a manually registered vulnerability.
ANY_SOURCE = object()


def select(records: list[dict], version: str, *, source=SOURCE):
    """All records of one package version for the CVE, restricted to a source.

    Pass ``source=None`` for the manually-registered source or
    ``source=ANY_SOURCE`` to include every source; the default is the OSV
    source under test.
    """
    return [
        record
        for record in records
        if record["component"]["service"] == SERVICE
        and record["component"]["ecosystem"] == ECOSYSTEM
        and record["component"]["name"] == PACKAGE
        and record["component"]["version"] == version
        and record["vulnerability"] == CVE
        and (source is ANY_SOURCE or record["source"] == source)
    ]


def explanation(record: dict) -> dict:
    return {field: record[field] for field in EXPLANATION_FIELDS}


class DirectHitNotDuplicatedAsIndirectTests(unittest.TestCase):
    """Before the replacement both versions are direct hits.

    ``web 2.0.0`` is itself a terminal of the hit group and can additionally
    reach the other directly hit version (``web 1.0.0``) along its dependency.
    The one-record-per-(component, vulnerability, source, package) rule means
    it gets exactly one, direct record - a second indirect record for the same
    tuple must never appear.
    """

    def setUp(self) -> None:
        self.catalog = build_catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def test_both_versions_are_direct_with_self_only_paths_and_own_conditions(
        self,
    ) -> None:
        records = self.catalog.impact(service=SERVICE)
        # Only the two versions and this source exist: exactly two records.
        self.assertEqual(len(records), 2)
        self.assertEqual(select(records, V1), [expected_v1_direct()])
        self.assertEqual(select(records, V2), [expected_v2_direct()])

    def test_reaching_a_second_direct_hit_adds_no_indirect_record_for_v2(
        self,
    ) -> None:
        for label, records in (
            ("directory-wide", self.catalog.impact()),
            ("service-scoped", self.catalog.impact(service=SERVICE)),
        ):
            with self.subTest(query=label):
                v2_records = select(records, V2)
                # Not two records (a direct and an indirect one) - just one.
                self.assertEqual(len(v2_records), 1)
                record = v2_records[0]
                self.assertTrue(record["direct"])
                # The path is itself only; it never continues to web 1.0.0,
                # although that edge exists and reaches another hit.
                self.assertEqual(record["path"], [identity(V2)])
                self.assertEqual(record["matched_conditions"], ["==2.0.0"])

    def test_full_identity_query_returns_the_same_single_record(self) -> None:
        service_record = select(self.catalog.impact(service=SERVICE), V2)
        identity_record = self.catalog.impact(
            service=SERVICE, ecosystem=ECOSYSTEM, name=PACKAGE, version=V2
        )
        self.assertEqual(identity_record, service_record)
        self.assertEqual(identity_record, [expected_v2_direct()])

    def test_approving_v2_record_leaves_the_v1_record_unexempted(self) -> None:
        request_and_approve_v2(self.catalog)
        report = self.catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
        self.assertEqual(report["impact_count"], 2)
        self.assertEqual(report["unhandled_component_count"], 1)
        self.assertEqual(report["highest_severity"], "high")

        v2 = select(report["impacts"], V2)[0]
        self.assertTrue(v2["exempted"])
        self.assertEqual(v2["exemption_request"], EXEMPTION_ID)
        self.assertIsNone(v2["not_exempt_reason"])

        # The other version's record is a different component identity and so
        # stays unhandled, with no request linked to it at all.
        v1 = select(report["impacts"], V1)[0]
        self.assertFalse(v1["exempted"])
        self.assertIsNone(v1["exemption_request"])
        self.assertIsNone(v1["not_exempt_reason"])


class DirectToIndirectReplacementTests(unittest.TestCase):
    """After the mid-term source replacement the same record becomes indirect.

    The approval granted for the direct record stays in force by its original
    scope while the current explanation (flag, path, conditions) changes.
    """

    def setUp(self) -> None:
        self.catalog = build_catalog()
        request_and_approve_v2(self.catalog)
        # The request exactly as it stood immediately after approval; the
        # replacement must leave this entire document (including history)
        # byte-for-byte unchanged.
        self.approved_request = self.catalog.get_exemption(EXEMPTION_ID)
        self.assertEqual(self.approved_request["status"], "approved")
        self.import_count = self.catalog.import_osv(SOURCE, ONLY_V1_RECORDS)

    def tearDown(self) -> None:
        self.catalog.close()

    def test_replacement_replaces_the_source_and_keeps_one_vulnerability_row(
        self,
    ) -> None:
        self.assertEqual(self.import_count, 1)
        rows = list(
            self.catalog.connection.execute(
                "SELECT id, package_name, severity FROM osv_vulnerabilities"
            )
        )
        self.assertEqual(
            [(str(r["id"]), str(r["package_name"]), str(r["severity"])) for r in rows],
            [(CVE, PACKAGE, "high")],
        )

    def test_v2_keeps_one_record_but_it_is_now_indirect(self) -> None:
        records = self.catalog.impact(service=SERVICE)
        self.assertEqual(len(records), 2)
        v2_records = select(records, V2)
        # No lingering direct record beside the indirect one: still exactly one.
        self.assertEqual(len(v2_records), 1)
        self.assertEqual(v2_records, [expected_v2_indirect()])
        # The 1.0.0 terminal itself is unchanged.
        self.assertEqual(select(records, V1), [expected_v1_direct()])

    def test_indirect_explanation_uses_current_conditions_not_old_direct_ones(
        self,
    ) -> None:
        record = select(self.catalog.impact(service=SERVICE), V2)[0]
        self.assertFalse(record["direct"])
        self.assertEqual(
            [node["version"] for node in record["path"]], [V2, V1]
        )
        # The matched condition now explains the terminal 1.0.0 hit; the old
        # ==2.0.0 direct condition must not survive or mix into the record.
        self.assertEqual(record["matched_conditions"], ["==1.0.0"])
        self.assertNotIn("==2.0.0", record["matched_conditions"])
        self.assertEqual(record["severity"], "high")
        self.assertEqual(record["severity_basis"], "declared")

        # Re-querying reproduces the same current explanation; nothing about
        # the previous direct answer is cached on the record.
        again = select(self.catalog.impact(service=SERVICE), V2)[0]
        self.assertEqual(again, record)

    def test_service_and_full_identity_queries_and_report_explain_v2_identically(
        self,
    ) -> None:
        service_record = select(self.catalog.impact(service=SERVICE), V2)[0]
        identity_records = self.catalog.impact(
            service=SERVICE, ecosystem=ECOSYSTEM, name=PACKAGE, version=V2
        )
        self.assertEqual(len(identity_records), 1)
        self.assertEqual(identity_records[0], service_record)

        directory_record = select(self.catalog.impact(), V2)[0]
        self.assertEqual(directory_record, service_record)

        report = self.catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
        report_v2 = select(report["impacts"], V2)[0]
        self.assertEqual(explanation(report_v2), explanation(service_record))
        self.assertEqual(explanation(report_v2), expected_v2_indirect())

        # The unscoped report (only one service exists) explains it the same.
        full_report = self.catalog.risk_report(evaluated_at=EVAL_AT)
        full_report_v2 = select(full_report["impacts"], V2)[0]
        self.assertEqual(
            explanation(full_report_v2), explanation(report_v2)
        )

    def test_report_counts_stay_two_records_one_unhandled_high(self) -> None:
        # After the flip the counts are unchanged from the pre-replacement
        # state covered earlier: only the explanation of the still-exempted
        # 2.0.0 record changes.
        for scope in (SERVICE, None):
            with self.subTest(scope=scope):
                report = self.catalog.risk_report(
                    service=scope, evaluated_at=EVAL_AT
                )
                self.assertEqual(report["impact_count"], 2)
                self.assertEqual(report["unhandled_component_count"], 1)
                self.assertEqual(report["highest_severity"], "high")

    def test_exemption_remains_in_force_while_the_explanation_changes(self) -> None:
        report = self.catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
        v2 = select(report["impacts"], V2)[0]
        # The indirect record keeps linking the original approved request and
        # is covered by it; no "out of approval scope" reason is attached.
        self.assertFalse(v2["direct"])
        self.assertTrue(v2["exempted"])
        self.assertEqual(v2["exemption_request"], EXEMPTION_ID)
        self.assertIsNone(v2["not_exempt_reason"])

        # The 1.0.0 record remains unhandled despite the family relationship.
        v1 = select(report["impacts"], V1)[0]
        self.assertFalse(v1["exempted"])
        self.assertIsNone(v1["exemption_request"])

    def test_request_scope_approved_level_and_history_are_untouched(self) -> None:
        request = self.catalog.get_exemption(EXEMPTION_ID)
        # The whole request document - scope, captured severity, decision
        # metadata and the complete event stream - is unchanged by replacing
        # the vulnerability source.
        self.assertEqual(request, self.approved_request)
        self.assertEqual(request["scope"], expected_scope())
        self.assertEqual(request["status"], "approved")
        self.assertEqual(request["approved_severity"], "high")
        self.assertEqual(request["applicant"], "alice")
        self.assertEqual(request["approver"], "bob")
        self.assertEqual(
            request["reason"], "accept the web 2.0.0 exposure for the term"
        )
        self.assertEqual(request["expires_at"], "2030-12-31T23:59:59.000000Z")
        # Exactly request + approve; the source swap appended no event.
        self.assertEqual(
            [
                (event["action"], event["actor"],
                 event["from_status"], event["to_status"])
                for event in request["events"]
            ],
            [
                ("request", "alice", None, "pending"),
                ("approve", "bob", "pending", "approved"),
            ],
        )
        self.assertEqual(
            [item["id"] for item in self.catalog.list_exemptions()],
            [EXEMPTION_ID],
        )

    def test_scope_stays_occupied_even_though_the_hit_is_now_indirect(self) -> None:
        # The indirect record exists and is a valid exemption target, but the
        # scope is still occupied by the unexpired approval: a new id for the
        # same seven-field scope is refused rather than becoming a second live
        # request, and the refusal changes nothing.
        with self.assertRaises(ValueError) as caught:
            self.catalog.request_exemption(
                OTHER_REQUEST_ID,
                SERVICE, ECOSYSTEM, PACKAGE, V2,
                CVE, PACKAGE, SOURCE,
                applicant="carol",
                reason="try to re-open the same scope",
                expires_at=EXPIRES_AT,
            )
        self.assertIn("同一范围", str(caught.exception))
        self.assertEqual(
            [item["id"] for item in self.catalog.list_exemptions()],
            [EXEMPTION_ID],
        )

        # Re-confirming the original id with identical content returns the
        # stored approval without re-checking the impact, extending the term
        # or appending history - even though the record is now indirect.
        confirmed = self.catalog.request_exemption(
            EXEMPTION_ID,
            SERVICE, ECOSYSTEM, PACKAGE, V2,
            CVE, PACKAGE, SOURCE,
            applicant="alice",
            reason="accept the web 2.0.0 exposure for the term",
            expires_at=EXPIRES_AT,
        )
        self.assertEqual(confirmed, self.approved_request)
        self.assertEqual(len(confirmed["events"]), 2)

    def test_indirect_explanation_and_linkage_survive_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)
            request_and_approve_v2(catalog)
            self.assertEqual(catalog.import_osv(SOURCE, ONLY_V1_RECORDS), 1)
            report_before = catalog.risk_report(
                service=SERVICE, evaluated_at=EVAL_AT
            )
            catalog.close()

            reopened = Catalog(database)
            self.assertEqual(
                select(reopened.impact(service=SERVICE), V2),
                [expected_v2_indirect()],
            )
            report_after = reopened.risk_report(
                service=SERVICE, evaluated_at=EVAL_AT
            )
            self.assertEqual(report_after, report_before)
            v2 = select(report_after["impacts"], V2)[0]
            self.assertTrue(v2["exempted"])
            self.assertEqual(v2["exemption_request"], EXEMPTION_ID)
            request = reopened.get_exemption(EXEMPTION_ID)
            self.assertEqual(request["status"], "approved")
            self.assertEqual(request["approved_severity"], "high")
            self.assertEqual(len(request["events"]), 2)
            reopened.close()


class OtherSourceCannotBorrowExemptionTests(unittest.TestCase):
    """The same CVE and package from another source is a separate scope.

    After the replacement the approved source only hits 1.0.0 directly; a
    second source then offers the same vulnerability id and package name. Its
    records must not be covered by the approval pinned to the first source,
    and web 2.0.0 - still carrying that source's unexempted record - counts as
    an unhandled component.
    """

    def setUp(self) -> None:
        self.catalog = build_catalog()
        request_and_approve_v2(self.catalog)
        self.catalog.import_osv(SOURCE, ONLY_V1_RECORDS)
        self.assertEqual(
            self.catalog.import_osv(OTHER_SOURCE, ONLY_V1_RECORDS), 1
        )

    def tearDown(self) -> None:
        self.catalog.close()

    def test_other_source_records_are_distinct_and_unexempted(self) -> None:
        records = self.catalog.impact(service=SERVICE)
        # Two versions times two sources: four records, never merged.
        self.assertEqual(len(records), 4)

        v2_sources = {
            record["source"]: record
            for record in select(records, V2, source=ANY_SOURCE)
        }
        self.assertEqual(set(v2_sources), {SOURCE, OTHER_SOURCE})
        # Each source reaches the 1.0.0 terminal indirectly; each is its own
        # record with its own source attribution.
        self.assertFalse(v2_sources[SOURCE]["direct"])
        self.assertFalse(v2_sources[OTHER_SOURCE]["direct"])
        self.assertEqual(
            v2_sources[OTHER_SOURCE]["matched_conditions"], ["==1.0.0"]
        )
        self.assertEqual(
            [node["version"] for node in v2_sources[OTHER_SOURCE]["path"]],
            [V2, V1],
        )

        # The full-identity query returns both source records for 2.0.0.
        identity_records = self.catalog.impact(
            service=SERVICE, ecosystem=ECOSYSTEM, name=PACKAGE, version=V2
        )
        self.assertEqual(
            sorted(record["source"] for record in identity_records),
            [OTHER_SOURCE, SOURCE],
        )

    def test_other_source_cannot_borrow_the_approval_and_counts_as_unhandled(
        self,
    ) -> None:
        report = self.catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT)
        self.assertEqual(report["impact_count"], 4)
        # web 2.0.0 has an unexempted other-source record, and web 1.0.0 has
        # two unexempted direct records: both versions are unhandled.
        self.assertEqual(report["unhandled_component_count"], 2)
        self.assertEqual(report["highest_severity"], "high")

        v2_nvd = select(report["impacts"], V2, source=SOURCE)[0]
        v2_other = select(report["impacts"], V2, source=OTHER_SOURCE)[0]
        self.assertTrue(v2_nvd["exempted"])
        self.assertEqual(v2_nvd["exemption_request"], EXEMPTION_ID)
        # No borrowing: the other-source record links to no request at all.
        self.assertFalse(v2_other["exempted"])
        self.assertIsNone(v2_other["exemption_request"])
        self.assertIsNone(v2_other["not_exempt_reason"])

        # Every other-source record (both versions) stays unhandled.
        other_entries = select(report["impacts"], V1, source=OTHER_SOURCE)
        self.assertEqual(len(other_entries), 1)
        self.assertFalse(other_entries[0]["exempted"])

        # The borrowed-scope check is symmetric: an approval scoped to the
        # other source would not cover the first source either.
        self.catalog.request_exemption(
            OTHER_REQUEST_ID,
            SERVICE, ECOSYSTEM, PACKAGE, V2,
            CVE, PACKAGE, OTHER_SOURCE,
            applicant="carol",
            reason="separate approval for the other source",
            expires_at=EXPIRES_AT,
        )
        self.catalog.approve_exemption(
            OTHER_REQUEST_ID, handler="dave", note="approved separately"
        )
        report_after = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVAL_AT
        )
        v2_nvd_after = select(report_after["impacts"], V2, source=SOURCE)[0]
        v2_other_after = select(
            report_after["impacts"], V2, source=OTHER_SOURCE
        )[0]
        self.assertTrue(v2_nvd_after["exempted"])
        self.assertEqual(v2_nvd_after["exemption_request"], EXEMPTION_ID)
        self.assertTrue(v2_other_after["exempted"])
        self.assertEqual(
            v2_other_after["exemption_request"], OTHER_REQUEST_ID
        )
        # Both versions' remaining unexempted records are the 1.0.0 direct
        # hits; 2.0.0 is fully covered (once per source).
        self.assertEqual(report_after["unhandled_component_count"], 1)


class CliDirectToIndirectContractTests(unittest.TestCase):
    """The existing commands and JSON output structure keep working."""

    def test_cli_replacement_indirect_explanation_and_exemption_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_catalog(database)
            request_and_approve_v2(catalog)
            catalog.close()

            replacement_path = Path(directory, "only-v1.json")
            replacement_path.write_text(json.dumps(ONLY_V1_RECORDS))

            def run_cli(*argv: str) -> tuple[int, str, str]:
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    status = main(["--database", database, *argv])
                return status, stdout.getvalue(), stderr.getvalue()

            # The source replacement command and its success count are intact.
            status, output, errors = run_cli(
                "import-osv", SOURCE, str(replacement_path)
            )
            self.assertEqual(status, 0)
            self.assertEqual(errors, "")
            self.assertIn("导入漏洞记录: 1 条", output)

            # Service-scoped impact: two records, web 2.0.0 now indirect.
            status, output, _ = run_cli("impact", "--service", SERVICE)
            self.assertEqual(status, 0)
            records = json.loads(output)
            self.assertEqual(len(records), 2)
            self.assertEqual(select(records, V2), [expected_v2_indirect()])

            # Full component identity impact gives the same explanation.
            status, output, _ = run_cli(
                "impact",
                "--service", SERVICE,
                "--ecosystem", ECOSYSTEM,
                "--name", PACKAGE,
                "--version", V2,
            )
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(output), [expected_v2_indirect()])

            # The risk report keeps path/flag/conditions and the exemption.
            status, output, _ = run_cli(
                "risk-report", "--service", SERVICE, "--at", EVAL_AT
            )
            self.assertEqual(status, 0)
            report = json.loads(output)
            self.assertEqual(report["impact_count"], 2)
            self.assertEqual(report["unhandled_component_count"], 1)
            self.assertEqual(report["highest_severity"], "high")
            v2 = select(report["impacts"], V2)[0]
            self.assertEqual(explanation(v2), expected_v2_indirect())
            self.assertTrue(v2["exempted"])
            self.assertEqual(v2["exemption_request"], EXEMPTION_ID)

            # The request and its history are queryable with the same shape.
            status, output, _ = run_cli("exemption-show", EXEMPTION_ID)
            self.assertEqual(status, 0)
            request = json.loads(output)
            self.assertEqual(request["status"], "approved")
            self.assertEqual(request["scope"], expected_scope())
            self.assertEqual(request["approved_severity"], "high")
            self.assertEqual(
                [event["action"] for event in request["events"]],
                ["request", "approve"],
            )

            status, output, _ = run_cli(
                "exemption-list", "--status", "approved"
            )
            self.assertEqual(status, 0)
            self.assertEqual(
                [item["id"] for item in json.loads(output)], [EXEMPTION_ID]
            )


if __name__ == "__main__":
    unittest.main()
