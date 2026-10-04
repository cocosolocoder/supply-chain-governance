import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard.cli import main


def osv_record(identifier, package="lib", severity=None, **affected):
    entry = {"package": {"ecosystem": "PyPI", "name": package}}
    entry.update(affected)
    record = {"id": identifier, "affected": [entry]}
    if severity is not None:
        record["database_specific"] = {"severity": severity}
    return record


class ExemptionFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()
        # api: app -> web -> lib ; lib is directly hit (manual + OSV).
        for name in ("app", "web", "lib"):
            self.catalog.add_component("api", "pypi", name, "1.0.0")
        self.catalog.add_component("worker", "pypi", "lib", "1.0.0")
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "web", "1.0.0"
        )
        self.catalog.add_dependency(
            "api", "pypi", "web", "1.0.0", "api", "pypi", "lib", "1.0.0"
        )
        self.catalog.add_vulnerability("CVE-MAN", "lib", "high")
        self.catalog.import_osv(
            "nvd",
            [osv_record("CVE-OSV", package="lib", severity="low",
                        versions=["1.0.0"])],
        )
        self.future = "2030-01-01T00:00:00+00:00"

    def tearDown(self) -> None:
        self.catalog.close()

    def request(self, request_id="REQ-1", **overrides):
        values = dict(
            request_id=request_id,
            service="api",
            ecosystem="pypi",
            name="lib",
            version="1.0.0",
            vulnerability="CVE-MAN",
            matched_name="lib",
            source=None,
            applicant="alice",
            reason="mitigated",
            expires_at=self.future,
        )
        values.update(overrides)
        return self.catalog.request_exemption(**values)


class RequestValidationTests(ExemptionFixture):
    def test_request_for_live_impact_is_stored_pending(self) -> None:
        record = self.request()
        self.assertEqual(record["status"], "pending")
        self.assertEqual(record["scope"]["source"], None)
        self.assertEqual(record["events"][0]["action"], "request")
        self.assertEqual(record["events"][0]["from_status"], None)
        self.assertEqual(record["events"][0]["to_status"], "pending")
        self.assertEqual(record["events"][0]["actor"], "alice")

    def test_named_osv_source_identified(self) -> None:
        record = self.request(
            "REQ-OSV", vulnerability="CVE-OSV", source="nvd"
        )
        self.assertEqual(record["scope"]["source"], "nvd")
        self.assertEqual(record["status"], "pending")

    def test_target_must_exist(self) -> None:
        with self.assertRaises(ValueError):
            self.request(name="ghost")
        with self.assertRaises(ValueError):
            self.request(service="billing")
        # Another component of the same service is a different version scope.
        with self.assertRaises(ValueError):
            self.request(version="2.0.0")
        with self.assertRaises(ValueError):
            self.request(vulnerability="CVE-NOPE")
        with self.assertRaises(ValueError):
            self.request(matched_name="other")
        # A different source is a different scope that does not exist.
        with self.assertRaises(ValueError):
            self.request(source="other-source")
        # The OSV record is not the manual one and vice versa.
        with self.assertRaises(ValueError):
            self.request(vulnerability="CVE-MAN", source="nvd")
        with self.assertRaises(ValueError):
            self.request(vulnerability="CVE-OSV")
        # No request row is left behind.
        self.assertEqual(self.catalog.list_exemptions(), [])

    def test_empty_fields_rejected(self) -> None:
        for field, value in [
            ("request_id", " "),
            ("service", " "),
            ("ecosystem", " "),
            ("name", " "),
            ("version", " "),
            ("vulnerability", " "),
            ("matched_name", " "),
            ("applicant", " "),
            ("reason", " "),
        ]:
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    self.request(**{field: value})

    def test_expiry_rules(self) -> None:
        with self.assertRaises(ValueError):
            self.request(expires_at="not-a-time")
        with self.assertRaises(ValueError):
            # Naive timestamp has no timezone.
            self.request(expires_at="2030-01-01T00:00:00")
        submitted = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with self.assertRaises(ValueError):
            self.request(
                expires_at="2026-01-01T00:00:00+00:00",
                submitted_at=submitted,
            )
        with self.assertRaises(ValueError):
            self.request(
                expires_at="2025-12-31T23:59:59+00:00",
                submitted_at=submitted,
            )
        # Exactly one instant later is accepted.
        record = self.request(
            expires_at="2026-01-01T00:00:01+00:00",
            submitted_at=submitted,
        )
        self.assertEqual(record["status"], "pending")

    def test_idempotent_retry_returns_original(self) -> None:
        first = self.request()
        second = self.request()
        self.assertEqual(first, second)
        rows = self.catalog.connection.execute(
            "SELECT COUNT(*) FROM exemption_requests"
        ).fetchone()[0]
        events = self.catalog.connection.execute(
            "SELECT COUNT(*) FROM exemption_events"
        ).fetchone()[0]
        self.assertEqual(rows, 1)
        self.assertEqual(events, 1)

    def test_identical_retry_after_expiry_confirms_original(self) -> None:
        submitted = datetime(2026, 1, 1, tzinfo=timezone.utc)
        expiry = "2026-02-01T00:00:00+00:00"
        first = self.request(expires_at=expiry, submitted_at=submitted)
        # The retry arrives at and then after the expiry instant: the original
        # successful submission is still confirmed, never rejected for being
        # late.
        for retry_at in (
            datetime(2026, 2, 1, tzinfo=timezone.utc),
            datetime(2026, 3, 1, tzinfo=timezone.utc),
        ):
            with self.subTest(retry_at=retry_at):
                again = self.request(
                    expires_at=expiry, submitted_at=retry_at
                )
                self.assertEqual(again, first)
                self.assertEqual(again["status"], "pending")
                self.assertEqual(again["expires_at"], first["expires_at"])
        rows = self.catalog.connection.execute(
            "SELECT COUNT(*) FROM exemption_requests"
        ).fetchone()[0]
        events = self.catalog.connection.execute(
            "SELECT COUNT(*) FROM exemption_events"
        ).fetchone()[0]
        self.assertEqual(rows, 1)
        self.assertEqual(events, 1)

    def test_identical_retry_accepts_equivalent_timezone_offset(self) -> None:
        self.request(expires_at="2030-02-01T00:00:00+00:00")
        again = self.request(expires_at="2030-02-01T08:00:00+08:00")
        self.assertEqual(again["expires_at"], "2030-02-01T00:00:00.000000Z")
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM exemption_events"
            ).fetchone()[0],
            1,
        )

    def test_retry_keeps_whitespace_handling(self) -> None:
        # Content equality follows the same stripping as a first submission.
        self.request(reason="  mitigated  ")
        again = self.request(reason="mitigated")
        self.assertEqual(again["reason"], "mitigated")

    def test_retry_returns_current_state_and_full_history(self) -> None:
        submitted = datetime(2026, 1, 1, tzinfo=timezone.utc)
        expiry = "2026-06-01T00:00:00+00:00"
        retry_at = datetime(2027, 1, 1, tzinfo=timezone.utc)

        # Approved (possibly since expired): state, approval info and history
        # come back as stored; the term is not extended.
        self.request("REQ-OK", expires_at=expiry, submitted_at=submitted)
        self.catalog.approve_exemption(
            "REQ-OK", "bob", "ok",
            decided_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        approved = self.request(
            "REQ-OK", expires_at=expiry, submitted_at=retry_at
        )
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["approver"], "bob")
        self.assertEqual(approved["approved_severity"], "high")
        self.assertEqual(approved["expires_at"], "2026-06-01T00:00:00.000000Z")
        self.assertEqual(
            [event["action"] for event in approved["events"]],
            ["request", "approve"],
        )

        # Rejected.
        self.request("REQ-NO", name="app", matched_name="lib",
                     expires_at=expiry, submitted_at=submitted)
        self.catalog.reject_exemption(
            "REQ-NO", "bob", "no",
            decided_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        rejected = self.request(
            "REQ-NO", name="app", matched_name="lib",
            expires_at=expiry, submitted_at=retry_at,
        )
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(len(rejected["events"]), 2)

        # Revoked.
        self.request("REQ-RV", name="web", matched_name="lib",
                     expires_at=expiry, submitted_at=submitted)
        self.catalog.approve_exemption(
            "REQ-RV", "bob", "ok", decided_at=submitted
        )
        self.catalog.revoke_exemption(
            "REQ-RV", "carol", "back",
            revoked_at=datetime(2026, 1, 3, tzinfo=timezone.utc),
        )
        revoked = self.request(
            "REQ-RV", name="web", matched_name="lib",
            expires_at=expiry, submitted_at=retry_at,
        )
        self.assertEqual(revoked["status"], "revoked")
        self.assertEqual(
            [event["action"] for event in revoked["events"]],
            ["request", "approve", "revoke"],
        )

    def test_late_retry_does_not_recheck_target_or_risk_level(self) -> None:
        submitted = datetime(2026, 1, 1, tzinfo=timezone.utc)
        expiry = "2026-06-01T00:00:00+00:00"
        retry_at = datetime(2027, 1, 1, tzinfo=timezone.utc)
        self.request(
            "REQ-OSV", vulnerability="CVE-OSV", source="nvd",
            expires_at=expiry, submitted_at=submitted,
        )
        self.catalog.approve_exemption(
            "REQ-OSV", "bob", "ok",
            decided_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        # The current rating rises above the approved level and the source is
        # then withdrawn: neither re-check runs on an id confirmation.
        self.catalog.import_osv(
            "nvd",
            [osv_record("CVE-OSV", package="lib", severity="critical",
                        versions=["1.0.0"])],
        )
        self.catalog.import_osv("nvd", [])
        again = self.request(
            "REQ-OSV", vulnerability="CVE-OSV", source="nvd",
            expires_at=expiry, submitted_at=retry_at,
        )
        self.assertEqual(again["status"], "approved")
        self.assertEqual(again["approved_severity"], "low")
        self.assertEqual(len(again["events"]), 2)

    def test_conflict_after_expiry_keeps_original(self) -> None:
        submitted = datetime(2026, 1, 1, tzinfo=timezone.utc)
        expiry = "2026-02-01T00:00:00+00:00"
        retry_at = datetime(2026, 3, 1, tzinfo=timezone.utc)
        self.request(expires_at=expiry, submitted_at=submitted)
        for overrides in (
            {"reason": "changed"},
            {"applicant": "bob"},
            {"expires_at": "2026-03-01T00:00:00+00:00"},
            {"name": "web"},
            {"matched_name": "libx"},
            {"vulnerability": "CVE-OSV", "source": "nvd"},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError):
                    self.request(submitted_at=retry_at, **overrides)
        record = self.catalog.get_exemption("REQ-1")
        self.assertEqual(record["reason"], "mitigated")
        self.assertEqual(record["applicant"], "alice")
        self.assertEqual(record["expires_at"], "2026-02-01T00:00:00.000000Z")
        self.assertEqual(len(record["events"]), 1)

    def test_manual_and_named_source_remain_distinct_on_confirm(self) -> None:
        submitted = datetime(2026, 1, 1, tzinfo=timezone.utc)
        expiry = "2026-02-01T00:00:00+00:00"
        self.request(expires_at=expiry, submitted_at=submitted)
        with self.assertRaises(ValueError):
            # A named source where the stored request had none is different
            # content — even though that target scope does not currently exist.
            self.request(
                source="nvd",
                expires_at=expiry,
                submitted_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
            )
        self.assertIsNone(
            self.catalog.get_exemption("REQ-1")["scope"]["source"]
        )

    def test_old_id_confirm_coexists_with_reused_scope(self) -> None:
        submitted = datetime(2026, 1, 1, tzinfo=timezone.utc)
        expiry = "2026-02-01T00:00:00+00:00"
        self.request(expires_at=expiry, submitted_at=submitted)
        # The expired request releases the scope; a new, legal request takes
        # it over.
        later = self.request(
            "REQ-2", expires_at="2030-01-01T00:00:00+00:00",
            submitted_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
        )
        self.assertEqual(later["status"], "pending")
        # Confirming the old id neither re-occupies the scope nor collides:
        # both records survive unchanged.
        again = self.request(
            expires_at=expiry,
            submitted_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
        )
        self.assertEqual(again["id"], "REQ-1")
        self.assertEqual(len(again["events"]), 1)
        ids = [
            row["id"]
            for row in self.catalog.connection.execute(
                "SELECT id FROM exemption_requests ORDER BY id"
            )
        ]
        self.assertEqual(ids, ["REQ-1", "REQ-2"])
        # The live request still blocks any other brand-new id.
        with self.assertRaises(ValueError):
            self.request(
                "REQ-3", expires_at="2031-01-01T00:00:00+00:00",
            )

    def test_fresh_id_rules_apply_only_to_new_ids(self) -> None:
        # An unparseable or naive expiry is rejected even for an existing id,
        # because parsing happens before the id is looked up.
        self.request()
        with self.assertRaises(ValueError):
            self.request(expires_at="not-a-time")
        with self.assertRaises(ValueError):
            self.request(expires_at="2030-01-01T00:00:00")
        # A genuinely new id keeps all first-submission requirements.
        with self.assertRaises(ValueError):
            self.request(
                "NEW", name="ghost",
                expires_at="2030-01-01T00:00:00+00:00",
            )
        with self.assertRaises(ValueError):
            self.request(
                "NEW",
                expires_at="2026-01-01T00:00:00+00:00",
                submitted_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
            )


        self.request()
        with self.assertRaises(ValueError):
            self.request(reason="changed reason")
        with self.assertRaises(ValueError):
            self.request(name="web")
        # Original record and its single event survive.
        record = self.catalog.get_exemption("REQ-1")
        self.assertEqual(record["reason"], "mitigated")
        self.assertEqual(len(record["events"]), 1)

    def test_one_live_request_per_scope(self) -> None:
        self.request()
        with self.assertRaises(ValueError):
            self.request(request_id="REQ-2")
        # A rejected request frees the scope.
        self.catalog.reject_exemption("REQ-1", "bob", "no")
        self.request(request_id="REQ-2")

    def test_distinct_scopes_are_independent(self) -> None:
        self.request()  # api lib manual
        self.request("REQ-W", name="web", vulnerability="CVE-MAN",
                     matched_name="lib")
        self.request("REQ-SVC", service="worker")
        self.request("REQ-OSV", vulnerability="CVE-OSV", source="nvd")
        self.assertEqual(len(self.catalog.list_exemptions()), 4)
        # Approving the direct hit does not exempt dependent components.
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        report = self.catalog.risk_report()
        by = {
            (i["component"]["service"], i["component"]["name"],
             i["vulnerability"], i["source"]): i
            for i in report["impacts"]
        }
        self.assertTrue(by[("api", "lib", "CVE-MAN", None)]["exempted"])
        self.assertFalse(by[("api", "web", "CVE-MAN", None)]["exempted"])
        self.assertFalse(by[("api", "app", "CVE-MAN", None)]["exempted"])


class ScopeIdentityRuleTests(ExemptionFixture):
    """One maintained rule for which impact record a request targets.

    These pin the shared scope rule: component identity is verbatim (PEP 503
    normalization belongs to OSV package matching only), the pinned matched
    package name is exact, and a manual source, two named OSV sources never
    merge even when id and package agree.
    """

    def test_component_case_is_never_normalized_into_scope(self) -> None:
        # The registered component is lowercase lib; a differently cased name
        # must not widen onto the same impact record.
        for target_name, matched, source in (
            ("LIB", "lib", None),
            ("LIB", "lib", "nvd"),
            ("Lib", "lib", None),
        ):
            with self.subTest(target=target_name, source=source):
                with self.assertRaises(ValueError):
                    self.request(
                        f"REQ-{target_name}-{source}",
                        name=target_name,
                        vulnerability=(
                            "CVE-OSV" if source else "CVE-MAN"
                        ),
                        matched_name=matched,
                        source=source,
                    )
        self.assertEqual(self.catalog.list_exemptions(), [])

    def test_similar_package_spellings_are_distinct_scopes(self) -> None:
        # PEP 503-equivalent spellings only describe OSV matching; the pinned
        # matched package must equal the record's matched_name exactly.
        with self.assertRaises(ValueError):
            self.request(
                "REQ-1", vulnerability="CVE-OSV", source="nvd",
                matched_name="LIB",
            )
        # ... while the exact normalized value does work.
        record = self.request(
            "REQ-2", vulnerability="CVE-OSV", source="nvd",
            matched_name="lib",
        )
        self.assertEqual(record["scope"]["matched_name"], "lib")

    def test_version_spelling_does_not_widen_scope(self) -> None:
        with self.assertRaises(ValueError):
            self.request(
                "REQ-1", vulnerability="CVE-OSV", source="nvd",
                version="1.0",
            )
        with self.assertRaises(ValueError):
            self.request(version="1.0.0+local")
        self.assertEqual(self.catalog.list_exemptions(), [])

    def test_same_id_and_package_keeps_three_independent_scopes(self) -> None:
        # nvd and ghsa carry the same id and package, and a manual entry also
        # shares the id; each must exist, block occupation and approve on its
        # own, and none may be borrowed as another scope's approval basis.
        self.catalog.import_osv(
            "ghsa",
            [osv_record("CVE-OSV", package="lib", severity="medium",
                        versions=["1.0.0"])],
        )
        self.catalog.add_vulnerability("CVE-OSV", "lib", "critical")

        self.request("REQ-NVD", vulnerability="CVE-OSV", source="nvd")
        self.request("REQ-GHSA", vulnerability="CVE-OSV", source="ghsa")
        self.request("REQ-MAN", vulnerability="CVE-OSV", matched_name="lib")
        self.assertEqual(len(self.catalog.list_exemptions()), 3)

        # Withdrawing nvd kills only the nvd target; ghsa and the manual
        # record keep their own scopes approvable.
        self.catalog.import_osv("nvd", [])
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("REQ-NVD", "bob", "gone")
        self.assertEqual(
            self.catalog.approve_exemption(
                "REQ-GHSA", "bob", "ok"
            )["approved_severity"],
            "medium",
        )
        self.assertEqual(
            self.catalog.approve_exemption(
                "REQ-MAN", "bob", "ok"
            )["approved_severity"],
            "critical",
        )
        pending = self.catalog.get_exemption("REQ-NVD")
        self.assertEqual(pending["status"], "pending")
        self.assertEqual(len(pending["events"]), 1)

    def test_provided_blank_source_never_becomes_manual(self) -> None:
        with self.assertRaises(ValueError):
            self.request("REQ-1", source="   ")
        self.assertEqual(self.catalog.list_exemptions(), [])


class ServiceScopedValidationTests(ExemptionFixture):
    """Other services' unparseable versions must not block this service.

    worker's same-named ``lib`` gets a version PEP 440 cannot parse; the
    imported CVE-OSV record matches the normalized package name, so every
    directory-wide impact computation has to compare it and fails. Exemption
    submission and approval for api must still succeed, while anything that
    genuinely needs a comparison inside api remains a hard error.
    """

    def setUp(self) -> None:
        super().setUp()
        self.catalog.add_component("worker", "pypi", "lib", "not-a-version")

    def assert_directory_wide_queries_still_fail(self) -> None:
        # The directory-wide behavior is unchanged: the bad version is a
        # query error for the whole catalog.
        with self.assertRaises(ValueError):
            self.catalog.impact()
        with self.assertRaises(ValueError):
            self.catalog.risk_report()
        with self.assertRaises(ValueError):
            self.catalog.summary()

    def test_request_manual_direct_hit_succeeds(self) -> None:
        record = self.request()
        self.assertEqual(record["status"], "pending")
        self.assertEqual(record["scope"]["source"], None)
        self.assertEqual(len(record["events"]), 1)
        self.assert_directory_wide_queries_still_fail()

    def test_request_osv_direct_hit_succeeds(self) -> None:
        record = self.request(
            "REQ-OSV", vulnerability="CVE-OSV", source="nvd"
        )
        self.assertEqual(record["status"], "pending")
        self.assertEqual(record["scope"]["source"], "nvd")

    def test_request_for_transitive_upstream_uses_full_dependency_graph(self) -> None:
        # app only exists because it depends, transitively, on lib: the
        # service-scoped graph keeps the complete dependency chain.
        for vulnerability, source in (
            ("CVE-MAN", None),
            ("CVE-OSV", "nvd"),
        ):
            with self.subTest(vulnerability=vulnerability):
                record = self.request(
                    f"REQ-{vulnerability}",
                    name="app",
                    vulnerability=vulnerability,
                    matched_name="lib",
                    source=source,
                )
                self.assertEqual(record["status"], "pending")
                self.assertEqual(record["scope"]["name"], "app")

    def test_request_for_missing_target_leaves_no_record(self) -> None:
        with self.assertRaises(ValueError):
            self.request(name="ghost")
        with self.assertRaises(ValueError):
            self.request(vulnerability="CVE-NOPE")
        # A different OSV source is a scope that does not exist in api.
        with self.assertRaises(ValueError):
            self.request(source="other-source")
        self.assertEqual(self.catalog.list_exemptions(), [])

    def test_unparseable_version_inside_target_service_blocks_request(self) -> None:
        # A second lib version inside api itself has to be compared with the
        # imported OSV record: the request must fail and name the component's
        # full identity, never silently skip it.
        self.catalog.add_component("api", "pypi", "lib", "not-a-version")
        with self.assertRaises(ValueError) as context:
            self.request()
        message = str(context.exception)
        self.assertIn("api/pypi/lib/not-a-version", message)
        self.assertEqual(self.catalog.list_exemptions(), [])

    def test_unrelated_bad_version_inside_service_still_blocks(self) -> None:
        # Even a different package: as long as an OSV record matches its name
        # and the version cannot be compared, existence cannot be decided.
        self.catalog.import_osv(
            "other",
            [osv_record("CVE-OTHER", package="brokenpkg", severity="low",
                        versions=["1.0.0"])],
        )
        self.catalog.add_component(
            "api", "pypi", "brokenpkg", "not-a-version"
        )
        with self.assertRaises(ValueError) as context:
            self.request()
        self.assertIn("api/pypi/brokenpkg/not-a-version", str(context.exception))

    def test_approve_succeeds_and_records_current_severity(self) -> None:
        self.request()
        record = self.catalog.approve_exemption("REQ-1", "bob", "ok")
        self.assertEqual(record["status"], "approved")
        self.assertEqual(record["approved_severity"], "high")
        self.assertEqual(
            [event["action"] for event in record["events"]],
            ["request", "approve"],
        )
        # The OSV request records the OSV severity in force at approval.
        self.request("REQ-OSV", vulnerability="CVE-OSV", source="nvd")
        osv = self.catalog.approve_exemption("REQ-OSV", "carol", "ok")
        self.assertEqual(osv["approved_severity"], "low")

    def test_approve_failure_keeps_pending_state_and_history(self) -> None:
        # The impact disappears after submission; the other service's bad
        # version must neither mask the disappearance nor block the error.
        self.request("REQ-OSV", vulnerability="CVE-OSV", source="nvd")
        self.catalog.import_osv("nvd", [])
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("REQ-OSV", "bob", "gone")
        record = self.catalog.get_exemption("REQ-OSV")
        self.assertEqual(record["status"], "pending")
        self.assertIsNone(record["approved_severity"])
        self.assertEqual(len(record["events"]), 1)

    def test_bad_version_new_in_target_service_blocks_approval(self) -> None:
        self.request()
        self.catalog.add_component("api", "pypi", "lib", "not-a-version")
        with self.assertRaises(ValueError) as context:
            self.catalog.approve_exemption("REQ-1", "bob", "ok")
        self.assertIn("api/pypi/lib/not-a-version", str(context.exception))
        record = self.catalog.get_exemption("REQ-1")
        self.assertEqual(record["status"], "pending")
        self.assertEqual(len(record["events"]), 1)

    def test_service_report_exemption_stays_scoped_with_bad_version(self) -> None:
        self.request()
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        report = self.catalog.risk_report(service="api")
        manual = next(
            entry for entry in report["impacts"]
            if entry["component"]["name"] == "lib"
            and entry["vulnerability"] == "CVE-MAN"
        )
        self.assertTrue(manual["exempted"])
        self.assertEqual(manual["exemption_request"], "REQ-1")
        # worker's same-name component is untouched (its report cannot even
        # build while its version is unparseable).
        with self.assertRaises(ValueError):
            self.catalog.risk_report(service="worker")


class DecisionTests(ExemptionFixture):
    def test_approve_records_severity_and_history(self) -> None:
        self.request()
        record = self.catalog.approve_exemption("REQ-1", "bob", "agreed")
        self.assertEqual(record["status"], "approved")
        self.assertEqual(record["approver"], "bob")
        self.assertEqual(record["decision_note"], "agreed")
        self.assertEqual(record["approved_severity"], "high")
        self.assertEqual([e["action"] for e in record["events"]],
                         ["request", "approve"])
        decision = record["events"][1]
        self.assertEqual(decision["from_status"], "pending")
        self.assertEqual(decision["to_status"], "approved")
        self.assertEqual(decision["actor"], "bob")
        self.assertEqual(decision["reason"], "agreed")
        self.assertIsNotNone(decision["at"])

    def test_reject_terminal(self) -> None:
        self.request()
        record = self.catalog.reject_exemption("REQ-1", "bob", "no way")
        self.assertEqual(record["status"], "rejected")
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("REQ-1", "bob", "late")
        with self.assertRaises(ValueError):
            self.catalog.reject_exemption("REQ-1", "bob", "again")
        with self.assertRaises(ValueError):
            self.catalog.revoke_exemption("REQ-1", "bob", "x")

    def test_only_pending_can_be_decided(self) -> None:
        self.request()
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("REQ-1", "carol", "again")
        with self.assertRaises(ValueError):
            self.catalog.reject_exemption("REQ-1", "carol", "again")

    def test_applicant_cannot_self_approve(self) -> None:
        self.request()
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("REQ-1", "alice", "self")
        # Still pending.
        self.assertEqual(self.catalog.get_exemption("REQ-1")["status"], "pending")
        # Self-rejection is allowed (not an approval conflict), different scope.
        self.request("REQ-2", name="web", matched_name="lib")
        self.catalog.reject_exemption("REQ-2", "alice", "withdraw")

    def test_empty_handler_and_note_rejected(self) -> None:
        self.request()
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("REQ-1", " ", "ok")
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("REQ-1", "bob", "  ")

    def test_unknown_id_errors(self) -> None:
        for operation in (
            self.catalog.approve_exemption,
            self.catalog.reject_exemption,
            self.catalog.revoke_exemption,
        ):
            with self.subTest(operation=operation.__name__):
                with self.assertRaises(ValueError):
                    operation("NOPE", "bob", "note")

    def test_decision_after_expiry_rejected_and_kept(self) -> None:
        submitted = datetime(2026, 1, 1, tzinfo=timezone.utc)
        expiry = "2026-02-01T00:00:00+00:00"
        self.request(expires_at=expiry, submitted_at=submitted)
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption(
                "REQ-1", "bob", "late",
                decided_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
            )
        record = self.catalog.get_exemption("REQ-1")
        self.assertEqual(record["status"], "pending")
        self.assertEqual(len(record["events"]), 1)
        # Just before expiry is accepted.
        self.catalog.approve_exemption(
            "REQ-1", "bob", "in time",
            decided_at=datetime(2026, 1, 31, 23, 59, 59, tzinfo=timezone.utc),
        )

    def test_approve_requires_target_to_still_exist(self) -> None:
        self.request()
        # Remove the dependency-free manual hit by clearing the vuln via a
        # fresh identical observation is not possible; instead withdraw impact
        # by deleting the component through catalog replacement. Simulate
        # disappearance with OSV source withdrawal on an OSV-scoped request.
        self.request("REQ-OSV", vulnerability="CVE-OSV", source="nvd")
        self.catalog.import_osv("nvd", [])
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("REQ-OSV", "bob", "gone")
        self.assertEqual(
            self.catalog.get_exemption("REQ-OSV")["status"], "pending"
        )

    def test_revoke_rules(self) -> None:
        self.request()
        with self.assertRaises(ValueError):
            self.catalog.revoke_exemption("REQ-1", "bob", "too soon")
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        with self.assertRaises(ValueError):
            self.catalog.revoke_exemption("REQ-1", " ", "x")
        with self.assertRaises(ValueError):
            self.catalog.revoke_exemption("REQ-1", "bob", " ")
        record = self.catalog.revoke_exemption("REQ-1", "carol", "rollback")
        self.assertEqual(record["status"], "revoked")
        self.assertEqual(record["revoker"], "carol")
        actions = [e["action"] for e in record["events"]]
        self.assertEqual(actions, ["request", "approve", "revoke"])
        with self.assertRaises(ValueError):
            self.catalog.revoke_exemption("REQ-1", "carol", "again")
        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("REQ-1", "carol", "reopen")

    def test_cannot_revoke_after_expiry_instant(self) -> None:
        submitted = datetime(2026, 1, 1, tzinfo=timezone.utc)
        expiry = "2026-02-01T00:00:00+00:00"
        self.request(expires_at=expiry, submitted_at=submitted)
        self.catalog.approve_exemption(
            "REQ-1", "bob", "ok",
            decided_at=submitted,
        )
        with self.assertRaises(ValueError):
            self.catalog.revoke_exemption(
                "REQ-1", "bob", "late",
                revoked_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
            )

    def test_revoking_frees_scope_for_new_request(self) -> None:
        self.request()
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        with self.assertRaises(ValueError):
            self.request(request_id="REQ-2")
        self.catalog.revoke_exemption("REQ-1", "bob", "reconsider")
        self.request(request_id="REQ-2")


class SeverityEscalationTests(ExemptionFixture):
    def test_exemption_stops_when_severity_outgrows_approval(self) -> None:
        self.request()
        self.catalog.approve_exemption("REQ-1", "bob", "ok")  # approved: high
        report = self.catalog.risk_report(service="api")
        (lib,) = [i for i in report["impacts"]
                  if i["component"]["name"] == "lib"
                  and i["vulnerability"] == "CVE-MAN"]
        self.assertTrue(lib["exempted"])

        # Raise the manual observation to critical.
        self.catalog.add_vulnerability("CVE-MAN", "lib", "critical")
        report = self.catalog.risk_report(service="api")
        (lib,) = [i for i in report["impacts"]
                  if i["component"]["name"] == "lib"
                  and i["vulnerability"] == "CVE-MAN"]
        self.assertFalse(lib["exempted"])
        self.assertEqual(lib["exemption_request"], "REQ-1")
        self.assertIn("超出审批范围", lib["not_exempt_reason"])

        # Equal rank still covered; a lower rank stays covered.
        self.catalog.add_vulnerability("CVE-MAN", "lib", "high")
        self.assertTrue(
            next(i for i in self.catalog.risk_report(service="api")["impacts"]
                 if i["component"]["name"] == "lib"
                 and i["vulnerability"] == "CVE-MAN")["exempted"]
        )


class ApprovalReconfirmationRegressionTests(ExemptionFixture):
    """Approve must judge the impact as it exists at approval time.

    Between submission and approval the named OSV source may have been fully
    re-imported. The approval therefore can neither keep the severity the
    record carried when the request was filed, nor borrow a same-id record
    from another source (or from manual registration) as its basis. These
    tests replace the whole ``nvd`` source while one unexpired request is
    pending and then drive the approval.
    """

    def replace_nvd(self, severity="high", fixed="2.0.0"):
        """Re-import the named source with one range record on lib.

        ``fixed='2.0.0'`` still affects lib/app/web at 1.0.0; ``fixed='1.0.0'``
        removes the hit on 1.0.0 altogether (the range ends before it).
        """
        self.catalog.import_osv(
            "nvd",
            [osv_record(
                "CVE-OSV", package="lib", severity=severity,
                ranges=[{
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": fixed},
                    ],
                }],
            )],
        )

    def add_same_id_records_elsewhere(self):
        # Another imported source and a manual observation share the id and
        # package name but carry their own severity; neither belongs to the
        # nvd scope of the pending request.
        self.catalog.import_osv(
            "ghsa",
            [osv_record("CVE-OSV", package="lib", severity="medium",
                        versions=["1.0.0"])],
        )
        self.catalog.add_vulnerability("CVE-OSV", "lib", "critical")

    def entry(self, report, name, source, vulnerability="CVE-OSV",
              service="api"):
        matches = [
            i for i in report["impacts"]
            if i["component"]["service"] == service
            and i["component"]["name"] == name
            and i["vulnerability"] == vulnerability
            and i["source"] == source
        ]
        self.assertEqual(
            len(matches), 1,
            f"expected exactly one {name}/{vulnerability}/source={source} record",
        )
        return matches[0]

    def request_nvd(self, name="lib"):
        return self.request(
            "REQ-OSV", name=name, vulnerability="CVE-OSV", source="nvd"
        )

    def assert_still_pristine_pending(self):
        record = self.catalog.get_exemption("REQ-OSV")
        self.assertEqual(record["status"], "pending")
        self.assertIsNone(record["approved_severity"])
        self.assertIsNone(record["approver"])
        self.assertIsNone(record["decided_at"])
        self.assertIsNone(record["decision_note"])
        self.assertEqual(
            [event["action"] for event in record["events"]], ["request"]
        )
        return record

    def test_direct_hit_approval_records_replaced_sources_high_level(self) -> None:
        self.request_nvd()
        # At submission the nvd record is the fixture's low one.
        before = self.entry(
            self.catalog.risk_report(service="api"), "lib", "nvd"
        )
        self.assertEqual(before["severity"], "low")

        # Re-import the whole source: same id and package, still hitting 1.0.0,
        # but upgraded to high. The import only swaps vulnerability data and
        # must not append any request-processing event.
        self.replace_nvd(severity="high", fixed="2.0.0")
        pending = self.catalog.get_exemption("REQ-OSV")
        self.assertEqual(pending["status"], "pending")
        self.assertEqual(
            [event["action"] for event in pending["events"]], ["request"]
        )

        approved = self.catalog.approve_exemption(
            "REQ-OSV", "bob", "controls verified"
        )
        # The saved level is the current high, never the submission-time low.
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["approved_severity"], "high")

        # Component identity, source, applicant, reason and term are untouched.
        scope = approved["scope"]
        self.assertEqual(
            (scope["service"], scope["ecosystem"], scope["name"],
             scope["version"], scope["vulnerability"],
             scope["matched_name"], scope["source"]),
            ("api", "pypi", "lib", "1.0.0", "CVE-OSV", "lib", "nvd"),
        )
        self.assertEqual(approved["applicant"], "alice")
        self.assertEqual(approved["reason"], "mitigated")
        self.assertEqual(
            approved["expires_at"], "2030-01-01T00:00:00.000000Z"
        )
        self.assertEqual(approved["approver"], "bob")
        self.assertEqual(
            [event["action"] for event in approved["events"]],
            ["request", "approve"],
        )
        decision = approved["events"][1]
        self.assertEqual(decision["actor"], "bob")
        self.assertEqual(decision["reason"], "controls verified")
        self.assertEqual(decision["from_status"], "pending")
        self.assertEqual(decision["to_status"], "approved")

        # The report marks the current nvd impact exempted under that request.
        report = self.catalog.risk_report(service="api")
        hit = self.entry(report, "lib", "nvd")
        self.assertEqual(hit["severity"], "high")
        self.assertTrue(hit["exempted"])
        self.assertEqual(hit["exemption_request"], "REQ-OSV")
        self.assertTrue(hit["direct"])
        self.assertEqual(hit["matched_conditions"], ["<2.0.0"])

    def test_same_id_other_source_and_manual_records_are_not_basis_or_exempted(
        self,
    ) -> None:
        self.request_nvd()
        self.replace_nvd(severity="high", fixed="2.0.0")
        self.add_same_id_records_elsewhere()

        # Only the nvd high level is recorded, despite the medium ghsa record
        # and the critical manual one sharing id and package name.
        approved = self.catalog.approve_exemption("REQ-OSV", "bob", "ok")
        self.assertEqual(approved["approved_severity"], "high")

        report = self.catalog.risk_report(service="api")
        nvd = self.entry(report, "lib", "nvd")
        self.assertTrue(nvd["exempted"])
        self.assertEqual(nvd["exemption_request"], "REQ-OSV")
        # The other-source and manual same-id records keep their own scope:
        # shown with their own severity, neither exempted nor linked.
        ghsa = self.entry(report, "lib", "ghsa")
        self.assertEqual(ghsa["severity"], "medium")
        self.assertFalse(ghsa["exempted"])
        self.assertIsNone(ghsa["exemption_request"])
        manual = self.entry(report, "lib", None)
        self.assertEqual(manual["severity"], "critical")
        self.assertFalse(manual["exempted"])
        self.assertIsNone(manual["exemption_request"])

    def test_indirect_target_reconfirmed_via_current_dependency_path(self) -> None:
        # app itself never matches the vulnerability; it is affected only
        # through app -> web -> lib, so approval must follow the current graph.
        self.request_nvd(name="app")
        self.replace_nvd(severity="high", fixed="2.0.0")
        self.add_same_id_records_elsewhere()

        approved = self.catalog.approve_exemption("REQ-OSV", "bob", "ok")
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["approved_severity"], "high")
        self.assertEqual(approved["scope"]["name"], "app")
        self.assertEqual(
            [event["action"] for event in approved["events"]],
            ["request", "approve"],
        )

        report = self.catalog.risk_report(service="api")
        nvd = self.entry(report, "app", "nvd")
        self.assertTrue(nvd["exempted"])
        self.assertEqual(nvd["exemption_request"], "REQ-OSV")
        self.assertFalse(nvd["direct"])
        self.assertEqual(
            [node["name"] for node in nvd["path"]], ["app", "web", "lib"]
        )
        self.assertEqual(nvd["matched_conditions"], ["<2.0.0"])
        # The same indirect impact reached through other sources stays live.
        ghsa = self.entry(report, "app", "ghsa")
        self.assertFalse(ghsa["direct"])
        self.assertFalse(ghsa["exempted"])
        self.assertIsNone(ghsa["exemption_request"])
        self.assertEqual(
            [node["name"] for node in ghsa["path"]], ["app", "web", "lib"]
        )
        manual = self.entry(report, "app", None)
        self.assertFalse(manual["exempted"])
        self.assertIsNone(manual["exemption_request"])

    def test_direct_approval_fails_when_replaced_source_stops_hitting(self) -> None:
        self.request_nvd()
        # The re-imported nvd range ends at 1.0.0 (exclusive), so lib 1.0.0 is
        # no longer in range; other sources still carry the same id.
        self.replace_nvd(severity="high", fixed="1.0.0")
        self.add_same_id_records_elsewhere()

        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("REQ-OSV", "bob", "ok")
        self.assert_still_pristine_pending()

        report = self.catalog.risk_report(service="api")
        # The nvd record is gone from the report entirely.
        self.assertFalse(
            any(i["source"] == "nvd" for i in report["impacts"])
        )
        # Nothing is marked exempted or linked to the failed approval; the
        # same-id records from other scopes are merely still displayed.
        self.assertFalse(any(i["exempted"] for i in report["impacts"]))
        self.assertFalse(
            any(i["exemption_request"] for i in report["impacts"])
        )
        ghsa = self.entry(report, "lib", "ghsa")
        self.assertEqual(ghsa["severity"], "medium")
        manual = self.entry(report, "lib", None)
        self.assertEqual(manual["severity"], "critical")

    def test_indirect_approval_fails_when_source_path_is_gone(self) -> None:
        # app is only affected through the nvd-hit lib; once nvd no longer hits
        # lib, a same-id hit imported from ghsa must not keep the nvd approval
        # alive.
        self.request_nvd(name="app")
        self.replace_nvd(severity="high", fixed="1.0.0")
        self.catalog.import_osv(
            "ghsa",
            [osv_record("CVE-OSV", package="lib", severity="medium",
                        versions=["1.0.0"])],
        )

        with self.assertRaises(ValueError):
            self.catalog.approve_exemption("REQ-OSV", "bob", "ok")
        record = self.assert_still_pristine_pending()
        self.assertEqual(record["scope"]["source"], "nvd")
        self.assertEqual(record["scope"]["name"], "app")

        report = self.catalog.risk_report(service="api")
        self.assertFalse(
            any(i["source"] == "nvd" for i in report["impacts"])
        )
        # app is still affected by the same id, but via ghsa and unexempted.
        ghsa = self.entry(report, "app", "ghsa")
        self.assertFalse(ghsa["direct"])
        self.assertFalse(ghsa["exempted"])
        self.assertIsNone(ghsa["exemption_request"])
        self.assertEqual(
            [node["name"] for node in ghsa["path"]], ["app", "web", "lib"]
        )
        self.assertFalse(any(i["exempted"] for i in report["impacts"]))

    def test_report_counts_follow_actual_unexempted_impacts(self) -> None:
        # Minimal directory: one component carrying three same-id records
        # (nvd, ghsa, manual). Several unexempted records on one component
        # still count as a single unhandled component.
        def catalog_with(nvd_fixed):
            catalog = Catalog()
            catalog.add_component("s", "pypi", "lib", "1.0.0")
            catalog.import_osv(
                "nvd",
                [osv_record("CVE-OSV", package="lib", severity="low",
                            versions=["1.0.0"])],
            )
            catalog.request_exemption(
                "R", "s", "pypi", "lib", "1.0.0",
                "CVE-OSV", "lib", "nvd",
                "alice", "r", "2030-01-01T00:00:00+00:00",
            )
            catalog.import_osv(
                "nvd",
                [osv_record(
                    "CVE-OSV", package="lib", severity="high",
                    ranges=[{
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": nvd_fixed},
                        ],
                    }],
                )],
            )
            catalog.import_osv(
                "ghsa",
                [osv_record("CVE-OSV", package="lib", severity="medium",
                            versions=["1.0.0"])],
            )
            catalog.add_vulnerability("CVE-OSV", "lib", "critical")
            return catalog

        # Success: the nvd high record alone is exempted; the medium/critical
        # records still leave this one component unhandled, highest critical.
        approved = catalog_with("2.0.0")
        self.assertEqual(
            approved.approve_exemption("R", "bob", "ok")["approved_severity"],
            "high",
        )
        report = approved.risk_report()
        self.assertEqual(report["impact_count"], 3)
        self.assertEqual(report["unhandled_component_count"], 1)
        self.assertEqual(report["highest_severity"], "critical")
        approved.close()

        # Failure: nvd dropped out of range, so the record vanishes and the
        # approval is refused; the two remaining records still count once.
        refused = catalog_with("1.0.0")
        with self.assertRaises(ValueError):
            refused.approve_exemption("R", "bob", "ok")
        report = refused.risk_report()
        self.assertEqual(report["impact_count"], 2)
        self.assertEqual(report["unhandled_component_count"], 1)
        self.assertEqual(report["highest_severity"], "critical")
        self.assertFalse(any(i["exempted"] for i in report["impacts"]))
        refused.close()


class RiskReportTests(ExemptionFixture):
    def by(self, report, name, vulnerability="CVE-MAN", source=None,
           service="api"):
        matches = [
            i for i in report["impacts"]
            if i["component"]["name"] == name
            and i["component"]["service"] == service
            and i["vulnerability"] == vulnerability
            and i["source"] == source
        ]
        (match,) = matches
        return match

    def test_report_shape_and_path(self) -> None:
        report = self.catalog.risk_report()
        self.assertEqual(report["highest_severity"], "high")
        self.assertEqual(report["unhandled_component_count"], 4)
        app = self.by(report, "app")
        self.assertFalse(app["direct"])
        self.assertEqual(
            [n["name"] for n in app["path"]], ["app", "web", "lib"]
        )
        lib = self.by(report, "lib")
        self.assertTrue(lib["direct"])
        self.assertEqual([n["name"] for n in lib["path"]], ["lib"])

    def test_exempted_record_excluded_from_counts(self) -> None:
        self.request()
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        report = self.catalog.risk_report()
        # lib's manual record exempted; lib still appears via OSV, and app/web
        # still have the manual record.
        self.assertTrue(self.by(report, "lib", "CVE-MAN")["exempted"])
        self.assertFalse(self.by(report, "lib", "CVE-OSV", "nvd")["exempted"])
        # 4 distinct components still carry at least one unexempted record.
        self.assertEqual(report["unhandled_component_count"], 4)
        # Exempting the OSV low record too does not change the highest (high).
        self.request("REQ-OSV", vulnerability="CVE-OSV", source="nvd")
        self.catalog.approve_exemption("REQ-OSV", "bob", "ok")
        report = self.catalog.risk_report()
        self.assertEqual(report["highest_severity"], "high")

    def test_highest_and_count_null_when_fully_exempted(self) -> None:
        # Single component, single vuln: fully exempted report.
        catalog = Catalog()
        catalog.add_component("s", "pypi", "only", "1.0.0")
        catalog.add_vulnerability("CVE-1", "only", "low")
        catalog.request_exemption(
            "R", "s", "pypi", "only", "1.0.0", "CVE-1", "only", None,
            "a", "r", self.future,
        )
        catalog.approve_exemption("R", "b", "ok")
        report = catalog.risk_report()
        self.assertEqual(report["unhandled_component_count"], 0)
        self.assertIsNone(report["highest_severity"])
        self.assertEqual(report["impact_count"], 1)
        self.assertTrue(report["impacts"][0]["exempted"])
        catalog.close()

    def test_service_filter(self) -> None:
        report = self.catalog.risk_report(service="api")
        self.assertTrue(all(
            i["component"]["service"] == "api" for i in report["impacts"]
        ))
        self.assertEqual(report["service"], "api")
        self.assertEqual(
            self.catalog.risk_report(service="nope")["impact_count"], 0
        )

    def test_other_service_bad_version_does_not_break_service_report(self) -> None:
        # Give worker's same-named lib a version PEP 440 cannot parse. api's
        # report must still build independently; worker queries still fail.
        self.catalog.add_component("worker", "pypi", "lib", "not-a-version")
        report = self.catalog.risk_report(service="api")
        self.assertEqual(report["service"], "api")
        self.assertTrue(all(
            entry["component"]["service"] == "api"
            for entry in report["impacts"]
        ))
        self.assertEqual(
            {entry["component"]["name"] for entry in report["impacts"]},
            {"app", "web", "lib"},
        )
        with self.assertRaises(ValueError):
            self.catalog.risk_report(service="worker")

    def test_service_report_exemption_does_not_cross_services(self) -> None:
        # An exemption on worker's same-name record never exempts api's.
        self.request(
            "REQ-W",
            service="worker",
            vulnerability="CVE-OSV",
            source="nvd",
        )
        self.catalog.approve_exemption("REQ-W", "bob", "ok")
        report = self.catalog.risk_report(service="api")
        api_osv = self.by(report, "lib", "CVE-OSV", "nvd")
        self.assertFalse(api_osv["exempted"])
        self.assertIsNone(api_osv["exemption_request"])
        worker_report = self.catalog.risk_report(service="worker")
        worker_osv = self.by(
            worker_report, "lib", "CVE-OSV", "nvd", service="worker"
        )
        self.assertTrue(worker_osv["exempted"])
        self.assertEqual(worker_osv["exemption_request"], "REQ-W")

    def test_sorting_is_stable(self) -> None:
        at = "2027-01-01T00:00:00+00:00"
        first = self.catalog.risk_report(evaluated_at=at)
        second = self.catalog.risk_report(evaluated_at=at)
        self.assertEqual(first, second)
        keys = [
            (i["component"]["service"], i["component"]["ecosystem"],
             i["component"]["name"], i["component"]["version"],
             i["vulnerability"], i["matched_name"], i["source"] or "")
            for i in first["impacts"]
        ]
        self.assertEqual(keys, sorted(keys))

    def test_evaluated_at_controls_only_the_term(self) -> None:
        expiry = "2030-06-01T00:00:00+00:00"
        self.request(expires_at=expiry)
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        # Before expiry instant: covered.
        before = self.catalog.risk_report(
            evaluated_at="2030-05-31T23:59:59+00:00"
        )
        self.assertTrue(self.by(before, "lib")["exempted"])
        # At/after expiry instant: not covered, reason states expiry.
        at = self.catalog.risk_report(
            evaluated_at="2030-06-01T00:00:00+00:00"
        )
        entry = self.by(at, "lib")
        self.assertFalse(entry["exempted"])
        self.assertEqual(entry["exemption_request"], "REQ-1")
        self.assertIn("到期", entry["not_exempt_reason"])
        # Timezone offset is normalized to the same UTC instant.
        shifted = self.catalog.risk_report(
            evaluated_at="2030-06-01T08:00:00+08:00"
        )
        self.assertFalse(self.by(shifted, "lib")["exempted"])

    def test_pending_link_shown(self) -> None:
        self.request()
        report = self.catalog.risk_report()
        entry = self.by(report, "lib")
        self.assertFalse(entry["exempted"])
        self.assertEqual(entry["exemption_request"], "REQ-1")
        self.assertIn("待审批", entry["not_exempt_reason"])

    def test_disappearance_removes_impact_but_keeps_history(self) -> None:
        self.request("REQ-OSV", vulnerability="CVE-OSV", source="nvd")
        self.catalog.approve_exemption("REQ-OSV", "bob", "ok")
        self.catalog.import_osv("nvd", [])  # withdraw the OSV record
        report = self.catalog.risk_report()
        self.assertFalse(any(
            i["vulnerability"] == "CVE-OSV" for i in report["impacts"]
        ))
        record = self.catalog.get_exemption("REQ-OSV")
        self.assertEqual(record["status"], "approved")
        self.assertEqual(len(record["events"]), 2)

    def test_reappearing_impact_resumes_exemption(self) -> None:
        self.request("REQ-OSV", vulnerability="CVE-OSV", source="nvd")
        self.catalog.approve_exemption("REQ-OSV", "bob", "ok")
        self.catalog.import_osv("nvd", [])
        self.catalog.import_osv(
            "nvd", [osv_record("CVE-OSV", package="lib", severity="low",
                               versions=["1.0.0"])]
        )
        entry = self.by(
            self.catalog.risk_report(), "lib", "CVE-OSV", "nvd"
        )
        self.assertTrue(entry["exempted"])
        self.assertEqual(entry["exemption_request"], "REQ-OSV")

    def test_latest_dependency_path_is_shown(self) -> None:
        # Add a shorter path app -> lib; the request scope (lib direct) is
        # unchanged but dependent records reflect the new path.
        self.request()
        self.catalog.approve_exemption("REQ-1", "bob", "ok")
        self.catalog.add_dependency(
            "api", "pypi", "app", "1.0.0", "api", "pypi", "lib", "1.0.0"
        )
        app = self.by(self.catalog.risk_report(), "app")
        self.assertEqual([n["name"] for n in app["path"]], ["app", "lib"])
        # The request's stored scope is untouched.
        self.assertEqual(
            self.catalog.get_exemption("REQ-1")["scope"]["name"], "lib"
        )


class RequestReadBatchingTests(ExemptionFixture):
    def request_statements_during_report(self, **report_kwargs):
        """Count SELECTs against exemption_requests during one risk report."""
        statements: list[str] = []
        self.catalog.connection.set_trace_callback(
            lambda statement: statements.append(statement)
        )
        self.catalog.risk_report(**report_kwargs)
        return [
            statement for statement in statements
            if "exemption_requests" in statement.lower()
        ]

    def test_request_reads_do_not_grow_with_record_count(self) -> None:
        # Many components depending on the directly hit lib produce many
        # impact records; without any requests the old implementation issued
        # one scope lookup per record. The batch read stays a single query.
        for index in range(8):
            name = f"dependent-{index}"
            self.catalog.add_component("api", "pypi", name, "1.0.0")
            self.catalog.add_dependency(
                "api", "pypi", name, "1.0.0",
                "api", "pypi", "lib", "1.0.0",
            )
        statements = self.request_statements_during_report()
        self.assertEqual(len(statements), 1)

        # A handful of requests for distinct scopes keeps the single read: it
        # loads every request at once instead of looking scopes up one by one.
        self.request("REQ-LIB")
        self.request("REQ-D0", name="dependent-0", matched_name="lib")
        self.request("REQ-D1", name="dependent-1", matched_name="lib")
        statements = self.request_statements_during_report()
        self.assertEqual(len(statements), 1)

    def test_service_report_only_reads_that_service_requests(self) -> None:
        statements = self.request_statements_during_report(service="api")
        self.assertEqual(len(statements), 1)
        self.assertIn("WHERE service =", statements[0])


class NewestRequestSelectionTests(ExemptionFixture):
    def by(self, report, name="lib", vulnerability="CVE-MAN", source=None,
           service="api"):
        matches = [
            i for i in report["impacts"]
            if i["component"]["name"] == name
            and i["component"]["service"] == service
            and i["vulnerability"] == vulnerability
            and i["source"] == source
        ]
        (match,) = matches
        return match

    def test_rejected_then_newer_pending_links_newer(self) -> None:
        self.request("REQ-OLD")
        self.catalog.reject_exemption("REQ-OLD", "bob", "no")
        self.request("REQ-NEW")
        entry = self.by(self.catalog.risk_report())
        self.assertEqual(entry["exemption_request"], "REQ-NEW")
        self.assertIn("待审批", entry["not_exempt_reason"])

    def test_equal_submission_time_prefers_larger_id(self) -> None:
        submitted = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.request("REQ-A", submitted_at=submitted)
        self.catalog.reject_exemption("REQ-A", "bob", "no")
        # The newer request shares the exact submission instant; id order is
        # the documented tie-breaker and must not change under batching.
        self.request("REQ-B", submitted_at=submitted)
        entry = self.by(self.catalog.risk_report())
        self.assertEqual(entry["exemption_request"], "REQ-B")
        self.assertIn("待审批", entry["not_exempt_reason"])

    def test_non_active_reasons_match_statuses(self) -> None:
        # Pending expired.
        self.request(
            "REQ-PENDING",
            expires_at="2026-02-01T00:00:00+00:00",
            submitted_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        entry = self.by(
            self.catalog.risk_report(
                evaluated_at="2026-02-01T00:00:00+00:00"
            ),
        )
        self.assertEqual(entry["exemption_request"], "REQ-PENDING")
        self.assertIn("到期，未获审批", entry["not_exempt_reason"])

        # Rejected.
        self.request("REQ-REJ", name="web", matched_name="lib")
        self.catalog.reject_exemption("REQ-REJ", "bob", "no")
        entry = self.by(self.catalog.risk_report(), name="web")
        self.assertEqual(entry["exemption_request"], "REQ-REJ")
        self.assertIn("已被拒绝", entry["not_exempt_reason"])

        # Revoked.
        self.request("REQ-REV", name="lib")
        self.catalog.approve_exemption("REQ-REV", "bob", "ok")
        self.catalog.revoke_exemption("REQ-REV", "carol", "back")
        entry = self.by(self.catalog.risk_report(), name="lib")
        self.assertEqual(entry["exemption_request"], "REQ-REV")
        self.assertIn("已被撤销", entry["not_exempt_reason"])

    def test_approved_expired_still_linked_with_expiry_reason(self) -> None:
        submitted = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.request(
            "REQ-1", expires_at="2026-06-01T00:00:00+00:00",
            submitted_at=submitted,
        )
        self.catalog.approve_exemption(
            "REQ-1", "bob", "ok",
            decided_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        entry = self.by(
            self.catalog.risk_report(
                evaluated_at="2026-06-01T00:00:00+00:00"
            )
        )
        self.assertFalse(entry["exempted"])
        self.assertEqual(entry["exemption_request"], "REQ-1")
        self.assertIn("到期", entry["not_exempt_reason"])

    def test_scope_identity_stays_exact_under_batch_read(self) -> None:
        # Manual scope request must not link the same-id OSV record; another
        # service's request must not link this service's record.
        self.request("REQ-MAN")
        self.request(
            "REQ-OSV", vulnerability="CVE-OSV", source="nvd",
            service="worker",
        )
        self.catalog.approve_exemption("REQ-OSV", "bob", "ok")
        report = self.catalog.risk_report(service="api")
        manual = self.by(report, name="lib", vulnerability="CVE-MAN")
        osv = self.by(report, name="lib", vulnerability="CVE-OSV",
                      source="nvd")
        self.assertEqual(manual["exemption_request"], "REQ-MAN")
        self.assertIsNone(osv["exemption_request"])

    def test_past_instant_with_two_approvals_uses_later_approval(self) -> None:
        # R1 is approved and lapses; R2 is approved later for the same scope.
        # At a past instant inside R1's term both approvals are "in force" by
        # the term-only rule; the last-registered approval is linked, and once
        # both terms lapse the newest id is linked as expired.
        self.request(
            "REQ-1",
            expires_at="2026-02-01T00:00:00+00:00",
            submitted_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        self.catalog.approve_exemption(
            "REQ-1", "bob", "ok",
            decided_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        self.request(
            "REQ-2",
            expires_at="2026-06-01T00:00:00+00:00",
            submitted_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
        )
        self.catalog.approve_exemption(
            "REQ-2", "carol", "ok",
            decided_at=datetime(2026, 3, 2, tzinfo=timezone.utc),
        )
        inside = self.catalog.risk_report(
            evaluated_at="2026-01-15T00:00:00+00:00"
        )
        entry = self.by(inside)
        self.assertTrue(entry["exempted"])
        self.assertEqual(entry["exemption_request"], "REQ-2")

        after_both = self.catalog.risk_report(
            evaluated_at="2026-07-01T00:00:00+00:00"
        )
        entry = self.by(after_both)
        self.assertFalse(entry["exempted"])
        self.assertEqual(entry["exemption_request"], "REQ-2")
        self.assertIn("到期", entry["not_exempt_reason"])

    def test_revoked_new_request_does_not_shadow_in_force_approval(self) -> None:
        # Newer request approved, then revoked; evaluated inside the older
        # approval's term the record is still exempted via the older approval,
        # even though the newest request of the scope is the revoked one.
        self.request(
            "REQ-1",
            expires_at="2026-02-01T00:00:00+00:00",
            submitted_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        self.catalog.approve_exemption(
            "REQ-1", "bob", "ok",
            decided_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        self.request(
            "REQ-2",
            expires_at="2026-06-01T00:00:00+00:00",
            submitted_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
        )
        self.catalog.approve_exemption(
            "REQ-2", "carol", "ok",
            decided_at=datetime(2026, 3, 2, tzinfo=timezone.utc),
        )
        self.catalog.revoke_exemption(
            "REQ-2", "carol", "back",
            revoked_at=datetime(2026, 3, 3, tzinfo=timezone.utc),
        )
        entry = self.by(
            self.catalog.risk_report(
                evaluated_at="2026-01-15T00:00:00+00:00"
            )
        )
        self.assertTrue(entry["exempted"])
        self.assertEqual(entry["exemption_request"], "REQ-1")
        # Once the older term has lapsed too, the revoked newer request is the
        # linked one with its revocation reason.
        lapsed = self.by(
            self.catalog.risk_report(
                evaluated_at="2026-07-01T00:00:00+00:00"
            )
        )
        self.assertFalse(lapsed["exempted"])
        self.assertEqual(lapsed["exemption_request"], "REQ-2")
        self.assertIn("已被撤销", lapsed["not_exempt_reason"])


class PersistenceAndConcurrencyTests(unittest.TestCase):
    def test_persists_across_reopen_and_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory, "catalog.db")
            catalog = Catalog(database)
            catalog.add_component("api", "pypi", "lib", "1.0.0")
            catalog.add_vulnerability("CVE-1", "lib", "high")
            catalog.request_exemption(
                "REQ-1", "api", "pypi", "lib", "1.0.0", "CVE-1", "lib", None,
                "alice", "reason", "2030-01-01T00:00:00+00:00",
            )
            catalog.approve_exemption("REQ-1", "bob", "ok")
            first = catalog.risk_report(
                evaluated_at="2027-01-01T00:00:00+00:00"
            )
            catalog.close()

            reopened = Catalog(database)
            record = reopened.get_exemption("REQ-1")
            self.assertEqual(record["status"], "approved")
            self.assertEqual(len(record["events"]), 2)
            second = reopened.risk_report(
                evaluated_at="2027-01-01T00:00:00+00:00"
            )
            self.assertEqual(first, second)
            reopened.close()

    def test_existing_database_keeps_working(self) -> None:
        # A database created before exemptions existed (no exemption tables)
        # migrates transparently.
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory, "catalog.db")
            catalog = Catalog(database)
            catalog.add_component("api", "pypi", "lib", "1.0.0")
            catalog.add_vulnerability("CVE-1", "lib", "high")
            catalog.close()

            reopened = Catalog(database)
            reopened.request_exemption(
                "REQ-1", "api", "pypi", "lib", "1.0.0", "CVE-1", "lib", None,
                "alice", "reason", "2030-01-01T00:00:00+00:00",
            )
            self.assertEqual(
                reopened.get_exemption("REQ-1")["status"], "pending"
            )
            reopened.close()

    def test_concurrent_decisions_accept_one_change(self) -> None:
        import sqlite3
        import threading

        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory, "catalog.db")
            catalog = Catalog(database)
            catalog.add_component("api", "pypi", "lib", "1.0.0")
            catalog.add_vulnerability("CVE-1", "lib", "high")
            catalog.request_exemption(
                "REQ-1", "api", "pypi", "lib", "1.0.0", "CVE-1", "lib", None,
                "alice", "reason", "2030-01-01T00:00:00+00:00",
            )
            catalog.close()

            outcomes: list[str] = []

            def decide(handler: str) -> None:
                local = Catalog(database)
                try:
                    local.approve_exemption("REQ-1", handler, "concurrent")
                    outcomes.append("approved")
                except ValueError:
                    outcomes.append("rejected")
                finally:
                    local.close()

            t1 = threading.Thread(target=decide, args=("bob",))
            t2 = threading.Thread(target=decide, args=("carol",))
            t1.start(); t2.start()
            t1.join(); t2.join()

            self.assertEqual(sorted(outcomes), ["approved", "rejected"])
            check = Catalog(database)
            record = check.get_exemption("REQ-1")
            self.assertEqual(record["status"], "approved")
            self.assertEqual(len(record["events"]), 2)
            check.close()


class CliTests(unittest.TestCase):
    def test_full_cli_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))

            def run(*args):
                return main(["--database", database, *args])

            self.assertEqual(run("add-component", "api", "pypi", "lib", "1"), 0)
            self.assertEqual(
                run("add-vulnerability", "CVE-1", "lib", "high"), 0
            )
            self.assertEqual(
                run(
                    "request-exemption", "REQ-1",
                    "api", "pypi", "lib", "1", "CVE-1", "lib",
                    "--applicant", "alice",
                    "--reason", "mitigated",
                    "--expires-at", "2030-01-01T00:00:00+00:00",
                ),
                0,
            )
            self.assertEqual(
                run("approve-exemption", "REQ-1",
                    "--handler", "alice", "--note", "self"),
                1,
            )
            self.assertEqual(
                run("approve-exemption", "REQ-1",
                    "--handler", "bob", "--note", "ok"),
                0,
            )
            self.assertEqual(run("exemption-show", "REQ-1"), 0)
            self.assertEqual(run("exemption-list"), 0)
            self.assertEqual(run("exemption-list", "--status", "approved"), 0)
            self.assertEqual(
                run("risk-report", "--service", "api",
                    "--at", "2027-01-01T00:00:00+00:00"),
                0,
            )
            self.assertEqual(
                run("revoke-exemption", "REQ-1",
                    "--handler", "bob", "--note", "rollback"),
                0,
            )

    def test_cli_naive_expiry_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            main(["--database", database, "add-component",
                  "api", "pypi", "lib", "1"])
            main(["--database", database, "add-vulnerability",
                  "CVE-1", "lib", "high"])
            code = main([
                "--database", database, "request-exemption", "REQ-1",
                "api", "pypi", "lib", "1", "CVE-1", "lib",
                "--applicant", "alice", "--reason", "x",
                "--expires-at", "2030-01-01T00:00:00",
            ])
            self.assertEqual(code, 1)

    def test_cli_identical_retry_after_expiry_confirms(self) -> None:
        from datetime import datetime as dt

        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))

            def run(*args):
                return main(["--database", database, *args])

            setup = Catalog(database)
            setup.add_component("api", "pypi", "lib", "1")
            setup.add_vulnerability("CVE-1", "lib", "high")
            setup.request_exemption(
                "REQ-1", "api", "pypi", "lib", "1", "CVE-1", "lib", None,
                "alice", "mitigated", "2026-02-01T00:00:00+00:00",
                submitted_at=dt(2026, 1, 1, tzinfo=timezone.utc),
            )
            setup.close()

            # The same instant expressed with a different offset, submitted
            # well after expiry: the stored request is returned with exit 0.
            self.assertEqual(
                run(
                    "request-exemption", "REQ-1",
                    "api", "pypi", "lib", "1", "CVE-1", "lib",
                    "--applicant", "alice",
                    "--reason", "mitigated",
                    "--expires-at", "2026-02-01T08:00:00+08:00",
                ),
                0,
            )
            # Different content is still a conflict error.
            self.assertEqual(
                run(
                    "request-exemption", "REQ-1",
                    "api", "pypi", "lib", "1", "CVE-1", "lib",
                    "--applicant", "alice",
                    "--reason", "changed",
                    "--expires-at", "2026-02-01T00:00:00+00:00",
                ),
                1,
            )
            check = Catalog(database)
            record = check.get_exemption("REQ-1")
            self.assertEqual(record["reason"], "mitigated")
            self.assertEqual(
                record["expires_at"], "2026-02-01T00:00:00.000000Z"
            )
            self.assertEqual(len(record["events"]), 1)
            check.close()


    def test_cli_exemption_not_blocked_by_other_service_bad_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            setup = Catalog(database)
            setup.add_component("api", "pypi", "app", "1.0.0")
            setup.add_component("api", "pypi", "lib", "1.0.0")
            setup.add_dependency(
                "api", "pypi", "app", "1.0.0",
                "api", "pypi", "lib", "1.0.0",
            )
            setup.add_component("worker", "pypi", "lib", "not-a-version")
            setup.import_osv(
                "nvd",
                [osv_record("CVE-OSV", package="lib", severity="low",
                            versions=["1.0.0"])],
            )
            setup.close()

            def run(*args):
                return main(["--database", database, *args])

            # The transitive impact on app can be requested through the CLI.
            self.assertEqual(
                run(
                    "request-exemption", "REQ-1",
                    "api", "pypi", "app", "1.0.0", "CVE-OSV", "lib", "nvd",
                    "--applicant", "alice", "--reason", "x",
                    "--expires-at", "2030-01-01T00:00:00+00:00",
                ),
                0,
            )
            # worker's bad version does not block approval via the CLI.
            self.assertEqual(
                run("approve-exemption", "REQ-1",
                    "--handler", "bob", "--note", "ok"),
                0,
            )
            # A genuinely missing target still fails via the CLI and leaves
            # no record.
            self.assertEqual(
                run(
                    "request-exemption", "REQ-2",
                    "api", "pypi", "ghost", "1.0.0", "CVE-OSV", "lib", "nvd",
                    "--applicant", "alice", "--reason", "x",
                    "--expires-at", "2030-01-01T00:00:00+00:00",
                ),
                1,
            )
            check = Catalog(database)
            ids = [
                row["id"]
                for row in check.connection.execute(
                    "SELECT id FROM exemption_requests ORDER BY id"
                )
            ]
            self.assertEqual(ids, ["REQ-1"])
            self.assertEqual(
                check.get_exemption("REQ-1")["status"], "approved"
            )
            check.close()


if __name__ == "__main__":
    unittest.main()
