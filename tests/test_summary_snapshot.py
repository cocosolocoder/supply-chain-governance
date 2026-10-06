"""Regression tests for summary consistency across directory updates.

A summary combines facts from several reads: the total component count, the
directly and transitively affected components, the deduplicated vulnerability
count, the highest risk and the sorted affected-service list. Another process
can replace an SBOM source (a whole service/source declaration, atomically)
while those reads are running; without one read snapshot the summary could
stitch the old directory's affected components to the new directory's total
count (zero components with two affected) or keep an old ``high`` while the
service list already reads ``none``.

These tests pin the contract for both entry points:

* a Python ``Catalog.summary`` call and the CLI's whole Chinese summary each
  reflect exactly one committed database state - the pre-replacement state
  whole or the post-replacement state whole, never a mixture;
* inside a caller-managed transaction the summary sees that transaction's own
  uncommitted changes and is never committed or rolled back by the query;
* with no caller transaction the query only reads, always releases its
  snapshot, and a version-comparison error names the component's service,
  ecosystem, name and version without leaving a half-open transaction or
  changing any business data; the CLI then exits non-zero with no partial
  summary on stdout.
"""

import contextlib
import io
import tempfile
import threading
import unittest
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard.cli import main, render_summary


SERVICE = "api"
OTHER_SERVICE = "worker"
SOURCE = "src"
OSV_SOURCE = "nvd"
CVE = "CVE-2026-3001"

HEADER = "软件供应链治理摘要"


def src_manifest():
    """The only declaration of the two components and their one edge."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"bom-ref": "web", "purl": "pkg:pypi/web@2.0.0"},
            {"bom-ref": "lib", "purl": "pkg:pypi/lib@1.0.0"},
        ],
        "dependencies": [{"ref": "web", "dependsOn": ["lib"]}],
    }


def empty_manifest():
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}


def lib_high_records():
    """One high OSV vulnerability hitting exactly lib 1.0.0."""
    return [
        {
            "id": CVE,
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "lib"},
                    "versions": ["1.0.0"],
                }
            ],
            "database_specific": {"severity": "high"},
        }
    ]


def build_catalog(database: str) -> Catalog:
    catalog = Catalog(database)
    # WAL lets a second connection commit while a read snapshot is held, so
    # the replacement can land strictly inside the summary's read window
    # without either connection blocking on the other.
    catalog.connection.execute("PRAGMA journal_mode=WAL")
    catalog.import_sbom(SERVICE, SOURCE, src_manifest())
    catalog.import_osv(OSV_SOURCE, lib_high_records())
    return catalog


# The only two complete, self-consistent states an interleaved summary may
# report: the old directory whole, or the emptied directory whole.
OLD_VALUES = (2, 2, 1, "high")
NEW_VALUES = (0, 0, 0, None)

OLD_RENDER = "\n".join(
    [
        HEADER,
        "组件数量: 2",
        "受影响组件: 2",
        "漏洞数量: 1",
        "最高风险: high",
        f"受影响服务: {SERVICE}",
    ]
)
NEW_RENDER = "\n".join(
    [
        HEADER,
        "组件数量: 0",
        "受影响组件: 0",
        "漏洞数量: 0",
        "最高风险: none",
        "受影响服务: none",
    ]
)


def summary_values(catalog: Catalog) -> tuple:
    summary = catalog.summary()
    return (
        summary.components,
        summary.affected_components,
        summary.vulnerabilities,
        summary.highest_severity,
    )


class SummarySnapshotConcurrencyTests(unittest.TestCase):
    """A source replaced mid-summary is seen whole or not at all."""

    def _run_interleaved(self, reader_action):
        """Replace src with [] from a second connection during the read.

        A trace barrier on the reader's final component-count SELECT releases
        the writer only once every hit computation has finished, then waits
        for the replacement transaction to commit before the count read runs.
        The reader is therefore guaranteed to straddle the commit with the
        affected-component, vulnerability and highest-risk facts already
        derived from the old directory while the total count (and, for the
        CLI, the separately queried service list) is read afterwards: with
        separate per-statement reads the summary stitches old impact figures
        to the new empty directory (zero total with two affected, high with
        no services); with one read snapshot every figure stays pinned to
        the state the read opened on.
        """
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        database = str(Path(directory.name, "catalog.db"))
        catalog = build_catalog(database)
        self.addCleanup(catalog.close)

        proceed = threading.Event()
        committed = threading.Event()
        errors: list[BaseException] = []

        def replace() -> None:
            proceed.wait(30)
            other = Catalog(database)
            try:
                other.import_sbom(SERVICE, SOURCE, empty_manifest())
            except BaseException as exc:  # report every writer failure
                errors.append(exc)
            finally:
                other.close()
                committed.set()

        thread = threading.Thread(target=replace)
        thread.start()

        fired = {"done": False}

        def barrier(sql: str) -> None:
            normalized = " ".join(sql.split()).upper()
            if not fired["done"] and normalized.startswith(
                "SELECT COUNT(*) AS COMPONENTS FROM COMPONENTS"
            ):
                fired["done"] = True
                catalog.connection.set_trace_callback(None)
                proceed.set()
                # The reader blocks here until the replacement has committed,
                # so the count read provably races the replacement commit.
                self.assertTrue(committed.wait(30))

        catalog.connection.set_trace_callback(barrier)
        try:
            result = reader_action(catalog)
        finally:
            catalog.connection.set_trace_callback(None)
            # Release the writer even when the reader failed before reaching
            # the barrier, so no replacement thread outlives the run's
            # temporary directory.
            proceed.set()

        thread.join(30)
        self.assertFalse(thread.is_alive())
        # Writer errors are meaningful only once the interleave really fired
        # with the directory still alive.
        self.assertTrue(fired["done"], "the interleave barrier never fired")
        self.assertTrue(committed.wait(15))
        self.assertEqual(errors, [])
        return result, catalog

    def test_python_summary_reports_one_complete_state(self) -> None:
        result, catalog = self._run_interleaved(summary_values)

        # One snapshot pins every figure to the state it opened on, which here
        # is the old directory because the barrier lets the commit land only
        # after the snapshot began. Either complete state would satisfy the
        # contract, but a stitched one must never appear: zero total with two
        # affected, or a high vulnerability with zero affected.
        self.assertEqual(result, OLD_VALUES)
        self.assertIn(result, (OLD_VALUES, NEW_VALUES))
        self.assertFalse(result[0] == 0 and result[1] == 2)
        self.assertFalse(result[3] == "high" and result[1] == 0)

        # After the read releases its snapshot, later reads see the committed
        # replacement: both components and their edge are gone, the surviving
        # OSV record matches nothing.
        self.assertEqual(summary_values(catalog), NEW_VALUES)
        self.assertFalse(catalog.connection.in_transaction)

    def test_cli_summary_renders_one_complete_state(self) -> None:
        rendered, catalog = self._run_interleaved(render_summary)

        # The component total, affected count, vulnerability count, highest
        # risk and service list must come from the same state: the old two
        # component/high/api summary whole or the empty none/none summary
        # whole. The deterministic snapshot result is the old state.
        self.assertEqual(rendered, OLD_RENDER)
        self.assertIn(rendered, (OLD_RENDER, NEW_RENDER))

        self.assertEqual(render_summary(catalog), NEW_RENDER)
        self.assertFalse(catalog.connection.in_transaction)

    def test_summary_and_services_share_one_snapshot(self) -> None:
        # The Python entry point backing the CLI returns the figures and the
        # service list from the very same read snapshot.
        def read(catalog: Catalog):
            summary, services = catalog.summary_with_services()
            return (
                summary.components,
                summary.affected_components,
                summary.vulnerabilities,
                summary.highest_severity,
                tuple(services),
            )

        result, catalog = self._run_interleaved(read)
        self.assertEqual(result, OLD_VALUES + (("api",),))
        summary_after, services_after = catalog.summary_with_services()
        self.assertEqual(
            (
                summary_after.components,
                summary_after.affected_components,
                summary_after.vulnerabilities,
                summary_after.highest_severity,
                tuple(services_after),
            ),
            NEW_VALUES + ((),),
        )
        self.assertEqual(services_after, [])


class SummaryCallerTransactionTests(unittest.TestCase):
    """A caller-managed transaction is honored, never committed or undone."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        self.connection = self.catalog.connection

    def tearDown(self) -> None:
        self.catalog.close()

    def _seed_uncommitted_directory(self) -> None:
        # Direct SQL, like a caller mid-transaction: the public write helpers
        # own their own commit and must not be used to stage uncommitted work.
        self.connection.execute(
            "INSERT INTO components(service, ecosystem, name, version, manual)"
            " VALUES ('api', 'pypi', 'web', '2.0.0', 0),"
            " ('api', 'pypi', 'lib', '1.0.0', 0)"
        )
        self.connection.execute(
            """
            INSERT INTO dependencies(dependent_id, dependency_id, manual)
            SELECT c1.id, c2.id, 0
            FROM components c1 JOIN components c2
            WHERE c1.name = 'web' AND c2.name = 'lib'
            """
        )
        self.connection.execute(
            "INSERT INTO vulnerabilities(id, component_name, severity)"
            " VALUES ('CVE-TX', 'lib', 'high')"
        )

    def test_summary_sees_uncommitted_changes_and_leaves_transaction_open(self) -> None:
        self.connection.execute("BEGIN")
        self._seed_uncommitted_directory()
        try:
            self.assertEqual(
                summary_values(self.catalog), (2, 2, 1, "high")
            )
            self.assertEqual(self.catalog.affected_services(), [SERVICE])
            summary, services = self.catalog.summary_with_services()
            self.assertEqual(summary.affected_components, 2)
            self.assertEqual(services, [SERVICE])
            # The query must not end, commit or roll back the caller's
            # transaction on a normal return.
            self.assertTrue(self.connection.in_transaction)
        finally:
            self.connection.rollback()

        # After the caller discards its own work the uncommitted directory is
        # invisible again, and no read state is left behind.
        self.assertEqual(summary_values(self.catalog), NEW_VALUES)
        self.assertFalse(self.connection.in_transaction)

    def test_caller_can_commit_what_summary_previewed(self) -> None:
        self.connection.execute("BEGIN")
        self._seed_uncommitted_directory()
        self.assertEqual(summary_values(self.catalog), (2, 2, 1, "high"))
        self.assertTrue(self.connection.in_transaction)
        self.connection.commit()
        self.assertFalse(self.connection.in_transaction)
        self.assertEqual(summary_values(self.catalog), (2, 2, 1, "high"))
        self.assertEqual(self.catalog.affected_services(), [SERVICE])

    def test_version_error_inside_caller_transaction_keeps_it_open(self) -> None:
        self.catalog.import_osv(OSV_SOURCE, lib_high_records())
        self.connection.execute("BEGIN")
        self.connection.execute(
            "INSERT INTO components(service, ecosystem, name, version, manual)"
            " VALUES ('api', 'pypi', 'lib', 'not-a-version', 1)"
        )
        try:
            for query in (
                lambda: self.catalog.summary(),
                lambda: self.catalog.summary_with_services(),
                lambda: self.catalog.affected_services(),
            ):
                with self.assertRaises(ValueError) as caught:
                    query()
                message = str(caught.exception)
                self.assertIn("api/pypi/lib/not-a-version", message)
                # An errored read neither rolls back nor commits caller work.
                self.assertTrue(self.connection.in_transaction)
        finally:
            self.connection.rollback()

        # The uncommitted bad component is gone with the rollback; the
        # committed OSV source is untouched and the connection stays usable.
        self.assertFalse(self.connection.in_transaction)
        self.assertEqual(summary_values(self.catalog), NEW_VALUES)
        osv_count = self.connection.execute(
            "SELECT COUNT(*) FROM osv_vulnerabilities"
        ).fetchone()[0]
        self.assertEqual(osv_count, 1)


class SummaryReadOnlyAndFailureTests(unittest.TestCase):
    """Without a caller transaction the query only reads and self-cleans."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        self.connection = self.catalog.connection
        self.catalog.import_sbom(SERVICE, SOURCE, src_manifest())
        self.catalog.import_osv(OSV_SOURCE, lib_high_records())

    def tearDown(self) -> None:
        self.catalog.close()

    def test_queries_issue_only_reads_and_release_their_snapshot(self) -> None:
        statements: list[str] = []
        self.connection.set_trace_callback(statements.append)
        try:
            first_values = summary_values(self.catalog)
            first_services = self.catalog.affected_services()
            bundled_summary, bundled_services = (
                self.catalog.summary_with_services()
            )
            second_values = summary_values(self.catalog)
        finally:
            self.connection.set_trace_callback(None)

        normalized = [" ".join(s.split()).upper() for s in statements]
        write_prefixes = (
            "INSERT", "UPDATE", "DELETE", "REPLACE", "CREATE", "DROP",
            "ALTER", "PRAGMA", "ATTACH", "DETACH", "COMMIT",
            "BEGIN IMMEDIATE", "SAVEPOINT", "RELEASE",
        )
        for statement in normalized:
            self.assertTrue(
                statement.startswith(("SELECT", "BEGIN", "ROLLBACK")),
                f"summary issued a non-read statement: {statement}",
            )
            self.assertFalse(
                statement.startswith(write_prefixes),
                f"summary must stay read-only: {statement}",
            )
        # Every self-opened snapshot is rolled back, never committed.
        self.assertNotIn("COMMIT", normalized)
        self.assertEqual(normalized.count("BEGIN"), normalized.count("ROLLBACK"))
        self.assertFalse(self.connection.in_transaction)

        self.assertEqual(first_values, OLD_VALUES)
        self.assertEqual(second_values, OLD_VALUES)
        self.assertEqual(first_services, [SERVICE])
        self.assertEqual(bundled_services, [SERVICE])
        self.assertEqual(
            (
                bundled_summary.components,
                bundled_summary.affected_components,
                bundled_summary.vulnerabilities,
                bundled_summary.highest_severity,
            ),
            OLD_VALUES,
        )

    def test_version_error_names_component_and_leaves_a_usable_catalog(self) -> None:
        # A second, healthy service proves a failed directory-wide read does
        # not leave read state that blocks later operations on the instance.
        self.catalog.add_component(OTHER_SERVICE, "pypi", "redis", "7.0.0")
        self.catalog.add_component(SERVICE, "pypi", "lib", "not-a-version")

        for query in (
            lambda: self.catalog.summary(),
            lambda: self.catalog.affected_services(),
        ):
            with self.assertRaises(ValueError) as caught:
                query()
            message = str(caught.exception)
            self.assertIn("版本无法解析", message)
            self.assertIn("api/pypi/lib/not-a-version", message)
            # No half-open snapshot transaction is left behind.
            self.assertFalse(self.connection.in_transaction)

        # Business data is unchanged by the failed reads.
        self.assertEqual(
            self.connection.execute("SELECT COUNT(*) FROM components").fetchone()[0],
            4,
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT COUNT(*) FROM osv_vulnerabilities"
            ).fetchone()[0],
            1,
        )
        # The same connection still serves healthy-scope queries and accepts
        # writes after the failed directory-wide reads.
        self.assertEqual(self.catalog.impact(service=OTHER_SERVICE), [])
        self.catalog.add_component(OTHER_SERVICE, "pypi", "queue", "4.0.0")
        self.assertFalse(self.connection.in_transaction)

    def test_cli_version_error_is_nonzero_with_no_partial_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            failing = Catalog(database)
            failing.import_sbom(SERVICE, SOURCE, src_manifest())
            failing.import_osv(OSV_SOURCE, lib_high_records())
            failing.add_component(SERVICE, "pypi", "lib", "not-a-version")
            failing.close()

            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), \
                    contextlib.redirect_stderr(stderr):
                status = main(["--database", database, "summary"])

            self.assertEqual(status, 1)
            # Not a single line of a partial summary may reach stdout.
            self.assertEqual(stdout.getvalue(), "")
            self.assertNotIn(HEADER, stdout.getvalue())
            self.assertIn("版本无法解析", stderr.getvalue())
            self.assertIn("api/pypi/lib/not-a-version", stderr.getvalue())

            reopened = Catalog(database)
            self.assertEqual(
                reopened.connection.execute(
                    "SELECT COUNT(*) FROM components"
                ).fetchone()[0],
                3,
            )
            self.assertEqual(
                reopened.connection.execute(
                    "SELECT COUNT(*) FROM osv_vulnerabilities"
                ).fetchone()[0],
                1,
            )
            with self.assertRaises(ValueError):
                reopened.summary()
            reopened.close()


class SummaryContentContractTests(unittest.TestCase):
    """The figures keep their existing counting rules and output shape."""

    def test_approved_exemption_does_not_reduce_raw_risk(self) -> None:
        catalog = Catalog()
        catalog.import_sbom(SERVICE, SOURCE, src_manifest())
        catalog.import_osv(OSV_SOURCE, lib_high_records())
        catalog.request_exemption(
            "EXM-1", SERVICE, "pypi", "lib", "1.0.0",
            CVE, "lib", OSV_SOURCE,
            applicant="alice",
            reason="accept risk",
            expires_at="2030-01-01T00:00:00+00:00",
        )
        catalog.approve_exemption("EXM-1", handler="bob", note="approved")
        # The summary keeps reflecting the original, unmitigated impact.
        self.assertEqual(summary_values(catalog), OLD_VALUES)
        self.assertEqual(catalog.affected_services(), [SERVICE])
        catalog.close()

    def test_empty_catalog_renders_zero_counts_and_none_placeholders(self) -> None:
        catalog = Catalog()
        self.assertEqual(summary_values(catalog), NEW_VALUES)
        self.assertEqual(catalog.affected_services(), [])
        self.assertEqual(render_summary(catalog), NEW_RENDER)
        catalog.close()

    def test_cli_summary_matches_python_and_keeps_service_sorting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = Catalog(database)
            catalog.import_sbom(SERVICE, SOURCE, src_manifest())
            catalog.add_component(OTHER_SERVICE, "pypi", "redis", "7.0.0")
            catalog.add_vulnerability("CVE-MAN", "redis", "low")
            catalog.import_osv(OSV_SOURCE, lib_high_records())
            expected = render_summary(catalog)
            catalog.close()

            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), \
                    contextlib.redirect_stderr(stderr):
                status = main(["--database", database, "summary"])
            self.assertEqual(status, 0)
            self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(stdout.getvalue().rstrip("\n"), expected)
            # Field order and the code-point service sorting are unchanged.
            self.assertEqual(
                stdout.getvalue().splitlines(),
                [
                    HEADER,
                    "组件数量: 3",
                    "受影响组件: 3",
                    "漏洞数量: 2",
                    "最高风险: high",
                    "受影响服务: api, worker",
                ],
            )

    def test_summary_dataclass_shape_is_unchanged(self) -> None:
        catalog = Catalog()
        summary = catalog.summary()
        self.assertEqual(
            list(vars(summary).keys()),
            [
                "components",
                "affected_components",
                "vulnerabilities",
                "highest_severity",
            ],
        )
        bundled, services = catalog.summary_with_services()
        self.assertEqual(vars(bundled), vars(summary))
        self.assertEqual(services, [])
        catalog.close()


if __name__ == "__main__":
    unittest.main()
