"""Regression tests for impact consistency across source updates.

An impact answer combines facts spread over several reads: the component
rows, the dependency edges, the manual vulnerability rows, every OSV source's
records and - for a full-identity query - a separate lookup of the target
component. Another process can replace an SBOM source (a whole
service/source declaration, committed atomically) or an OSV source while
those reads are running. Without one read snapshot the query could then:

* stitch the old directory's components to the replacement's (empty) edge
  list, keeping the directly hit library while silently dropping the
  component that depended on it; or
* load the old graph and OSV conditions and only afterwards resolve the
  full-identity target, so a target the replacement just removed is judged
  against the old directory and the old impact is falsely reported as empty.

These tests pin the contract for every impact entry point (directory-wide,
``--service`` and full component identity, both the Python ``Catalog.impact``
API and the CLI):

* one answer always comes from one complete database state - the
  pre-replacement impact whole (a directly hit library together with
  everything that depends on it) or the post-replacement impact whole (an
  empty list), never a mixture, never a dropped indirect hit, never an
  internal error;
* inside a caller-managed transaction the query sees that transaction's own
  uncommitted changes and is never committed or rolled back by the query;
* with no caller transaction the query only reads and always releases its
  snapshot, including when an OSV version comparison fails, so the same
  Catalog object stays usable, a later independent query observes an
  already-completed source update, and the CLI exits non-zero with no
  half result on stdout.

The existing output shape, source distinction, shortest-path choice and
stable ordering are content-checked against an ordinary, uncontended query.
"""

import contextlib
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path

import supply_guard.cli as cli
from supply_guard.catalog import Catalog


SERVICE = "api"
OTHER_SERVICE = "worker"
SOURCE = "src"
OSV_SOURCE = "nvd"
CVE = "CVE-2026-3001"
MANUAL_CVE = "CVE-2026-9001"


def src_manifest():
    """The only declaration of web and lib and of web's edge onto lib."""
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


def build_catalog(database: str, *, manual: bool = False) -> Catalog:
    catalog = Catalog(database)
    # WAL lets a second connection commit while a read snapshot is held, so
    # the replacement lands strictly inside the query's read window without
    # either connection blocking on the other.
    catalog.connection.execute("PRAGMA journal_mode=WAL")
    catalog.import_sbom(SERVICE, SOURCE, src_manifest())
    if manual:
        catalog.add_vulnerability(MANUAL_CVE, "lib", "high")
    else:
        catalog.import_osv(OSV_SOURCE, lib_high_records())
    return catalog


def impact_names(records: list[dict]) -> list[tuple[str, bool]]:
    return sorted(
        (record["component"]["name"], record["direct"]) for record in records
    )


class ImpactSnapshotConcurrencyTests(unittest.TestCase):
    """A source replaced mid-query is seen whole or not at all."""

    def _run_interleaved(self, reader_action, trigger_sql, writer_action):
        """Run ``writer_action`` from a second Catalog inside the read window.

        A trace barrier on the reader statement whose normalized text starts
        with ``trigger_sql`` releases the writer only once the reads issued
        before that statement have finished, then waits for the writer's
        replacement to commit before the reader continues. The reader
        therefore provably straddles the commit with its earlier reads
        derived from the old directory and every later read executed
        afterwards. With separate per-statement reads the query stitches the
        two states (the old direct hit without the old indirect one, or a
        target resolved after its removal); with one read snapshot every
        read stays pinned to the state the query opened on.

        Returns ``(result, expected, catalog)`` where ``expected`` is the
        quiet, uncontended answer captured before the barrier was armed.
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
                writer_action(other)
            except BaseException as exc:  # report every writer failure
                errors.append(exc)
            finally:
                other.close()
                committed.set()

        thread = threading.Thread(target=replace)
        thread.start()

        # The quiet, uncontended old-state answer is captured while the
        # writer is still blocked on ``proceed``; it is exactly the record
        # the interleaved query must reproduce whole (versus the empty new
        # state whole).
        expected = reader_action(catalog)

        fired = {"done": False}

        def barrier(sql: str) -> None:
            normalized = " ".join(sql.split()).upper()
            if not fired["done"] and normalized.startswith(trigger_sql):
                fired["done"] = True
                catalog.connection.set_trace_callback(None)
                proceed.set()
                # The reader blocks here until the replacement has committed,
                # so every statement after the barrier provably races the
                # replacement commit.
                self.assertTrue(committed.wait(30))

        catalog.connection.set_trace_callback(barrier)
        try:
            result = reader_action(catalog)
        finally:
            catalog.connection.set_trace_callback(None)
            # Release the writer even when the reader failed early.
            proceed.set()

        thread.join(30)
        self.assertFalse(thread.is_alive())
        self.assertTrue(fired["done"], "the interleave barrier never fired")
        self.assertTrue(committed.wait(15))
        self.assertEqual(errors, [])
        return result, expected, catalog

    @staticmethod
    def _replace_sbom_with_empty(other: Catalog) -> None:
        other.import_sbom(SERVICE, SOURCE, empty_manifest())

    @staticmethod
    def _clear_osv_source(other: Catalog) -> None:
        other.import_osv(OSV_SOURCE, [])

    def test_directory_wide_impact_reports_one_complete_state(self) -> None:
        result, expected, catalog = self._run_interleaved(
            lambda c: c.impact(),
            "SELECT DEPENDENT_ID, DEPENDENCY_ID FROM DEPENDENCIES",
            self._replace_sbom_with_empty,
        )

        # Deterministically the old state: the snapshot opened before the
        # edge read pins every later read. lib direct and web indirect must
        # appear together, with the same paths and ordering a quiet query
        # gives.
        self.assertEqual(impact_names(result), [("lib", True), ("web", False)])
        self.assertEqual(result, expected)
        self.assertIn(result, (expected, []))

        # Snapshot released: a fresh query on the same object sees the
        # committed empty declaration, and no read transaction lingers.
        self.assertEqual(catalog.impact(), [])
        self.assertFalse(catalog.connection.in_transaction)

    def test_service_scoped_impact_reports_one_complete_state(self) -> None:
        result, expected, catalog = self._run_interleaved(
            lambda c: c.impact(service=SERVICE),
            "SELECT D.DEPENDENT_ID, D.DEPENDENCY_ID FROM DEPENDENCIES D",
            self._replace_sbom_with_empty,
        )

        self.assertEqual(impact_names(result), [("lib", True), ("web", False)])
        self.assertEqual(result, expected)
        self.assertEqual(catalog.impact(service=SERVICE), [])
        self.assertFalse(catalog.connection.in_transaction)

    def test_manual_vulnerability_keeps_the_same_snapshot_guarantee(self) -> None:
        # Manual and OSV hits match by different rules, but both must stay
        # consistent: replacing the SBOM source while a query runs can never
        # keep the manual lib hit while dropping web's indirect one.
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        database = str(Path(directory.name, "catalog.db"))
        catalog = build_catalog(database, manual=True)
        self.addCleanup(catalog.close)
        expected = catalog.impact()

        proceed, committed = threading.Event(), threading.Event()
        errors: list[BaseException] = []

        def replace() -> None:
            proceed.wait(30)
            other = Catalog(database)
            try:
                other.import_sbom(SERVICE, SOURCE, empty_manifest())
            except BaseException as exc:
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
                "SELECT D.DEPENDENT_ID, D.DEPENDENCY_ID FROM DEPENDENCIES D"
            ):
                fired["done"] = True
                catalog.connection.set_trace_callback(None)
                proceed.set()
                self.assertTrue(committed.wait(30))

        catalog.connection.set_trace_callback(barrier)
        try:
            result = catalog.impact(service=SERVICE)
        finally:
            catalog.connection.set_trace_callback(None)
            proceed.set()
        thread.join(30)

        self.assertTrue(fired["done"])
        self.assertEqual(errors, [])
        self.assertEqual(result, expected)
        self.assertEqual(impact_names(result), [("lib", True), ("web", False)])
        # The components are gone but the manual observation itself survives
        # the source replacement and simply matches nothing afterwards.
        self.assertEqual(catalog.impact(), [])
        manual_rows = catalog.connection.execute(
            "SELECT COUNT(*) FROM vulnerabilities"
        ).fetchone()[0]
        self.assertEqual(manual_rows, 1)

    def test_full_identity_query_keeps_old_target_and_its_indirect_hit(self) -> None:
        def identity_query(catalog: Catalog) -> list[dict]:
            return catalog.impact(
                service=SERVICE, ecosystem="pypi", name="web", version="2.0.0"
            )

        # The barrier fires on the service graph's edge read: the whole graph
        # (including OSV matching) is old, while the target existence lookup
        # runs only after the replacement committed. Unfixed code resolves a
        # now-removed target against the old graph and falsely returns [];
        # the snapshot pins the lookup to the old state and keeps web's
        # indirect hit with its web -> lib path.
        result, expected, catalog = self._run_interleaved(
            identity_query,
            "SELECT D.DEPENDENT_ID, D.DEPENDENCY_ID FROM DEPENDENCIES D",
            self._replace_sbom_with_empty,
        )
        self.assertEqual(result, expected)
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0]["direct"])
        self.assertEqual(
            [node["name"] for node in result[0]["path"]], ["web", "lib"]
        )

        # A directly hit target removed the same way is not falsely emptied
        # either: the old lib self-hit must still come back whole.
        result_lib, expected_lib, _ = self._run_interleaved(
            lambda c: c.impact(
                service=SERVICE, ecosystem="pypi", name="lib", version="1.0.0"
            ),
            "SELECT D.DEPENDENT_ID, D.DEPENDENCY_ID FROM DEPENDENCIES D",
            self._replace_sbom_with_empty,
        )
        self.assertEqual(result_lib, expected_lib)
        self.assertEqual(len(result_lib), 1)
        self.assertTrue(result_lib[0]["direct"])
        self.assertEqual(
            [node["name"] for node in result_lib[0]["path"]], ["lib"]
        )

        # Once the snapshot is released the removed target is gone for later
        # queries on the same object.
        self.assertEqual(identity_query(catalog), [])
        self.assertFalse(catalog.connection.in_transaction)

    def test_osv_source_replaced_mid_query_is_seen_whole(self) -> None:
        # Replacing only the OSV source cannot fabricate a mixed answer by
        # itself (the components and edges are identical in both states), so
        # the contract here is "old records whole or empty whole, never an
        # internal error": the same snapshot still brackets the OSV read and
        # the rest of the query.
        result, expected, catalog = self._run_interleaved(
            lambda c: c.impact(),
            "SELECT SOURCE, ID, PACKAGE_NAME",
            self._clear_osv_source,
        )
        self.assertIn(result, (expected, []))
        self.assertFalse(catalog.connection.in_transaction)
        # The cleared source is visible to the next independent query.
        self.assertEqual(catalog.impact(), [])


class ImpactCliConsistencyTests(unittest.TestCase):
    """The CLI command shares the one-snapshot query and failure contract."""

    @staticmethod
    def _run_cli_with_catalog(catalog: Catalog, argv: list[str]):
        """Run the CLI query against an already-built, instrumented Catalog.

        main() normally opens its own Catalog from --database and closes it
        in ``finally``; the factory is redirected to the instance carrying
        the race barrier so the whole command path is exercised. main() also
        closes that instance, so it must not be reused after the call.
        """
        original_factory = cli.Catalog
        cli.Catalog = lambda database: catalog
        stdout, stderr = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout), \
                    contextlib.redirect_stderr(stderr):
                status = cli.main(argv)
        finally:
            cli.Catalog = original_factory
        return status, stdout.getvalue(), stderr.getvalue()

    def _race_cli_impact(self, argv: list[str], trigger_sql: str):
        """Commit an SBOM replacement strictly inside one CLI impact read."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        database = str(Path(directory.name, "catalog.db"))
        catalog = build_catalog(database)
        identity = any(flag in argv for flag in ("--ecosystem", "--name"))
        expected = catalog.impact(
            service=SERVICE,
            **(
                {"ecosystem": "pypi", "name": "web", "version": "2.0.0"}
                if identity
                else {}
            ),
        )

        proceed, committed = threading.Event(), threading.Event()

        def replace() -> None:
            proceed.wait(30)
            other = Catalog(database)
            try:
                other.import_sbom(SERVICE, SOURCE, empty_manifest())
            finally:
                other.close()
                committed.set()

        thread = threading.Thread(target=replace)
        thread.start()
        fired = {"done": False}

        def barrier(sql: str) -> None:
            normalized = " ".join(sql.split()).upper()
            if not fired["done"] and normalized.startswith(trigger_sql):
                fired["done"] = True
                catalog.connection.set_trace_callback(None)
                proceed.set()
                self.assertTrue(committed.wait(30))

        catalog.connection.set_trace_callback(barrier)
        try:
            status, stdout_text, stderr_text = self._run_cli_with_catalog(
                catalog, ["--database", database, *argv]
            )
        finally:
            # main() closes the shared connection on return, by which point
            # the barrier has already disabled itself; just free the writer.
            proceed.set()
        thread.join(30)
        self.assertFalse(thread.is_alive())
        return fired["done"], status, stdout_text, stderr_text, expected

    def test_cli_directory_impact_prints_one_complete_state(self) -> None:
        fired, status, stdout_text, stderr_text, expected = (
            self._race_cli_impact(
                ["impact"],
                "SELECT DEPENDENT_ID, DEPENDENCY_ID FROM DEPENDENCIES",
            )
        )
        self.assertTrue(fired, "the interleave barrier never fired")
        self.assertEqual(status, 0)
        self.assertEqual(stderr_text, "")
        parsed = json.loads(stdout_text)
        self.assertEqual(parsed, expected)
        self.assertEqual(
            impact_names(parsed), [("lib", True), ("web", False)]
        )

    def test_cli_identity_impact_prints_one_complete_state(self) -> None:
        fired, status, stdout_text, stderr_text, expected = (
            self._race_cli_impact(
                [
                    "impact", "--service", SERVICE,
                    "--ecosystem", "pypi", "--name", "web", "--version", "2.0.0",
                ],
                "SELECT D.DEPENDENT_ID, D.DEPENDENCY_ID FROM DEPENDENCIES D",
            )
        )
        self.assertTrue(fired, "the interleave barrier never fired")
        self.assertEqual(status, 0)
        self.assertEqual(stderr_text, "")
        parsed = json.loads(stdout_text)
        self.assertEqual(parsed, expected)
        self.assertEqual(
            [node["name"] for node in parsed[0]["path"]], ["web", "lib"]
        )

    @staticmethod
    def _failing_database(directory: str) -> str:
        # app 1.0.0 depends on a lib whose version PEP 440 cannot parse, and
        # the OSV record matches lib by name, so the version has to be
        # compared inside every query that includes this service.
        database = str(Path(directory, "catalog.db"))
        catalog = Catalog(database)
        catalog.add_component(SERVICE, "pypi", "app", "1.0.0")
        catalog.add_component(SERVICE, "pypi", "lib", "not-a-version")
        catalog.add_dependency(
            SERVICE, "pypi", "app", "1.0.0",
            SERVICE, "pypi", "lib", "not-a-version",
        )
        catalog.import_osv(OSV_SOURCE, lib_high_records())
        catalog.close()
        return database

    def test_cli_version_error_is_nonzero_with_no_half_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = self._failing_database(directory)
            cases = [
                ["impact"],
                ["impact", "--service", SERVICE],
                [
                    "impact", "--service", SERVICE,
                    "--ecosystem", "pypi", "--name", "app", "--version", "1.0.0",
                ],
            ]
            for argv in cases:
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), \
                        contextlib.redirect_stderr(stderr):
                    status = cli.main(["--database", database, *argv])
                self.assertEqual(status, 1, argv)
                # Not a single record of a half result may reach stdout.
                self.assertEqual(stdout.getvalue(), "", argv)
                self.assertIn("版本无法解析", stderr.getvalue(), argv)
                self.assertIn(
                    "api/pypi/lib/not-a-version", stderr.getvalue(), argv
                )

    def test_cli_healthy_service_is_isolated_and_prints_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = self._failing_database(directory)
            # A healthy second service answers even though a directory-wide
            # query over the same database fails on an unparseable version.
            setup = Catalog(database)
            setup.add_component(OTHER_SERVICE, "pypi", "redis", "7.0.0")
            setup.close()

            for argv in (
                ["impact", "--service", OTHER_SERVICE],
                ["impact", "--service", "ghost"],
            ):
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), \
                        contextlib.redirect_stderr(stderr):
                    status = cli.main(["--database", database, *argv])
                self.assertEqual(status, 0, argv)
                self.assertEqual(stderr.getvalue(), "")
                self.assertEqual(json.loads(stdout.getvalue()), [])


class ImpactCallerTransactionTests(unittest.TestCase):
    """A caller-managed transaction is honored, never committed or undone."""

    def setUp(self) -> None:
        self.catalog = Catalog()
        self.connection = self.catalog.connection

    def tearDown(self) -> None:
        self.catalog.close()

    def _seed_uncommitted_directory(self) -> None:
        # Direct SQL, like a caller mid-transaction: the public write helpers
        # own their own commit and must not stage uncommitted work.
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

    def test_impact_sees_uncommitted_changes_and_leaves_transaction_open(self) -> None:
        self.connection.execute("BEGIN")
        self._seed_uncommitted_directory()
        try:
            self.assertEqual(
                impact_names(self.catalog.impact()),
                [("lib", True), ("web", False)],
            )
            self.assertEqual(
                impact_names(self.catalog.impact(service=SERVICE)),
                [("lib", True), ("web", False)],
            )
            identity = self.catalog.impact(
                service=SERVICE, ecosystem="pypi", name="web", version="2.0.0"
            )
            self.assertEqual(len(identity), 1)
            self.assertFalse(identity[0]["direct"])
            self.assertEqual(
                [node["name"] for node in identity[0]["path"]], ["web", "lib"]
            )
            # The query must not end, commit or roll back the caller's
            # transaction, for any of the three query shapes.
            self.assertTrue(self.connection.in_transaction)
        finally:
            self.connection.rollback()

        # After the caller discards its own work the uncommitted directory is
        # invisible again, and no read state is left behind.
        self.assertEqual(self.catalog.impact(), [])
        self.assertFalse(self.connection.in_transaction)

    def test_caller_can_commit_what_impact_previewed(self) -> None:
        self.connection.execute("BEGIN")
        self._seed_uncommitted_directory()
        self.assertEqual(
            impact_names(self.catalog.impact(service=SERVICE)),
            [("lib", True), ("web", False)],
        )
        self.assertTrue(self.connection.in_transaction)
        self.connection.commit()
        self.assertFalse(self.connection.in_transaction)
        identity = self.catalog.impact(
            service=SERVICE, ecosystem="pypi", name="web", version="2.0.0"
        )
        self.assertEqual(len(identity), 1)
        self.assertFalse(identity[0]["direct"])

    def test_version_error_inside_caller_transaction_keeps_it_open(self) -> None:
        self.catalog.import_osv(OSV_SOURCE, lib_high_records())
        self.connection.execute("BEGIN")
        self.connection.execute(
            "INSERT INTO components(service, ecosystem, name, version, manual)"
            " VALUES ('api', 'pypi', 'lib', 'not-a-version', 1)"
        )
        try:
            for query in (
                lambda: self.catalog.impact(),
                lambda: self.catalog.impact(service=SERVICE),
                lambda: self.catalog.impact(
                    service=SERVICE, ecosystem="pypi",
                    name="web", version="2.0.0",
                ),
            ):
                with self.assertRaises(ValueError) as caught:
                    query()
                self.assertIn("api/pypi/lib/not-a-version", str(caught.exception))
                # An errored read neither rolls back nor commits caller work.
                self.assertTrue(self.connection.in_transaction)
        finally:
            self.connection.rollback()

        self.assertFalse(self.connection.in_transaction)
        self.assertEqual(self.catalog.impact(), [])


class ImpactReadOnlyAndFailureTests(unittest.TestCase):
    """Without a caller transaction impact only reads and self-cleans."""

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
            self.catalog.impact()
            self.catalog.impact(service=SERVICE)
            self.catalog.impact(
                service=SERVICE, ecosystem="pypi", name="web", version="2.0.0"
            )
            # A target that does not exist takes the same snapshot path.
            self.catalog.impact(
                service=SERVICE, ecosystem="pypi", name="ghost", version="9.9.9"
            )
        finally:
            self.connection.set_trace_callback(None)

        normalized = [" ".join(s.split()).upper() for s in statements]
        for statement in normalized:
            self.assertTrue(
                statement.startswith(("SELECT", "BEGIN", "ROLLBACK")),
                f"impact issued a non-read statement: {statement}",
            )
            self.assertFalse(
                statement.startswith(
                    (
                        "INSERT", "UPDATE", "DELETE", "REPLACE", "CREATE",
                        "DROP", "ALTER", "PRAGMA", "ATTACH", "DETACH",
                        "COMMIT", "BEGIN IMMEDIATE", "SAVEPOINT", "RELEASE",
                    )
                ),
                f"impact must stay read-only: {statement}",
            )
        # Every self-opened snapshot is rolled back, never committed, and no
        # transaction is left open - for every query shape.
        self.assertEqual(
            normalized.count("BEGIN"), normalized.count("ROLLBACK")
        )
        self.assertNotIn("COMMIT", normalized)
        self.assertFalse(self.connection.in_transaction)

    def test_version_error_releases_snapshot_and_names_full_identity(self) -> None:
        # A healthy second service proves a failed read leaves no state that
        # disturbs later queries on the same Catalog instance.
        self.catalog.add_component(OTHER_SERVICE, "pypi", "redis", "7.0.0")
        self.catalog.add_component(SERVICE, "pypi", "lib", "not-a-version")

        with self.assertRaises(ValueError) as caught:
            self.catalog.impact()
        self.assertIn("版本无法解析", str(caught.exception))
        self.assertIn("api/pypi/lib/not-a-version", str(caught.exception))
        self.assertFalse(self.connection.in_transaction)

        # Another service's bad version neither fails this service's query
        # nor leaves a snapshot behind.
        self.assertEqual(self.catalog.impact(service=OTHER_SERVICE), [])
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
        # The same connection still accepts writes afterwards.
        self.catalog.add_component(OTHER_SERVICE, "pypi", "queue", "4.0.0")
        self.assertFalse(self.connection.in_transaction)

    def test_failed_read_is_followed_by_a_freshly_updated_state(self) -> None:
        # The snapshot of an errored query must be released exactly like a
        # successful one, so another connection's source replacement can
        # commit afterwards and be observed by the next independent query on
        # this object. The database uses the default rollback journal, where
        # a lingering read transaction is what blocks a writer at commit.
        with tempfile.TemporaryDirectory() as tempdir:
            database = str(Path(tempdir, "catalog.db"))
            catalog = Catalog(database)
            catalog.import_sbom(SERVICE, SOURCE, src_manifest())
            catalog.import_osv(OSV_SOURCE, lib_high_records())
            catalog.add_component(
                OTHER_SERVICE, "pypi", "lib", "not-a-version"
            )

            # The directory-wide query fails on the other service's version
            # and must release its read.
            with self.assertRaises(ValueError):
                catalog.impact()
            self.assertFalse(catalog.connection.in_transaction)

            writer = Catalog(database)
            try:
                # A leaked snapshot would block this commit on the default
                # journal; completing at all proves the read was released.
                writer.import_sbom(SERVICE, SOURCE, empty_manifest())
            finally:
                writer.close()

            # The selected service's graph is now empty: the next query sees
            # the finished replacement (not the failed query's old snapshot),
            # while the other service still fails on its own bad version.
            self.assertEqual(catalog.impact(service=SERVICE), [])
            with self.assertRaises(ValueError):
                catalog.impact(service=OTHER_SERVICE)
            self.assertFalse(catalog.connection.in_transaction)
            catalog.close()


if __name__ == "__main__":
    unittest.main()
