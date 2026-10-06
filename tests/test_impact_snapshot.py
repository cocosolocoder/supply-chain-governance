"""Regression tests for impact-query consistency across source updates.

An ``impact`` answer combines several reads: the selected service's (or the
whole directory's) components, the dependency edges, the manual vulnerability
observations and the imported OSV records; a full-identity query additionally
resolves the target component and walks its forward dependency closure.
Another process can replace an SBOM or OSV source - atomically, in one
committed write transaction - while those reads run. Without one read
snapshot the answer could stitch two states together:

* the old component and vulnerability list joined to the new empty edge set
  keeps a library's direct hit but drops the component that depended on it, so
  the source's own record of an indirect impact silently disappears;
* the whole-service graph is read first and the full-identity target only
  located afterwards, so a target the replacement removes mid-query turns
  impacts that existed in the old directory into a false empty list;
* an edge read after the component read can even reference a component the
  new state already deleted, surfacing as an internal error instead of an
  answer.

These tests pin the contract for every impact entry point - directory-wide,
``--service`` and a full component identity, through both ``Catalog.impact``
and the CLI:

* one answer reflects exactly one committed state: the pre-replacement
  directory whole or the post-replacement directory whole, never a mixture
  (a lone direct library hit without its old dependent, or a false empty
  identity result, are both rejected);
* inside a caller-managed transaction the query sees that transaction's own
  uncommitted changes and is never committed or rolled back by the query;
* with no caller transaction the query only reads, always releases its
  snapshot (also on a version-comparison error), changes no business data and
  leaves the same Catalog usable so later queries observe completed updates;
* a version the selected service must compare but cannot parse still names
  the component's full identity, and the CLI exits non-zero with no partial
  JSON on stdout.
"""

import contextlib
import io
import tempfile
import threading
import unittest
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard.cli import main


SERVICE = "api"
OTHER_SERVICE = "worker"
SOURCE = "src"
OSV_SOURCE = "nvd"
CVE = "CVE-2026-3001"


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
    # the replacement lands strictly inside the query's read window without
    # either connection blocking on the other.
    catalog.connection.execute("PRAGMA journal_mode=WAL")
    catalog.import_sbom(SERVICE, SOURCE, src_manifest())
    catalog.import_osv(OSV_SOURCE, lib_high_records())
    return catalog


def record_outline(record: dict) -> tuple:
    """(component, direct, vulnerability, path names) for state assertions."""
    return (
        record["component"]["name"],
        record["direct"],
        record["vulnerability"],
        tuple(node["name"] for node in record["path"]),
    )


# The old directory's complete answer: lib directly hit, web affected through
# its dependency web -> lib. The new (emptied) directory answers with [].
OLD_OUTLINE = {
    ("lib", True, CVE, ("lib",)),
    ("web", False, CVE, ("web", "lib")),
}


class ImpactSnapshotConcurrencyTests(unittest.TestCase):
    """A source replaced mid-query is seen whole or not at all."""

    def _run_interleaved(self, reader_action, sql_predicate):
        """Replace src with [] from a second connection during the read.

        A trace barrier fires on the reader's first statement matching
        ``sql_predicate``, releases the writer, and waits for the replacement
        to commit before letting that reader statement run, so the query
        provably straddles the commit with some reads already derived from
        the old directory and the remaining reads about to observe the new
        one. With per-statement autocommit reads the answer stitches states;
        with one read snapshot every read stays pinned to the opening state.
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
            if not fired["done"] and sql_predicate(" ".join(sql.split()).upper()):
                fired["done"] = True
                catalog.connection.set_trace_callback(None)
                proceed.set()
                # Block the reader here until the replacement committed, so
                # its next read provably races the replacement commit.
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
        return result, catalog

    def test_directory_impact_reports_one_complete_state(self) -> None:
        # Components and vulnerability rows are read from the old state; the
        # edge read is held until after the replacement commits. Un-snapshotted
        # it joins the old hits to the new empty edge set and keeps only lib's
        # direct hit; one snapshot keeps the old web -> lib indirect impact.
        result, catalog = self._run_interleaved(
            lambda cat: cat.impact(),
            lambda sql: sql == "SELECT DEPENDENT_ID, DEPENDENCY_ID FROM DEPENDENCIES",
        )
        outline = {record_outline(record) for record in result}
        self.assertEqual(outline, OLD_OUTLINE)
        self.assertIn(outline, (OLD_OUTLINE, set()))
        # The specific forbidden mixture: old direct hit, missing old indirect.
        self.assertFalse(
            any(name == "lib" and direct for name, direct, _, _ in outline)
            and not any(name == "web" for name, *_ in outline)
        )

        # After the snapshot is released, later reads see the committed
        # replacement: both components and their edge are gone.
        self.assertEqual(catalog.impact(), [])
        self.assertFalse(catalog.connection.in_transaction)

    def test_service_impact_reports_one_complete_state(self) -> None:
        result, catalog = self._run_interleaved(
            lambda cat: cat.impact(service=SERVICE),
            lambda sql: sql.startswith(
                "SELECT D.DEPENDENT_ID, D.DEPENDENCY_ID FROM DEPENDENCIES D "
                "JOIN COMPONENTS"
            ),
        )

        outline = {record_outline(record) for record in result}
        self.assertEqual(outline, OLD_OUTLINE)
        self.assertTrue(
            all(
                node["service"] == SERVICE
                for record in result
                for node in record["path"]
            )
        )
        self.assertEqual(catalog.impact(service=SERVICE), [])
        self.assertFalse(catalog.connection.in_transaction)

    def test_full_identity_keeps_impact_when_target_removed_mid_query(self) -> None:
        # The whole service graph (components, edges, OSV matching) is read
        # from the old state; the target lookup is held until the replacement
        # commits and removes web. Un-snapshotted the lookup says "gone" and
        # the query falsely returns []; one snapshot judges the target against
        # the same old directory the graph came from.
        def query(cat: Catalog):
            return cat.impact(
                service=SERVICE, ecosystem="pypi", name="web", version="2.0.0"
            )

        result, catalog = self._run_interleaved(
            query,
            lambda sql: sql.startswith(
                "SELECT ID FROM COMPONENTS WHERE SERVICE ="
            ),
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(record_outline(result[0]), ("web", False, CVE, ("web", "lib")))

        # The later, independent query runs against the committed replacement
        # and correctly finds the target absent.
        self.assertEqual(query(catalog), [])
        self.assertFalse(catalog.connection.in_transaction)

    def test_full_identity_direct_hit_uses_one_state(self) -> None:
        def query(cat: Catalog):
            return cat.impact(
                service=SERVICE, ecosystem="pypi", name="lib", version="1.0.0"
            )

        result, catalog = self._run_interleaved(
            query,
            lambda sql: sql.startswith(
                "SELECT ID FROM COMPONENTS WHERE SERVICE ="
            ),
        )
        self.assertEqual(
            {record_outline(r) for r in result}, {("lib", True, CVE, ("lib",))}
        )
        self.assertEqual(query(catalog), [])


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
            # Directory-wide and service-scoped return lib's direct hit and
            # web's indirect hit; the full-identity query returns only the
            # requested target (web), still reached through the uncommitted
            # web -> lib edge.
            full = {
                ("lib", True, "CVE-TX", ("lib",)),
                ("web", False, "CVE-TX", ("web", "lib")),
            }
            for query, expected in (
                (lambda: self.catalog.impact(), full),
                (lambda: self.catalog.impact(service=SERVICE), full),
                (
                    lambda: self.catalog.impact(
                        service=SERVICE, ecosystem="pypi",
                        name="web", version="2.0.0",
                    ),
                    {("web", False, "CVE-TX", ("web", "lib"))},
                ),
            ):
                self.assertEqual({record_outline(r) for r in query()}, expected)
                # The query must not end, commit or roll back the caller's
                # transaction on a normal return.
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
        self.assertEqual(len(self.catalog.impact()), 2)
        self.assertTrue(self.connection.in_transaction)
        self.connection.commit()
        self.assertFalse(self.connection.in_transaction)
        self.assertEqual(len(self.catalog.impact()), 2)

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
                lambda: self.catalog.impact(
                    service=SERVICE, ecosystem="pypi", name="web", version="2.0.0"
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
        osv_count = self.connection.execute(
            "SELECT COUNT(*) FROM osv_vulnerabilities"
        ).fetchone()[0]
        self.assertEqual(osv_count, 1)


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
            directory_records = self.catalog.impact()
            service_records = self.catalog.impact(service=SERVICE)
            identity_records = self.catalog.impact(
                service=SERVICE, ecosystem="pypi", name="web", version="2.0.0"
            )
        finally:
            self.connection.set_trace_callback(None)

        normalized = [" ".join(s.split()).upper() for s in statements]
        write_prefixes = (
            "INSERT", "UPDATE", "DELETE", "REPLACE", "CREATE", "DROP",
            "ALTER", "PRAGMA", "ATTACH", "DETACH",
            "BEGIN IMMEDIATE", "SAVEPOINT", "RELEASE",
        )
        for statement in normalized:
            self.assertTrue(
                statement.startswith(("SELECT", "BEGIN", "ROLLBACK")),
                f"impact issued a non-read statement: {statement}",
            )
            self.assertFalse(
                statement.startswith(write_prefixes),
                f"impact must stay read-only: {statement}",
            )
        # Every self-opened snapshot is rolled back, never committed: one
        # begin/rollback pair per query, regardless of mode.
        self.assertNotIn("COMMIT", normalized)
        self.assertEqual(normalized.count("BEGIN"), normalized.count("ROLLBACK"))
        self.assertEqual(normalized.count("BEGIN"), 3)
        self.assertFalse(self.connection.in_transaction)

        self.assertEqual({record_outline(r) for r in directory_records}, OLD_OUTLINE)
        self.assertEqual({record_outline(r) for r in service_records}, OLD_OUTLINE)
        self.assertEqual(
            [record_outline(r) for r in identity_records],
            [("web", False, CVE, ("web", "lib"))],
        )

    def test_version_error_names_component_and_leaves_a_usable_catalog(self) -> None:
        # A second, healthy service proves a failed directory-wide read does
        # not leave read state that blocks later operations on the instance.
        self.catalog.add_component(OTHER_SERVICE, "pypi", "redis", "7.0.0")
        self.catalog.add_component(SERVICE, "pypi", "lib", "not-a-version")

        with self.assertRaises(ValueError) as caught:
            self.catalog.impact()
        message = str(caught.exception)
        self.assertIn("版本无法解析", message)
        self.assertIn("api/pypi/lib/not-a-version", message)
        # No half-open snapshot transaction is left behind.
        self.assertFalse(self.connection.in_transaction)

        # The other service's illegal version neither fails nor enters the
        # selected service's graph, and that successful read also releases.
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
        # The same connection still accepts writes after the failed reads.
        self.catalog.add_component(OTHER_SERVICE, "pypi", "queue", "4.0.0")
        self.assertFalse(self.connection.in_transaction)

    def test_bad_version_in_selected_service_still_raises_and_releases(self) -> None:
        self.catalog.add_component(OTHER_SERVICE, "pypi", "lib", "not-a-version")
        # api is healthy and must answer; worker's own bad version errors.
        self.assertEqual(
            {record_outline(r) for r in self.catalog.impact(service=SERVICE)},
            OLD_OUTLINE,
        )
        with self.assertRaises(ValueError) as caught:
            self.catalog.impact(service=OTHER_SERVICE)
        self.assertIn(
            "worker/pypi/lib/not-a-version", str(caught.exception)
        )
        self.assertFalse(self.connection.in_transaction)

    def test_cli_version_error_is_nonzero_with_no_partial_impact(self) -> None:
        # A file database so each main() call opens a fresh Catalog, like a
        # separate CLI invocation.
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            failing = Catalog(database)
            failing.import_sbom(SERVICE, SOURCE, src_manifest())
            failing.import_osv(OSV_SOURCE, lib_high_records())
            failing.add_component(SERVICE, "pypi", "lib", "not-a-version")
            failing.close()

            for argv in (
                ["--database", database, "impact"],
                ["--database", database, "impact", "--service", SERVICE],
                ["--database", database, "impact", "--service", SERVICE,
                 "--ecosystem", "pypi", "--name", "web", "--version", "2.0.0"],
            ):
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), \
                        contextlib.redirect_stderr(stderr):
                    status = main(argv)
                self.assertEqual(status, 1, argv)
                # Not a single record of a half-built result reaches stdout.
                self.assertEqual(stdout.getvalue(), "", argv)
                self.assertIn("版本无法解析", stderr.getvalue(), argv)
                self.assertIn("api/pypi/lib/not-a-version", stderr.getvalue(), argv)

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
            reopened.close()


if __name__ == "__main__":
    unittest.main()
