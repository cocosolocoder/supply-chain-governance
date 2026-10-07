"""Regression tests for manual dependency registration racing source replacement.

The bug: ``add_dependency`` resolved the two endpoint row ids first and only
then opened a transaction to insert the relationship. The endpoints may be
provided solely by imported manifests. If another process replaced the
owning source in that gap - withdrawing ownership, deleting the old
component rows, and importing different components that reuse the same row
ids - the registration attached the edge to the freshly imported, unrelated
components, or surfaced a raw foreign-key database error.

The contract under concurrency is that the two operations are equivalent to
one strict serial order:

* registration commits first: the edge belongs to the exact two identities
  the user named; a later source withdrawal still keeps that manual edge and
  anchors both endpoints under the existing retention rule;
* replacement commits first and removes a named endpoint: registration
  fails with a clear naming of which endpoint (and its full identity) is
  missing, changes nothing, and the completed replacement keeps its normal
  result - in particular a different version of the same package, a
  component in another service or a wholly unrelated component that happens
  to reuse the old row id can never stand in for the named object;
* replacement commits first but both named identities survive: registration
  still succeeds.

The races here are made deterministic with SQLite progress handlers: the
winning transaction is paused inside its write lock (after the relevant
statement started, before commit), the losing operation is proven to be
blocked waiting for the write lock, and only then is the winner released.
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
SOURCE = "build"
CVE = "CVE-2026-7001"

APP1 = (SERVICE, "pypi", "app", "1.0.0")
LIB1 = (SERVICE, "pypi", "libone", "1.0.0")
APP2 = (SERVICE, "pypi", "app", "2.0.0")
LIB2 = (SERVICE, "pypi", "libtwo", "2.0.0")

APP1_ARGS = (*APP1, *LIB1)


def cdx(components, dependencies=None):
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"bom-ref": f"{name}-{version}", "purl": f"pkg:pypi/{name}@{version}"}
            for _, _, name, version in components
        ],
    }
    if dependencies is not None:
        document["dependencies"] = [
            {
                "ref": f"{dep_name}-{dep_version}",
                "dependsOn": [f"{lib_name}-{lib_version}"],
            }
            for (_, _, dep_name, dep_version), (_, _, lib_name, lib_version)
            in dependencies
        ]
    return document


OLD_MANIFEST = cdx([APP1, LIB1], [(APP1, LIB1)])
# Wholly different components (other versions, other package names); the new
# rows reuse the row ids freed by the deleted old ones.
NEW_MANIFEST = cdx([APP2, LIB2], [(APP2, LIB2)])
# Keeps the application but replaces the library: only one endpoint vanishes.
NEW_MANIFEST_KEEPS_APP = cdx([APP1, LIB2], [(APP1, LIB2)])
# Same two identities as the old manifest; nothing named disappears.
SAME_IDENTITY_MANIFEST = cdx([APP1, LIB1], [(APP1, LIB1)])


def component_rows(catalog):
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


def dependency_rows(catalog):
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


class PausedWrite:
    """Run ``action`` on a Catalog in a thread, paused inside the write lock.

    The progress handler blocks the connection once a traced statement whose
    text starts with ``gate_prefix`` has begun executing: the transaction
    holds the write lock and its changes are not yet committed, so a second
    connection trying ``BEGIN IMMEDIATE`` provably queues behind it.
    ``release()`` lets the statement finish and the transaction commit.
    """

    def __init__(self, database, action, gate_prefix):
        self._database = database
        self._action = action
        self._gate_prefix = gate_prefix
        self.inside_statement = threading.Event()
        self._may_finish = threading.Event()
        self.finished = threading.Event()
        self.result = {}
        self._thread = threading.Thread(target=self._run)

    def start(self):
        self._thread.start()

    def _run(self):
        catalog = Catalog(self._database)
        gate_seen = False

        def trace(statement):
            nonlocal gate_seen
            if (
                not gate_seen
                and statement.strip().startswith(self._gate_prefix)
            ):
                gate_seen = True
                self.inside_statement.set()

        def progress():
            if self.inside_statement.is_set():
                self._may_finish.wait(timeout=10)
            return 0

        catalog.connection.set_trace_callback(trace)
        catalog.connection.set_progress_handler(progress, 1)
        try:
            self.result["value"] = self._action(catalog)
        except Exception as error:  # noqa: BLE001 - reported to the test
            self.result["error"] = error
        finally:
            catalog.connection.set_progress_handler(None, 0)
            catalog.connection.set_trace_callback(None)
            catalog.close()
            self.finished.set()

    def wait_inside(self):
        self.inside_statement.wait(timeout=10)
        # The statement is now executing under the held write lock.
        self._assert_alive()

    def release(self):
        self._may_finish.set()
        self.finished.wait(timeout=10)
        self._thread.join(timeout=10)
        self._assert_alive()

    def _assert_alive(self):
        if not self._thread.is_alive() and not self.finished.is_set():
            raise AssertionError("paused writer thread died unexpectedly")


def background(database, action):
    """Run ``action(Catalog)`` in a thread; reports start and completion."""
    started = threading.Event()
    finished = threading.Event()
    result = {}

    def run():
        catalog = Catalog(database)
        started.set()
        try:
            result["value"] = action(catalog)
        except Exception as error:  # noqa: BLE001 - reported to the test
            result["error"] = error
        finally:
            catalog.close()
            finished.set()

    thread = threading.Thread(target=run)
    thread.start()
    started.wait(timeout=10)
    return thread, finished, result


def blocking_registration(database, *args):
    """Run add_dependency in a thread; reports start/finish for block checks."""
    return background(database, lambda catalog: catalog.add_dependency(*args))


class ManualDependencySourceReplacementRaceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name, "catalog.db"))
        setup = Catalog(self.database)
        setup.import_sbom(SERVICE, SOURCE, OLD_MANIFEST)
        setup.add_vulnerability(CVE, "libone", "high")
        setup.close()

    def tearDown(self):
        self.directory.cleanup()

    def _assert_registrar_blocked(self, thread, finished):
        # The queued writer holds no lock and cannot make progress: after a
        # short delay its call still has not returned.
        thread.join(timeout=0.5)
        self.assertTrue(
            thread.is_alive() and not finished.is_set(),
            "the second writer should be queued behind the held write lock",
        )

    def _assert_only_old_edge_is_manual(self, catalog):
        self.assertEqual(component_rows(catalog), {
            APP1: 0,
            LIB1: 0,
            APP2: 0,
            LIB2: 0,
        })
        self.assertEqual(dependency_rows(catalog), {
            # The user's registration belongs to the original two identities,
            # and only to them.
            (APP1, LIB1): 1,
            # The imported replacement edge stays purely source-declared: the
            # registration neither marked it manual nor created any edge
            # touching app 2.0.0 / libtwo 2.0.0.
            (APP2, LIB2): 0,
        })

    def test_replacement_reuses_rowids_during_gap_without_write_lock(self):
        # The reported misattachment scenario, reproduced at the exact window
        # of the old implementation: "after confirming the endpoints exist,
        # before saving the relationship". Registration resolves both endpoint
        # row ids and pauses there. Another process then withdraws the source
        # (deleting the named endpoints) and imports different components as a
        # separate commit; SQLite reuses the freed row ids. Registration
        # resumes and writes against the stale ids.
        #
        # The fixed registration resolves the identities inside its write
        # transaction, so the replacement provably cannot run in that window:
        # it queues on the write lock, registration finishes against the exact
        # named identities, and only then does the replacement commit second.
        gate = threading.Event()
        may_finish = threading.Event()

        def stale_window_registration(database):
            catalog = Catalog(database)
            resolved = []
            original_lookup = catalog._component_id

            def lookup_then_pause(*identity):
                component_id = original_lookup(*identity)
                resolved.append(component_id)
                if len(resolved) == 2:
                    gate.set()
                    may_finish.wait(timeout=10)
                return component_id

            catalog._component_id = lookup_then_pause
            try:
                catalog.add_dependency(*APP1_ARGS)
            finally:
                catalog.close()

        registration = threading.Thread(target=stale_window_registration, args=(self.database,))
        registration.start()
        gate.wait(timeout=10)

        # While registration is paused between endpoint confirmation and save,
        # a different process clears the source and imports other components
        # that reuse the freed row ids.
        intruder_thread, intruder_finished, intruder_result = background(
            self.database,
            lambda catalog: (
                catalog.import_sbom(SERVICE, SOURCE, cdx([])),
                catalog.import_sbom(SERVICE, SOURCE, NEW_MANIFEST),
            )[1],
        )
        # Old behavior: registration holds no lock in this window, so the
        # replacement commits here. Fixed behavior: the write lock is already
        # held, so the intruder is still queued.
        intruder_thread.join(timeout=0.5)
        intruder_completed_while_paused = intruder_finished.is_set()

        may_finish.set()
        registration.join(timeout=10)
        self.assertFalse(registration.is_alive())
        intruder_finished.wait(timeout=10)
        intruder_thread.join(timeout=10)

        catalog = Catalog(self.database)
        if intruder_completed_while_paused:
            # Old, racy behavior: the stale ids were reused and the manual
            # edge was attached to the imported strangers. This branch exists
            # only to make the failure mode legible; the fixed code never
            # reaches it.
            state = dependency_rows(catalog)
            catalog.close()
            self.fail(
                "source replacement committed while registration held stale "
                "endpoint ids; edge state: " + repr(state)
            )
        # Serial order registration-first: the intruder only committed after
        # the edge was saved, so it reports success and the manual edge
        # anchors the original endpoints; new components arrive without
        # receiving any manual basis.
        self.assertIn("value", intruder_result)
        self._assert_only_old_edge_is_manual(catalog)
        catalog.close()

    def test_registration_first_then_replacement_keeps_edge_on_old_identities(self):
        # Winner: registration, paused after its INSERT (write lock held,
        # uncommitted). The replacement queues behind it and commits second.
        registration = PausedWrite(
            self.database, lambda catalog: catalog.add_dependency(*APP1_ARGS),
            "INSERT INTO dependencies",
        )
        registration.start()
        registration.wait_inside()

        replacement = PausedWrite(
            self.database, lambda catalog: catalog.import_sbom(
                SERVICE, SOURCE, NEW_MANIFEST
            ),
            "DELETE FROM components WHERE",
        )
        replacement.start()
        # No event can fire while the replacement waits for the lock.
        replacement._thread.join(timeout=0.5)
        self.assertTrue(replacement._thread.is_alive())

        registration.release()
        replacement.wait_inside()
        replacement.release()

        self.assertIn("value", registration.result)
        # Old endpoints survive because the manual edge anchors them; the new
        # components arrive; nothing is deleted.
        self.assertEqual(
            replacement.result["value"].deleted_components, 0
        )
        self.assertEqual(
            replacement.result["value"].added_components, 2
        )

        catalog = Catalog(self.database)
        self._assert_only_old_edge_is_manual(catalog)

        # Impact follows the manual edge between the original components and
        # never spreads to the replacement components that reuse the old row
        # ids: libone is hit directly, app 1.0.0 indirectly, app 2.0.0 and
        # libtwo are not affected at all.
        records = {
            (record["component"]["name"], record["component"]["version"]): record
            for record in catalog.impact(service=SERVICE)
        }
        self.assertEqual(set(records), {("app", "1.0.0"), ("libone", "1.0.0")})
        self.assertTrue(records[("libone", "1.0.0")]["direct"])
        self.assertEqual(
            [node["name"] for node in records[("app", "1.0.0")]["path"]],
            ["app", "libone"],
        )
        self.assertEqual(catalog.summary().affected_components, 2)
        report = catalog.risk_report(service=SERVICE)
        reported = {
            (entry["component"]["name"], entry["component"]["version"])
            for entry in report["impacts"]
        }
        self.assertEqual(reported, {("app", "1.0.0"), ("libone", "1.0.0")})
        catalog.close()

    def test_replacement_first_removing_both_endpoints_is_rejected(self):
        # Winner: replacement, paused during retention (old rows about to be
        # deleted, new rows about to survive, all uncommitted). Registration
        # queues and only resolves the identities after seeing this commit.
        replacement = PausedWrite(
            self.database,
            lambda catalog: catalog.import_sbom(SERVICE, SOURCE, NEW_MANIFEST),
            "DELETE FROM components WHERE",
        )
        replacement.start()
        replacement.wait_inside()

        thread, finished, result = blocking_registration(self.database, *APP1_ARGS)
        self._assert_registrar_blocked(thread, finished)

        replacement.release()
        finished.wait(timeout=10)
        thread.join(timeout=10)

        error = result.get("error")
        self.assertIsInstance(error, ValueError)
        message = str(error)
        # Both named endpoints are gone, and each is named with its full
        # identity; no raw database error leaks out.
        self.assertIn(
            "dependent component is not registered: api/pypi/app/1.0.0", message
        )
        self.assertIn(
            "dependency component is not registered: api/pypi/libone/1.0.0",
            message,
        )

        # The completed replacement keeps its normal result...
        self.assertEqual(replacement.result["value"].added_components, 2)
        self.assertEqual(replacement.result["value"].deleted_components, 2)
        catalog = Catalog(self.database)
        self.assertEqual(component_rows(catalog), {APP2: 0, LIB2: 0})
        # ...and the failed registration added no manual basis of any kind to
        # the replacement components, even though their rows reuse the old ids.
        self.assertEqual(dependency_rows(catalog), {(APP2, LIB2): 0})
        owners = {
            (str(row["service"]), str(row["ecosystem"]), str(row["name"]))
            for row in catalog.connection.execute(
                """
                SELECT c.service, c.ecosystem, c.name
                FROM component_sources cs JOIN components c ON c.id = cs.component_id
                """
            )
        }
        self.assertEqual(owners, {
            (SERVICE, "pypi", "app"),
            (SERVICE, "pypi", "libtwo"),
        })
        self.assertEqual(catalog.summary().affected_components, 0)
        catalog.close()

    def test_replacement_first_removing_one_endpoint_names_that_endpoint(self):
        replacement = PausedWrite(
            self.database,
            lambda catalog: catalog.import_sbom(
                SERVICE, SOURCE, NEW_MANIFEST_KEEPS_APP
            ),
            "DELETE FROM components WHERE",
        )
        replacement.start()
        replacement.wait_inside()

        thread, finished, result = blocking_registration(self.database, *APP1_ARGS)
        self._assert_registrar_blocked(thread, finished)

        replacement.release()
        finished.wait(timeout=10)
        thread.join(timeout=10)

        error = result.get("error")
        self.assertIsInstance(error, ValueError)
        message = str(error)
        # The application identity survives, so only the missing library is
        # reported, with its full identity.
        self.assertNotIn("dependent component is not registered", message)
        self.assertIn(
            "dependency component is not registered: api/pypi/libone/1.0.0",
            message,
        )
        catalog = Catalog(self.database)
        self.assertEqual(component_rows(catalog), {APP1: 0, LIB2: 0})
        # No manual edge leaked onto the surviving application or the imported
        # edge app 1.0.0 -> libtwo 2.0.0.
        self.assertEqual(dependency_rows(catalog), {(APP1, LIB2): 0})
        catalog.close()

    def test_replacement_first_but_identities_survive_still_registers(self):
        replacement = PausedWrite(
            self.database,
            lambda catalog: catalog.import_sbom(
                SERVICE, SOURCE, SAME_IDENTITY_MANIFEST
            ),
            "DELETE FROM components WHERE",
        )
        replacement.start()
        replacement.wait_inside()

        thread, finished, result = blocking_registration(self.database, *APP1_ARGS)
        self._assert_registrar_blocked(thread, finished)

        replacement.release()
        finished.wait(timeout=10)
        thread.join(timeout=10)

        self.assertIsNone(result.get("error"))
        catalog = Catalog(self.database)
        # The one edge stays unique and now carries both bases: the source
        # declaration and the manual registration.
        self.assertEqual(dependency_rows(catalog), {(APP1, LIB1): 1})
        source_declared = catalog.connection.execute(
            """
            SELECT COUNT(*) AS n FROM dependency_sources ds
            JOIN dependencies d ON d.id = ds.dependency_id
            JOIN components c1 ON c1.id = d.dependent_id
            JOIN components c2 ON c2.id = d.dependency_id
            WHERE c1.name = 'app' AND c2.name = 'libone'
            """
        ).fetchone()["n"]
        self.assertEqual(source_declared, 1)
        catalog.close()


class ManualDependencySequentialTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name, "catalog.db"))

    def tearDown(self):
        self.directory.cleanup()

    def test_imported_endpoints_register_without_manual_component_entries(self):
        catalog = Catalog(self.database)
        catalog.import_sbom(SERVICE, SOURCE, OLD_MANIFEST)
        # Neither endpoint was manually registered; the cataloged components
        # are already sufficient.
        catalog.add_dependency(*APP1_ARGS)
        # A repeat adds a manual basis without creating a second edge.
        catalog.add_dependency(*APP1_ARGS)
        self.assertEqual(dependency_rows(catalog), {(APP1, LIB1): 1})
        edges = catalog.connection.execute(
            "SELECT COUNT(*) AS n FROM dependencies"
        ).fetchone()["n"]
        self.assertEqual(edges, 1)
        catalog.close()

    def test_later_source_withdrawal_keeps_manual_edge_and_both_endpoints(self):
        catalog = Catalog(self.database)
        catalog.import_sbom(SERVICE, SOURCE, OLD_MANIFEST)
        catalog.add_dependency(*APP1_ARGS)
        result = catalog.import_sbom(SERVICE, SOURCE, cdx([]))
        self.assertEqual(result.deleted_components, 0)
        self.assertEqual(result.deleted_dependencies, 0)
        self.assertEqual(component_rows(catalog), {APP1: 0, LIB1: 0})
        self.assertEqual(dependency_rows(catalog), {(APP1, LIB1): 1})
        catalog.close()

    def test_validation_rules_are_unchanged(self):
        catalog = Catalog(self.database)
        catalog.import_sbom(SERVICE, SOURCE, OLD_MANIFEST)
        catalog.import_sbom("worker", SOURCE, cdx(
            [("worker", "pypi", "libone", "1.0.0")]
        ))
        with self.assertRaises(ValueError):
            catalog.add_dependency(*APP1, *APP1)
        with self.assertRaises(ValueError):
            catalog.add_dependency(
                SERVICE, "pypi", "app", "1.0.0",
                "worker", "pypi", "libone", "1.0.0",
            )
        with self.assertRaises(ValueError):
            catalog.add_dependency(
                SERVICE, "pypi", "app", " ",
                SERVICE, "pypi", "libone", "1.0.0",
            )
        catalog.close()

    def test_cli_fails_nonzero_without_success_line_when_endpoint_missing(self):
        catalog = Catalog(self.database)
        catalog.import_sbom(SERVICE, SOURCE, OLD_MANIFEST)
        # Replacement removes both named identities and imports others.
        catalog.import_sbom(SERVICE, SOURCE, NEW_MANIFEST)
        catalog.close()

        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = main([
                "--database", self.database, "add-dependency",
                *APP1, *LIB1,
            ])
        self.assertEqual(status, 1)
        self.assertNotIn("dependency recorded", stdout.getvalue())
        error_text = stderr.getvalue()
        self.assertIn("api/pypi/app/1.0.0", error_text)
        self.assertIn("api/pypi/libone/1.0.0", error_text)

        # A registration whose identities survived still succeeds on the CLI.
        catalog = Catalog(self.database)
        catalog.import_sbom(
            SERVICE, SOURCE,
            cdx([APP1, LIB1, APP2, LIB2], [(APP1, LIB1), (APP2, LIB2)]),
        )
        catalog.close()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main([
                "--database", self.database, "add-dependency",
                *APP2, *LIB2,
            ])
        self.assertEqual(status, 0)
        self.assertIn("dependency recorded", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
