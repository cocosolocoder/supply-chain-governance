"""Regression tests for manual dependency revocation racing another terminal.

The bug: ``remove_dependency`` resolved the two endpoint row ids and the
relationship row id *before* opening its write transaction and then wrote
against those remembered ids (``UPDATE dependencies ... WHERE id = ?`` plus a
retention cleanup scoped to the two endpoint ids). If another terminal
revoked the very same relationship in that gap, the retention cleanup
deleted its rows and freed their ids; a subsequent manual registration of a
*different* relationship could then create components and an edge that
reuse those ids. When the still-open removal reached its save phase it
silently revoked the new relationship and deleted the new endpoints - an
unrelated dependency path vanished and, with it, the new library version's
vulnerability propagation to the new application version.

The contract is that revoking a relationship is equivalent to one strict
serial order against every other writer, and that the deletion can only ever
affect the exact relationship joining the two full identities the user named
(service, ecosystem, package name and version on both ends):

* another terminal completing the same deletion first and then registering a
  different relationship (different versions, another service, another pair
  of packages) must leave that new relationship fully registered - still
  manual, with both endpoints and its vulnerability propagation intact;
* a target or endpoint that has already disappeared when the deletion runs
  keeps the lenient success result and changes nothing, and never sweeps
  unrelated components;
* while any SBOM source still declares the relationship the revocation only
  clears the manual registration and the relationship stays; overlapping a
  concurrent source replacement yields the rule-consistent serial result;
* the existing save-failure rollback contract is unchanged: a database error
  during the save rolls the whole revocation back.

The races are made deterministic with SQLite progress handlers: the paused
transaction is held inside its write lock (or inside the exact locate window
the old implementation left unprotected), the other terminal is proven to
have committed or to be queued, and only then is the paused call released.
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
OTHER_SERVICE = "billing"
SOURCE = "build"
CVE = "CVE-2026-7001"

# The relationship the user asks to delete.
APP1 = (SERVICE, "pypi", "app", "1.0")
LIB1 = (SERVICE, "pypi", "lib", "1.0")
# The wholly different relationship another terminal registers meanwhile.
APP2 = (SERVICE, "pypi", "app", "2.0")
LIB2 = (SERVICE, "pypi", "lib", "2.0")
# A same-name component in another service: identity scoping must protect it.
BILLING_LIB = (OTHER_SERVICE, "pypi", "lib", "2.0")

REMOVE_OLD = (*APP1, *LIB1)
ADD_NEW = (*APP2, *LIB2)


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
NEW_MANIFEST = cdx([APP2, LIB2], [(APP2, LIB2)])
EMPTY_MANIFEST = cdx([], [])


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
    text starts with ``gate_prefix`` has begun: the transaction holds the
    write lock and its changes are uncommitted, so a second writer provably
    queues behind it. ``release()`` lets the statement finish and commit.
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
            if not gate_seen and statement.strip().startswith(self._gate_prefix):
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


def start_removal_paused_after_locate(database, *remove_args):
    """Run ``remove_dependency`` paused in its locate-to-save window.

    The removal has finished locating the target by reading the catalog but
    has not yet taken its write lock or written anything - the exact window in
    which another terminal can complete the same deletion and register a
    different relationship. The paused statement has already released its
    read lock, so the other terminal is free to commit meanwhile.

    The seam is chosen from the implementation under test so the regression
    runs unchanged against both the old and the fixed code: the fixed code
    locates through ``_dependency_edge`` (paused after its lock-free read);
    the old code located through two ``_component_id`` lookups (paused after
    the second - its following stale edge lookup and UPDATE are what
    misdelete the reused rows).
    """
    gate = threading.Event()
    may_finish = threading.Event()
    result: dict = {}
    statements: list[str] = []

    def run():
        catalog = Catalog(database)
        catalog.connection.set_trace_callback(statements.append)
        if hasattr(catalog, "_dependency_edge"):
            original_locate = catalog._dependency_edge
            calls = {"n": 0}

            def locate(*identity):
                row = original_locate(*identity)
                calls["n"] += 1
                if calls["n"] == 1 and row is not None:
                    gate.set()
                    may_finish.wait(timeout=10)
                return row

            catalog._dependency_edge = locate
        else:  # pragma: no cover - exercised only against the old code
            original_lookup = catalog._component_id
            calls = {"n": 0}

            def lookup(*identity):
                row = original_lookup(*identity)
                calls["n"] += 1
                if calls["n"] == 2:
                    gate.set()
                    may_finish.wait(timeout=10)
                return row

            catalog._component_id = lookup
        try:
            catalog.remove_dependency(*remove_args)
        except Exception as error:  # noqa: BLE001 - reported to the test
            result["error"] = error
        finally:
            catalog.connection.set_trace_callback(None)
            catalog.close()
            result["statements"] = [
                statement.strip() for statement in statements
            ]

    thread = threading.Thread(target=run)
    thread.start()
    gate.wait(timeout=10)
    return thread, may_finish, result


class RemoveDependencyReplacementRaceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name, "catalog.db"))
        # The old source once declared app 1.0 -> lib 1.0; the relationship was
        # then manually registered, and the source has since withdrawn. The
        # manual registration is therefore the sole anchor of the edge and its
        # two endpoints, so revoking it deletes exactly those three rows and
        # frees their ids - the precondition of the reported misdeletion.
        setup = Catalog(self.database)
        setup.import_sbom(SERVICE, SOURCE, OLD_MANIFEST)
        setup.add_dependency(*REMOVE_OLD)
        setup.import_sbom(SERVICE, SOURCE, EMPTY_MANIFEST)
        setup.add_vulnerability(CVE, "lib", "high")
        setup.close()

    def tearDown(self):
        self.directory.cleanup()

    def _open_with_old_components(self):
        catalog = Catalog(self.database)
        self.assertEqual(component_rows(catalog), {APP1: 0, LIB1: 0})
        self.assertEqual(dependency_rows(catalog), {(APP1, LIB1): 1})
        return catalog

    def _delete_old_then_register_new(self, catalog):
        """Another terminal's complete sequence during the locate window.

        1. finishes revoking app 1.0 -> lib 1.0 (edge and both endpoints
           leave, their row ids are freed);
        2. imports, manually registers and then loses the source for the
           different app 2.0 -> lib 2.0 relationship, whose rows reuse the
           just-freed ids.
        """
        catalog.remove_dependency(*REMOVE_OLD)
        catalog.import_sbom(SERVICE, SOURCE, NEW_MANIFEST)
        catalog.add_dependency(*ADD_NEW)
        catalog.import_sbom(SERVICE, SOURCE, EMPTY_MANIFEST)

    def test_deletion_completed_and_new_edge_registered_during_window(self):
        # Terminal A pauses inside the locate-to-save window.
        removal, may_finish, result = start_removal_paused_after_locate(
            self.database, *REMOVE_OLD
        )

        # Terminal B commits the same deletion and registers the different
        # relationship while A is still between locating and saving.
        intruder = Catalog(self.database)
        self._delete_old_then_register_new(intruder)
        intruder.close()

        # A now finishes. Under the fix it re-resolves under the write lock,
        # finds the named relationship gone, and changes nothing.
        may_finish.set()
        removal.join(timeout=10)
        self.assertFalse(removal.is_alive())
        self.assertNotIn("error", result)

        catalog = Catalog(self.database)
        # Only the new pair exists; the old rows did not drag it down with
        # them, and nothing unrelated was swept.
        self.assertEqual(component_rows(catalog), {APP2: 0, LIB2: 0})
        self.assertEqual(dependency_rows(catalog), {(APP2, LIB2): 1})

        # The new relationship still propagates lib 2.0's vulnerability to
        # app 2.0: the direct library hit and the indirect application hit
        # through app 2.0 -> lib 2.0.
        records = {
            (record["component"]["name"], record["component"]["version"]): record
            for record in catalog.impact(service=SERVICE)
        }
        self.assertEqual(set(records), {("app", "2.0"), ("lib", "2.0")})
        self.assertTrue(records[("lib", "2.0")]["direct"])
        indirect = records[("app", "2.0")]
        self.assertFalse(indirect["direct"])
        self.assertEqual(indirect["vulnerability"], CVE)
        self.assertEqual(
            [node["name"] for node in indirect["path"]], ["app", "lib"]
        )
        self.assertEqual(catalog.summary().affected_components, 2)
        report = catalog.risk_report(service=SERVICE)
        self.assertEqual(report["impact_count"], 2)
        self.assertEqual(report["unhandled_component_count"], 2)
        self.assertEqual(report["highest_severity"], "high")
        catalog.close()

    def test_target_vanishing_before_lock_is_lenient_and_writes_nothing(self):
        # Terminal B completes the deletion outright while A is in its locate
        # window. A then finds nothing and must succeed without writing
        # anything - its own traced statements prove no modification ran.
        thread, may_finish, result = start_removal_paused_after_locate(
            self.database, *REMOVE_OLD
        )

        winner = Catalog(self.database)
        winner.remove_dependency(*REMOVE_OLD)
        winner.close()

        may_finish.set()
        thread.join(timeout=10)
        self.assertFalse(thread.is_alive())
        self.assertNotIn("error", result)

        normalized = result["statements"]
        self.assertFalse(
            [
                statement
                for statement in normalized
                if statement.startswith(("UPDATE", "DELETE", "INSERT"))
            ],
            "a target that vanished before the save must not be written",
        )

        final = Catalog(self.database)
        self.assertEqual(component_rows(final), {})
        self.assertEqual(dependency_rows(final), {})
        self.assertEqual(final.impact(), [])
        self.assertEqual(final.summary().affected_components, 0)
        final.close()

    def test_concurrent_registration_queues_behind_the_revocation_lock(self):
        # Endpoints for a separate manual relationship must already exist
        # (creating them while the revocation holds the write lock would
        # itself queue); register them up front.
        prepared = Catalog(self.database)
        prepared.add_component(*APP2)
        prepared.add_component(*LIB2)
        prepared.close()

        # While the revocation holds the write lock mid-save, the different
        # registration cannot interleave.
        paused = PausedWrite(
            self.database,
            lambda catalog: catalog.remove_dependency(*REMOVE_OLD),
            "UPDATE dependencies",
        )
        paused.start()
        paused.wait_inside()

        thread, finished, result = background(
            self.database, lambda catalog: catalog.add_dependency(*ADD_NEW)
        )
        thread.join(timeout=0.5)
        self.assertTrue(
            thread.is_alive() and not finished.is_set(),
            "the concurrent registration must queue behind the revocation",
        )

        paused.release()
        finished.wait(timeout=10)
        thread.join(timeout=10)
        self.assertNotIn("error", result)

        catalog = Catalog(self.database)
        # The old edge and both of its solely-anchored endpoints left; the
        # separately registered edge and its endpoints are fully intact.
        self.assertEqual(component_rows(catalog), {APP2: 1, LIB2: 1})
        self.assertEqual(dependency_rows(catalog), {(APP2, LIB2): 1})
        catalog.close()

    def test_source_replacement_queuing_behind_revocation_is_rule_consistent(self):
        # The source still declares app 1.0 -> lib 1.0 when the revocation
        # starts; a concurrent source withdrawal (empty re-import) queues
        # behind the revocation lock. Serial result: the revocation first only
        # clears the manual flag (the edge stays, source-declared), and the
        # committed withdrawal then removes the edge and the endpoints.
        setup = Catalog(self.database)
        setup.import_sbom(SERVICE, SOURCE, OLD_MANIFEST)
        setup.add_dependency(*REMOVE_OLD)
        # Re-establish the source declaration that setUp had withdrawn.
        self.assertEqual(dependency_rows(setup), {(APP1, LIB1): 1})
        setup.close()

        paused = PausedWrite(
            self.database,
            lambda catalog: catalog.remove_dependency(*REMOVE_OLD),
            "UPDATE dependencies",
        )
        paused.start()
        paused.wait_inside()

        thread, finished, result = background(
            self.database,
            lambda catalog: catalog.import_sbom(SERVICE, SOURCE, EMPTY_MANIFEST),
        )
        thread.join(timeout=0.5)
        self.assertTrue(
            thread.is_alive() and not finished.is_set(),
            "the source replacement must queue behind the revocation",
        )

        paused.release()
        finished.wait(timeout=10)
        thread.join(timeout=10)
        self.assertNotIn("error", result)

        catalog = Catalog(self.database)
        # Manual revoked, source then withdrew: nothing keeps the edge or its
        # endpoints, so all three leave together.
        self.assertEqual(component_rows(catalog), {})
        self.assertEqual(dependency_rows(catalog), {})
        self.assertEqual(catalog.impact(service=SERVICE), [])
        catalog.close()

    def test_replacement_first_then_revocation_converges_on_retention_rule(self):
        # Opposite serial order: the source replacement commits first while
        # the revocation queues. Because the manual registration survives the
        # replacement, the edge and endpoints still exist for the queued
        # revocation, which then removes all three.
        setup = Catalog(self.database)
        setup.import_sbom(SERVICE, SOURCE, OLD_MANIFEST)
        setup.add_dependency(*REMOVE_OLD)
        setup.close()

        replacement = PausedWrite(
            self.database,
            lambda catalog: catalog.import_sbom(
                SERVICE, SOURCE, EMPTY_MANIFEST
            ),
            "DELETE FROM components WHERE",
        )
        replacement.start()
        replacement.wait_inside()

        thread, finished, result = background(
            self.database,
            lambda catalog: catalog.remove_dependency(*REMOVE_OLD),
        )
        thread.join(timeout=0.5)
        self.assertTrue(thread.is_alive() and not finished.is_set())

        replacement.release()
        finished.wait(timeout=10)
        thread.join(timeout=10)
        self.assertNotIn("error", result)

        catalog = Catalog(self.database)
        self.assertEqual(component_rows(catalog), {})
        self.assertEqual(dependency_rows(catalog), {})
        catalog.close()

    def test_revocation_keeps_edge_another_source_still_declares(self):
        # Even under the write-lock rewrite, the source-retention rule stands:
        # one remaining SBOM declaration keeps the relationship after the
        # manual registration is revoked.
        setup = Catalog(self.database)
        setup.import_sbom(SERVICE, SOURCE, OLD_MANIFEST)
        setup.import_sbom(SERVICE, "audit", OLD_MANIFEST)
        setup.add_dependency(*REMOVE_OLD)
        setup.close()

        catalog = Catalog(self.database)
        catalog.remove_dependency(*REMOVE_OLD)
        # The relationship stays (source-declared) and the impact keeps
        # flowing; only the manual basis was cleared.
        self.assertEqual(dependency_rows(catalog), {(APP1, LIB1): 0})
        records = catalog.impact(service=SERVICE)
        self.assertEqual(
            sorted(
                (record["component"]["name"], record["component"]["version"])
                for record in records
            ),
            [("app", "1.0"), ("lib", "1.0")],
        )
        # Withdrawing the last declaration is what finally removes the edge.
        catalog.import_sbom(SERVICE, "audit", EMPTY_MANIFEST)
        catalog.import_sbom(SERVICE, SOURCE, EMPTY_MANIFEST)
        self.assertEqual(dependency_rows(catalog), {})
        catalog.close()

    def test_other_service_same_name_component_is_never_touched(self):
        # A same-name/same-version library in another service exists alongside
        # the racy deletion. The other-service component is created first so it
        # holds a lower row id; the api old pair and the api new pair therefore
        # share the same higher ids, making the stale-id misdeletion possible
        # while still proving the deletion can never cross the service
        # boundary.
        directory = tempfile.TemporaryDirectory()
        database = str(Path(directory.name, "catalog.db"))
        try:
            seed = Catalog(database)
            seed.add_component(*BILLING_LIB)
            seed.import_sbom(SERVICE, SOURCE, OLD_MANIFEST)
            seed.add_dependency(*REMOVE_OLD)
            seed.import_sbom(SERVICE, SOURCE, EMPTY_MANIFEST)
            seed.close()

            thread, may_finish, result = start_removal_paused_after_locate(
                database, *REMOVE_OLD
            )
            intruder = Catalog(database)
            self._delete_old_then_register_new(intruder)
            intruder.close()
            may_finish.set()
            thread.join(timeout=10)
            self.assertNotIn("error", result)

            final = Catalog(database)
            # The new api pair survives intact and the billing library -
            # although it holds a lower row id - is completely untouched.
            self.assertEqual(
                component_rows(final), {APP2: 0, LIB2: 0, BILLING_LIB: 1}
            )
            self.assertEqual(dependency_rows(final), {(APP2, LIB2): 1})
            final.close()
        finally:
            directory.cleanup()

    def test_cli_succeeds_when_target_disappeared_concurrently(self):
        # The lenient no-op path must keep the CLI contract: exit 0 and the
        # success line even though another terminal completed the deletion.
        winner = Catalog(self.database)
        winner.remove_dependency(*REMOVE_OLD)
        winner.close()

        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = main(["--database", self.database, "remove-dependency", *REMOVE_OLD])
        self.assertEqual(status, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("dependency removed", stdout.getvalue())

        catalog = Catalog(self.database)
        self.assertEqual(component_rows(catalog), {})
        self.assertEqual(dependency_rows(catalog), {})
        catalog.close()


if __name__ == "__main__":
    unittest.main()
