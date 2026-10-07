"""Regression tests for manual dependency revocation racing other writers.

The bug: ``remove_dependency`` resolved the endpoint and relationship row
ids first and only then opened a transaction to revoke the manual
registration. If another process removed the same relationship in that gap
(deleting the old component and edge rows) and then registered a *different*
relationship whose rows reused the freed ids, the in-flight revocation wrote
against the stale ids: it cleared the manual flag of the new, unrelated
relationship and swept its endpoints through the cleanup rule, silently
breaking vulnerability propagation along the new edge.

The contract under concurrency is that the revocation is equivalent to one
strict serial order against other writers:

* the revocation commits first: the target relationship and any endpoint
  that lost its last retention basis leave; a later registration of
  different components is unaffected;
* the other removal commits first: the revocation re-resolves the target by
  its full identity (service, ecosystem, name, version at both ends), finds
  it gone, and succeeds without changing anything - a relationship
  registered in between keeps its manual registration and both endpoints,
  and its vulnerability propagation is never interrupted;
* overlapping with a source replacement likewise yields the complete result
  of exactly one serial order of the two operations.

The races are made deterministic the same way as the add-dependency race
tests: the operation under test is paused at the exact window the old
implementation left open (after the target was located, before the write),
the competing operation is proven to commit in that window, and only then is
the paused operation released.
"""

import tempfile
import threading
import unittest
from pathlib import Path

from supply_guard.catalog import Catalog

SERVICE = "api"
SOURCE = "build"
CVE = "CVE-2026-7001"

APP1 = (SERVICE, "pypi", "app", "1.0.0")
LIB1 = (SERVICE, "pypi", "lib", "1.0.0")
APP2 = (SERVICE, "pypi", "app", "2.0.0")
LIB2 = (SERVICE, "pypi", "lib", "2.0.0")

OLD_EDGE_ARGS = APP1 + LIB1
NEW_EDGE_ARGS = APP2 + LIB2


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


class RemoveDependencyReregisterRaceTests(unittest.TestCase):
    """The exact reported scenario: revoking app 1.0 -> lib 1.0 while another
    terminal deletes that same relationship first and then registers the
    different app 2.0 -> lib 2.0 relationship. The new relationship must
    survive the stale revocation completely, manual flag included, and keep
    propagating the library's vulnerability to the application."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name, "catalog.db"))
        setup = Catalog(self.database)
        setup.import_sbom(SERVICE, SOURCE, OLD_MANIFEST)
        setup.add_dependency(*OLD_EDGE_ARGS)
        # The source withdraws: the manual registration is the sole anchor
        # of the old edge and its two endpoints.
        setup.import_sbom(SERVICE, SOURCE, cdx([]))
        # One manually registered vulnerability hits every "lib" version.
        setup.add_vulnerability(CVE, "lib", "high")
        setup.close()

    def tearDown(self):
        self.directory.cleanup()

    def _assert_new_relationship_intact(self, catalog):
        # Only the new components remain, with their manual registrations.
        self.assertEqual(component_rows(catalog), {APP2: 1, LIB2: 1})
        # The new relationship kept its manual registration; the stale
        # revocation neither cleared it nor deleted the edge.
        self.assertEqual(dependency_rows(catalog), {(APP2, LIB2): 1})
        # The vulnerability still propagates along the new edge: lib 2.0.0
        # is hit directly, app 2.0.0 indirectly through app -> lib.
        records = {
            (record["component"]["name"], record["component"]["version"]): record
            for record in catalog.impact(service=SERVICE)
        }
        self.assertEqual(set(records), {("app", "2.0.0"), ("lib", "2.0.0")})
        self.assertTrue(records[("lib", "2.0.0")]["direct"])
        indirect = records[("app", "2.0.0")]
        self.assertFalse(indirect["direct"])
        self.assertEqual(indirect["vulnerability"], CVE)
        self.assertEqual(
            [node["name"] for node in indirect["path"]], ["app", "lib"]
        )
        summary = catalog.summary()
        self.assertEqual(
            (
                summary.components,
                summary.affected_components,
                summary.vulnerabilities,
                summary.highest_severity,
            ),
            (2, 2, 1, "high"),
        )
        report = catalog.risk_report(service=SERVICE)
        self.assertEqual(report["impact_count"], 2)
        self.assertEqual(report["unhandled_component_count"], 2)
        self.assertEqual(report["highest_severity"], "high")

    def test_stale_revocation_never_lands_on_the_new_relationship(self):
        # The revocation locates its target and pauses at the exact window
        # the old implementation left open: after the row ids were resolved,
        # before the write. The competing terminal then completes the same
        # removal (freeing the old rows) and registers the new relationship,
        # whose rows reuse the freed ids.
        target_located = threading.Event()
        may_finish = threading.Event()

        def paused_revocation(database):
            catalog = Catalog(database)
            original_lookup = catalog._component_id
            resolved = []

            def lookup_then_pause(*identity):
                component_id = original_lookup(*identity)
                resolved.append(component_id)
                if len(resolved) == 2:
                    # Both endpoint ids resolved; pause before the write.
                    target_located.set()
                    may_finish.wait(timeout=10)
                return component_id

            catalog._component_id = lookup_then_pause
            try:
                catalog.remove_dependency(*OLD_EDGE_ARGS)
            finally:
                catalog.close()

        revocation = threading.Thread(
            target=paused_revocation, args=(self.database,)
        )
        revocation.start()
        self.assertTrue(target_located.wait(timeout=10))

        # The other terminal: same removal commits first, then the new
        # components and their relationship are registered. SQLite reuses
        # the row ids freed by the deletion.
        intruder_thread, intruder_finished, intruder_result = background(
            self.database,
            lambda catalog: (
                catalog.remove_dependency(*OLD_EDGE_ARGS),
                catalog.add_component(*APP2),
                catalog.add_component(*LIB2),
                catalog.add_dependency(*NEW_EDGE_ARGS),
            ),
        )
        intruder_finished.wait(timeout=10)
        intruder_thread.join(timeout=10)
        self.assertNotIn("error", intruder_result)

        may_finish.set()
        revocation.join(timeout=10)
        self.assertFalse(revocation.is_alive())

        catalog = Catalog(self.database)
        self._assert_new_relationship_intact(catalog)
        catalog.close()

        # Durable: a reopened database shows the same intact state.
        reopened = Catalog(self.database)
        self._assert_new_relationship_intact(reopened)
        reopened.close()

    def test_sequential_repeat_of_the_same_scenario(self):
        # The same contract without threads: once the old relationship is
        # gone and a different one registered, repeating the old revocation
        # is a lenient no-op that leaves the new relationship untouched.
        catalog = Catalog(self.database)
        catalog.remove_dependency(*OLD_EDGE_ARGS)
        catalog.add_component(*APP2)
        catalog.add_component(*LIB2)
        catalog.add_dependency(*NEW_EDGE_ARGS)

        catalog.remove_dependency(*OLD_EDGE_ARGS)
        self._assert_new_relationship_intact(catalog)
        catalog.close()


class RemoveDependencySourceReplacementRaceTests(unittest.TestCase):
    """A revocation overlapping a source replacement yields the complete
    result of exactly one serial order of the two operations."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name, "catalog.db"))
        setup = Catalog(self.database)
        setup.import_sbom(SERVICE, SOURCE, OLD_MANIFEST)
        setup.add_dependency(*OLD_EDGE_ARGS)
        setup.add_vulnerability(CVE, "lib", "high")
        setup.close()

    def tearDown(self):
        self.directory.cleanup()

    def test_revocation_first_then_replacement(self):
        # The revocation is paused inside its write lock after the manual
        # flag was cleared (uncommitted); the replacement queues behind it.
        revocation_inside = threading.Event()
        revocation_may_finish = threading.Event()
        revocation_done = threading.Event()

        def paused_revocation(database):
            catalog = Catalog(database)

            def trace(statement):
                if statement.strip().startswith("UPDATE dependencies"):
                    revocation_inside.set()

            def progress():
                if revocation_inside.is_set():
                    revocation_may_finish.wait(timeout=10)
                return 0

            catalog.connection.set_trace_callback(trace)
            catalog.connection.set_progress_handler(progress, 1)
            try:
                catalog.remove_dependency(*OLD_EDGE_ARGS)
            finally:
                catalog.connection.set_progress_handler(None, 0)
                catalog.connection.set_trace_callback(None)
                catalog.close()
                revocation_done.set()

        revocation = threading.Thread(
            target=paused_revocation, args=(self.database,)
        )
        revocation.start()
        self.assertTrue(revocation_inside.wait(timeout=10))

        # The replacement withdraws the library and the edge, keeping only
        # the application. It must queue behind the held write lock.
        replacement_thread, replacement_finished, replacement_result = background(
            self.database,
            lambda catalog: catalog.import_sbom(
                SERVICE, SOURCE, cdx([APP1])
            ),
        )
        replacement_thread.join(timeout=0.5)
        self.assertTrue(
            replacement_thread.is_alive() and not replacement_finished.is_set(),
            "the replacement should be queued behind the held write lock",
        )

        revocation_may_finish.set()
        revocation_done.wait(timeout=10)
        revocation.join(timeout=10)
        replacement_finished.wait(timeout=10)
        replacement_thread.join(timeout=10)

        # Serial order revocation-first: the edge survived the revocation
        # (still source-declared at that moment), so the replacement's own
        # withdrawal is what removes it and the library. The application,
        # still declared by the source, stays.
        result = replacement_result.get("value")
        self.assertIsNotNone(result, replacement_result.get("error"))
        self.assertEqual(result.deleted_components, 1)
        self.assertEqual(result.deleted_dependencies, 1)

        catalog = Catalog(self.database)
        self.assertEqual(component_rows(catalog), {APP1: 0})
        self.assertEqual(dependency_rows(catalog), {})
        # No stale propagation path survives: nothing is affected anymore.
        self.assertEqual(catalog.impact(service=SERVICE), [])
        summary = catalog.summary()
        self.assertEqual(summary.affected_components, 0)
        self.assertIsNone(summary.highest_severity)
        catalog.close()


if __name__ == "__main__":
    unittest.main()
