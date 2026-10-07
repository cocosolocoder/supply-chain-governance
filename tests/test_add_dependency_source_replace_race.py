"""Regression tests for a manual dependency registration racing a source
replacement.

``add_dependency`` registers "the first component depends on the second" and
locates both ends by the full identity (service, ecosystem, package name and
version). The ends need not be manually registered components: an endpoint is
usable as soon as it is in the catalog, including when an imported SBOM
manifest is the only thing providing it.

The endpoint existence check and the relationship insert used to run as two
separate autocommit statements, with no transaction covering both. Another
process replacing an SBOM source in that gap could therefore:

1. withdraw the source declaring the two components, deleting the very
   endpoints the registration had just resolved;
2. import other components into the catalog.

The registration then finished against a state the user never named:

* when SQLite reused a deleted endpoint's rowid for a newly imported
  component, the relationship silently attached to that new component - a
  same-named other version, a component in another service, or a completely
  different component;
* when the rowids were merely left as a gap, the foreign-key constraint
  failed and the command surfaced a raw database error instead of reporting
  the missing endpoint.

The fix resolves both endpoints and saves the relationship inside one
serialized write transaction (``BEGIN IMMEDIATE``), so the registration and a
concurrent source replacement are linearized: the result is exactly as if one
operation finished first.

* Registration first: it commits a manual relationship between the original
  two components. A later source withdrawal follows the existing retention
  rules - the manual relationship and the endpoints it needs are kept.
* Replacement first: if either named endpoint disappeared, the registration
  fails with a ``ValueError`` that names the missing endpoint's role and full
  identity; the CLI exits non-zero and never prints a success line. Newly
  imported components (including ones that reused a deleted rowid) never
  receive the manual edge or a changed retention basis, and the committed
  replacement keeps its normal result.
* Replacement first but the named full identities still exist: the
  registration still succeeds, on the surviving identity rows.

These tests pin both orderings deterministically: one side holds the write
lock paused inside its transaction while the other side is proven to have
queued behind it, and only then is the holder released.
"""

import contextlib
import io
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from supply_guard.catalog import Catalog
from supply_guard.cli import main

SERVICE = "api"
OTHER_SERVICE = "billing"
SOURCE = "build"

# The two full identities the user names in the registration.
APP = (SERVICE, "pypi", "app", "1.0.0")
LIB = (SERVICE, "pypi", "lib", "1.0.0")
REGISTER_ARGS = APP + LIB

# Decoys that must never be mistaken for a named endpoint: the same package
# name in another version, and the same name/version in another service.
LIB_OTHER_VERSION = (SERVICE, "pypi", "lib", "2.0.0")
LIB_OTHER_SERVICE = (OTHER_SERVICE, "pypi", "lib", "1.0.0")
# A component with a completely different identity that the replacement
# imports after deleting the named endpoints.
NEW = (SERVICE, "pypi", "new", "9.0.0")

CVE = "CVE-2026-7100"


def cdx(components, dependencies=()):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"bom-ref": ref, "purl": purl} for ref, purl in components
        ],
        "dependencies": [
            {"ref": dependent, "dependsOn": [dependency]}
            for dependent, dependency in dependencies
        ],
    }


def manifest_app_to_lib():
    """The build source originally declares app 1.0.0 -> lib 1.0.0."""
    return cdx(
        [("build/app", "pkg:pypi/app@1.0.0"),
         ("build/lib", "pkg:pypi/lib@1.0.0")],
        [("build/app", "build/lib")],
    )


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


def component_owners(catalog):
    owners = {}
    for row in catalog.connection.execute(
        """
        SELECT c.service AS service, c.name AS name, c.version AS version,
               s.name AS source
        FROM component_sources cs
        JOIN components c ON c.id = cs.component_id
        JOIN sources s ON s.id = cs.source_id
        ORDER BY s.name
        """
    ):
        key = (str(row["service"]), str(row["name"]), str(row["version"]))
        owners.setdefault(key, []).append(str(row["source"]))
    return owners


def ids_by_identity(catalog):
    return {
        (
            str(row["service"]),
            str(row["ecosystem"]),
            str(row["name"]),
            str(row["version"]),
        ): int(row["id"])
        for row in catalog.connection.execute(
            "SELECT id, service, ecosystem, name, version FROM components"
        )
    }


class _PausedWorker:
    """Run one Catalog action on a background connection, paused at a SQL
    statement, while the write lock is held.

    The worker creates its own Catalog (SQLite connections are
    thread-affine), acquires the write lock as part of the action, and blocks
    on ``proceed`` immediately before the first statement matching
    ``predicate`` executes (tracing keeps running afterwards, so callers see
    every later statement too). The test thread can then start and queue a
    second action behind this lock before releasing it.
    """

    def __init__(self, database, run, predicate):
        self._database = database
        self._run = run
        self._predicate = predicate
        self.reached = threading.Event()
        self.proceed = threading.Event()
        self.finished = threading.Event()
        self.result = None
        self.error = None
        self.thread = threading.Thread(target=self._work)

    def _work(self):
        catalog = Catalog(self._database)
        armed = {"fired": False}

        def trace(statement):
            normalized = " ".join(statement.split())
            if not armed["fired"] and self._predicate(normalized):
                armed["fired"] = True
                self.reached.set()
                self.proceed.wait(30)

        catalog.connection.set_trace_callback(trace)
        try:
            self.result = self._run(catalog)
        except BaseException as exc:  # surfaced to the test via self.error
            self.error = exc
        finally:
            catalog.close()
            self.finished.set()

    def start_and_wait_paused(self):
        self.thread.start()
        if not self.reached.wait(30):
            self.proceed.set()
            self.thread.join(30)
            raise AssertionError("the pause point was never reached")
        return self

    def release(self):
        self.proceed.set()
        self.finished.wait(30)
        if self.thread.is_alive():
            raise AssertionError("the paused worker never finished")


class _QueuedRegistration:
    """A manual dependency registration on a background connection that has
    submitted its ``BEGIN IMMEDIATE`` and is therefore queued behind the
    write lock another connection holds.

    SQLite has a single writer, so while the holder keeps an immediate
    transaction open the second ``BEGIN IMMEDIATE`` blocks; the ``began``
    signal (traced when the statement starts executing, before the lock is
    granted) proves the registration is genuinely waiting in the race rather
    than merely having been scheduled late. Every statement stays recorded,
    including the rollback a failed registration ends with.
    """

    def __init__(self, database, args):
        self._database = database
        self._args = args
        self.began = threading.Event()
        self.finished = threading.Event()
        self.error = None
        self.statements = []
        self.thread = threading.Thread(target=self._work)

    def _work(self):
        catalog = Catalog(self._database)
        armed = {"fired": False}

        def trace(statement):
            normalized = " ".join(statement.split())
            self.statements.append(normalized)
            if not armed["fired"] and normalized.upper().startswith(
                "BEGIN IMMEDIATE"
            ):
                armed["fired"] = True
                self.began.set()

        catalog.connection.set_trace_callback(trace)
        try:
            catalog.add_dependency(*self._args)
        except BaseException as exc:
            self.error = exc
        finally:
            catalog.close()
            self.finished.set()

    def start_and_wait_queued(self):
        self.thread.start()
        if not self.began.wait(30):
            self.thread.join(30)
            raise AssertionError("the registration never queued on the lock")
        return self

    def wait(self):
        self.finished.wait(30)
        if self.thread.is_alive():
            raise AssertionError("the queued registration never finished")


class _QueuedReplacement:
    """A source replacement whose BEGIN IMMEDIATE has queued on the lock."""

    def __init__(self, database, document):
        self._database = database
        self._document = document
        self.began = threading.Event()
        self.finished = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self._work)

    def _work(self):
        catalog = Catalog(self._database)
        armed = {"fired": False}

        def trace(statement):
            normalized = " ".join(statement.split())
            # import_sbom runs in a lazily upgraded deferred transaction, so
            # it never issues BEGIN IMMEDIATE itself; the first write
            # (withdrawing the source's component ownership) is the point
            # where it queues behind the held write lock.
            if (
                not armed["fired"]
                and normalized.upper().startswith("DELETE FROM COMPONENT_SOURCES")
            ):
                armed["fired"] = True
                catalog.connection.set_trace_callback(None)
                self.began.set()

        catalog.connection.set_trace_callback(trace)
        try:
            catalog.import_sbom(SERVICE, SOURCE, self._document)
        except BaseException as exc:
            self.error = exc
        finally:
            catalog.close()
            self.finished.set()

    def start_and_wait_queued(self):
        self.thread.start()
        if not self.began.wait(30):
            self.thread.join(30)
            raise AssertionError("the replacement never queued on the lock")
        return self

    def wait(self):
        self.finished.wait(30)
        if self.thread.is_alive():
            raise AssertionError("the queued replacement never finished")


def build_raced_catalog(database, *, decoys=True):
    """app/lib declared only by the imported build source, plus decoys."""
    catalog = Catalog(database)
    catalog.import_sbom(SERVICE, SOURCE, manifest_app_to_lib())
    if decoys:
        catalog.add_component(*LIB_OTHER_VERSION)
        catalog.add_component(*LIB_OTHER_SERVICE)
    return catalog


def osv_record(package_name, version):
    return [
        {
            "id": CVE,
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": package_name},
                    "versions": [version],
                }
            ],
            "database_specific": {"severity": "high"},
        }
    ]


def join_thread(thread, label):
    thread.join(30)
    if thread.is_alive():
        raise AssertionError(f"{label} thread is still alive")


class RegistrationFirstTests(unittest.TestCase):
    """When the manual registration holds the lock first, it wins."""

    def test_manual_edge_between_original_components_survives_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            catalog = build_raced_catalog(database)
            original_ids = ids_by_identity(catalog)

            # The registration pauses holding the write lock, right before the
            # relationship insert.
            registration = _PausedWorker(
                database,
                lambda cat: cat.add_dependency(*REGISTER_ARGS),
                lambda sql: sql.upper().startswith("INSERT INTO DEPENDENCIES"),
            ).start_and_wait_paused()

            # The replacement submits its own BEGIN IMMEDIATE and queues
            # behind the registration.
            replacement = _QueuedReplacement(
                database, cdx([("build/new", "pkg:pypi/new@9.0.0")])
            ).start_and_wait_queued()

            # Release the registration first; it commits, then the queued
            # replacement runs against the state that already holds the
            # manual edge.
            registration.release()
            join_thread(registration.thread, "registration")
            self.assertIsNone(registration.error)
            replacement.wait()
            self.assertIsNone(replacement.error)

            # The relationship belongs to the original two components and
            # their original rows: app 1.0.0 depends on lib 1.0.0, manually
            # registered. The imported new component has no relationship and
            # no changed retention basis.
            check = Catalog(database)
            self.assertEqual(dependency_rows(check), {(APP, LIB): 1})
            self.assertEqual(
                component_rows(check),
                {APP: 0, LIB: 0, NEW: 0,
                 LIB_OTHER_VERSION: 1, LIB_OTHER_SERVICE: 1},
            )
            self.assertEqual(ids_by_identity(check)[APP], original_ids[APP])
            self.assertEqual(ids_by_identity(check)[LIB], original_ids[LIB])
            self.assertEqual(
                component_owners(check)[("api", "new", "9.0.0")], [SOURCE]
            )

            # The later source withdrawal follows the existing rules: the
            # manual relationship keeps itself and both original endpoints;
            # the source-only replacement component leaves.
            check.import_sbom(SERVICE, SOURCE, cdx([]))
            self.assertEqual(dependency_rows(check), {(APP, LIB): 1})
            self.assertEqual(
                component_rows(check),
                {APP: 0, LIB: 0,
                 LIB_OTHER_VERSION: 1, LIB_OTHER_SERVICE: 1},
            )

            # Impact flows only over the real app -> lib edge; vulnerability
            # impact never propagates to a mistaken replacement component.
            check.import_osv("nvd", osv_record("lib", "1.0.0"))
            records = check.impact()
            affected = {
                (r["component"]["service"], r["component"]["name"],
                 r["component"]["version"])
                for r in records
            }
            self.assertEqual(
                affected,
                {(SERVICE, "app", "1.0.0"), (SERVICE, "lib", "1.0.0"),
                 (OTHER_SERVICE, "lib", "1.0.0")},
            )
            indirect = next(
                r for r in records
                if (r["component"]["service"], r["component"]["name"])
                == (SERVICE, "app")
            )
            self.assertFalse(indirect["direct"])
            self.assertEqual(
                [(n["name"], n["version"]) for n in indirect["path"]],
                [("app", "1.0.0"), ("lib", "1.0.0")],
            )
            self.assertNotIn((SERVICE, "new", "9.0.0"), affected)

            summary = check.summary()
            self.assertEqual(summary.components, 4)
            self.assertEqual(summary.affected_components, 3)
            report = check.risk_report()
            impacted = {
                (e["component"]["name"], e["component"]["version"])
                for e in report["impacts"]
            }
            self.assertNotIn(("new", "9.0.0"), impacted)
            check.close()
            catalog.close()


class ReplacementFirstTests(unittest.TestCase):
    """When the replacement commits first, the registration reacts to the
    committed state and never attaches to an imported lookalike."""

    def _race_replacement_then_registration(self, document):
        """Replace the source with ``document`` while the registration waits
        for the write lock; return the registration outcome and a fresh
        catalog reflecting the durable state."""
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            held = build_raced_catalog(database)
            held.close()

            # The holder pauses inside the replacement's retention cleanup
            # (the DELETE FROM COMPONENTS statement always runs, even when it
            # deletes nothing), after the new components were inserted - the
            # write lock is held the whole time.
            replacement = _PausedWorker(
                database,
                lambda cat: cat.import_sbom(SERVICE, SOURCE, document),
                lambda sql: sql.upper().startswith("DELETE FROM COMPONENTS"),
            ).start_and_wait_paused()

            registration = _QueuedRegistration(
                database, REGISTER_ARGS
            ).start_and_wait_queued()

            replacement.release()
            registration.wait()
            join_thread(replacement.thread, "replacement")
            self.assertIsNone(replacement.error)

            return registration, Catalog(database)

    def test_both_endpoints_gone_names_missing_dependent(self):
        registration, check = self._race_replacement_then_registration(
            cdx([("build/new", "pkg:pypi/new@9.0.0")])
        )
        try:
            self.assertIsInstance(registration.error, ValueError)
            self.assertNotIsInstance(registration.error, sqlite3.Error)
            message = str(registration.error)
            self.assertIn("dependent component is not registered", message)
            self.assertIn("api/pypi/app/1.0.0", message)

            # The failed registration wrote nothing: only the replacement
            # component exists, with no edge and its source-provided basis
            # untouched.
            self.assertEqual(
                component_rows(check),
                {NEW: 0, LIB_OTHER_VERSION: 1, LIB_OTHER_SERVICE: 1},
            )
            self.assertEqual(dependency_rows(check), {})
            self.assertEqual(
                component_owners(check),
                {("api", "new", "9.0.0"): [SOURCE]},
            )

            # The failure ended with a rollback inside the serialized
            # transaction: both endpoint lookups ran after BEGIN IMMEDIATE,
            # the relationship insert never did, and nothing committed.
            normalized = [s.upper() for s in registration.statements]
            self.assertIn("BEGIN IMMEDIATE", normalized)
            self.assertTrue(
                any(s.startswith("SELECT ID FROM COMPONENTS") for s in normalized)
            )
            self.assertFalse(
                any(s.startswith("INSERT INTO DEPENDENCIES") for s in normalized)
            )
            self.assertIn("ROLLBACK", normalized)
            self.assertNotIn("COMMIT", normalized)
        finally:
            check.close()

    def test_only_dependency_endpoint_gone_is_named_precisely(self):
        # The replacement keeps app 1.0.0 but drops lib 1.0.0, importing a
        # different component instead.
        registration, check = self._race_replacement_then_registration(
            cdx([
                ("build/app", "pkg:pypi/app@1.0.0"),
                ("build/new", "pkg:pypi/new@9.0.0"),
            ])
        )
        try:
            self.assertIsInstance(registration.error, ValueError)
            message = str(registration.error)
            self.assertIn("dependency component is not registered", message)
            self.assertIn("api/pypi/lib/1.0.0", message)
            self.assertNotIn("dependent", message)

            # The surviving dependent gained no outgoing manual edge; the
            # replacement component and the same-name other version/service
            # gained no edge or retention basis at all.
            self.assertEqual(
                component_rows(check),
                {APP: 0, NEW: 0,
                 LIB_OTHER_VERSION: 1, LIB_OTHER_SERVICE: 1},
            )
            self.assertEqual(dependency_rows(check), {})
            self.assertEqual(
                component_owners(check),
                {("api", "app", "1.0.0"): [SOURCE],
                 ("api", "new", "9.0.0"): [SOURCE]},
            )
        finally:
            check.close()

    def test_same_named_other_version_or_service_cannot_substitute(self):
        # The replacement imports the same package name at a different
        # version in api; a same name/version component in another service
        # pre-exists. Neither may be taken for lib 1.0.0 in api.
        registration, check = self._race_replacement_then_registration(
            cdx([
                ("build/app", "pkg:pypi/app@1.0.0"),
                ("build/lib2", "pkg:pypi/lib@2.0.0"),
            ])
        )
        try:
            self.assertIsInstance(registration.error, ValueError)
            self.assertIn("api/pypi/lib/1.0.0", str(registration.error))
            # The surviving api lib 2.0.0 is the pre-existing manually
            # registered decoy (manual = 1), now additionally declared by the
            # source; it did not become the endpoint of anything.
            self.assertEqual(
                component_rows(check),
                {APP: 0, LIB_OTHER_VERSION: 1, LIB_OTHER_SERVICE: 1},
            )
            self.assertEqual(dependency_rows(check), {})
            self.assertEqual(
                component_owners(check),
                {("api", "app", "1.0.0"): [SOURCE],
                 ("api", "lib", "2.0.0"): [SOURCE]},
            )
        finally:
            check.close()

    def test_fresh_same_named_other_version_cannot_substitute(self):
        # The replacement freshly imports the same package name at another
        # version (no pre-existing decoy); it still cannot stand in for the
        # named lib 1.0.0.
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            held = build_raced_catalog(database, decoys=False)
            held.close()

            replacement = _PausedWorker(
                database,
                lambda cat: cat.import_sbom(
                    SERVICE, SOURCE,
                    cdx([
                        ("build/app", "pkg:pypi/app@1.0.0"),
                        ("build/lib2", "pkg:pypi/lib@2.0.0"),
                    ]),
                ),
                lambda sql: sql.upper().startswith("DELETE FROM COMPONENTS"),
            ).start_and_wait_paused()
            registration = _QueuedRegistration(
                database, REGISTER_ARGS
            ).start_and_wait_queued()
            replacement.release()
            registration.wait()
            join_thread(replacement.thread, "replacement")
            self.assertIsNone(replacement.error)

            self.assertIsInstance(registration.error, ValueError)
            self.assertIn("api/pypi/lib/1.0.0", str(registration.error))
            check = Catalog(database)
            try:
                self.assertEqual(
                    component_rows(check),
                    {APP: 0, (SERVICE, "pypi", "lib", "2.0.0"): 0},
                )
                self.assertEqual(dependency_rows(check), {})
                self.assertEqual(
                    component_owners(check),
                    {("api", "app", "1.0.0"): [SOURCE],
                     ("api", "lib", "2.0.0"): [SOURCE]},
                )
            finally:
                check.close()

    def test_reused_rowid_of_deleted_endpoint_never_gets_the_edge(self):
        # Sharpest rowid-reuse case: with the endpoints being the only
        # component rows, the competing operation deletes them (the table
        # empties, so SQLite resets its rowid sequence) and then inserts a
        # different component that reuses the dependent's old rowid, all in
        # one committed transaction. The old code resolved dependent_id in an
        # autocommit read before the write transaction, carried that stale
        # rowid across the gap, and silently attached the new component.
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            setup = build_raced_catalog(database, decoys=False)
            app_rowid = ids_by_identity(setup)[APP]
            lib_rowid = ids_by_identity(setup)[LIB]
            setup.close()
            self.assertEqual((app_rowid, lib_rowid), (1, 2))

            def clear_and_reimport(catalog):
                connection = catalog.connection
                connection.execute("BEGIN IMMEDIATE")
                try:
                    source_row = connection.execute(
                        "SELECT id FROM sources WHERE service = ? AND name = ?",
                        (SERVICE, SOURCE),
                    ).fetchone()
                    source_id = int(source_row["id"])
                    # Delete the two named endpoints; foreign-key cascade
                    # removes their edge and source ownership. The table is
                    # then empty, so the next insert binds to rowid 1 - the
                    # dependent's freed rowid.
                    connection.execute(
                        "DELETE FROM components WHERE "
                        "(service = ? AND ecosystem = ? AND name = ? "
                        "AND version = ?) "
                        "OR (service = ? AND ecosystem = ? AND name = ? "
                        "AND version = ?)",
                        APP + LIB,
                    )
                    cursor = connection.execute(
                        "INSERT INTO components(service, ecosystem, name, "
                        "version, manual) VALUES (?, ?, ?, ?, 0)",
                        NEW,
                    )
                    reused_rowid = int(cursor.lastrowid)
                    connection.execute(
                        "INSERT INTO component_sources(component_id, source_id)"
                        " VALUES (?, ?)",
                        (reused_rowid, source_id),
                    )
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    raise
                return reused_rowid

            # Pause right before the replacement component reuses the rowid.
            # The queued registration waits behind the lock and only reads
            # after this whole transaction commits.
            holder = _PausedWorker(
                database, clear_and_reimport,
                lambda sql: sql.upper().startswith(
                    "INSERT INTO COMPONENTS(SERVICE, ECOSYSTEM, NAME"
                ),
            ).start_and_wait_paused()
            registration = _QueuedRegistration(
                database, REGISTER_ARGS
            ).start_and_wait_queued()
            holder.release()
            registration.wait()
            join_thread(holder.thread, "rowid-reuse writer")
            self.assertIsNone(holder.error)
            reused_rowid = holder.result

            self.assertEqual(reused_rowid, app_rowid)
            self.assertIsInstance(registration.error, ValueError)
            self.assertIn("api/pypi/app/1.0.0", str(registration.error))

            check = Catalog(database)
            try:
                # The component now sitting at the dependent's old rowid is
                # new 9.0.0, and it has no manual edge and no manual retention
                # basis.
                self.assertEqual(ids_by_identity(check)[NEW], app_rowid)
                self.assertEqual(component_rows(check), {NEW: 0})
                self.assertEqual(dependency_rows(check), {})
                self.assertFalse(
                    check.connection.execute(
                        "SELECT EXISTS(SELECT 1 FROM dependencies WHERE "
                        "dependent_id = ? OR dependency_id = ?)",
                        (app_rowid, app_rowid),
                    ).fetchone()[0]
                )
                self.assertEqual(
                    component_owners(check),
                    {("api", "new", "9.0.0"): [SOURCE]},
                )
            finally:
                check.close()

    def test_cli_fails_nonzero_and_never_prints_success(self):
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            setup = build_raced_catalog(database)
            setup.close()

            replacement = _PausedWorker(
                database,
                lambda cat: cat.import_sbom(
                    SERVICE, SOURCE,
                    cdx([("build/new", "pkg:pypi/new@9.0.0")]),
                ),
                lambda sql: sql.upper().startswith("DELETE FROM COMPONENTS"),
            ).start_and_wait_paused()

            began = threading.Event()
            stdout = io.StringIO()
            stderr = io.StringIO()
            outcome = {}

            real_connect = sqlite3.connect

            def traced_connect(path, *args, **kwargs):
                connection = real_connect(path, *args, **kwargs)
                if str(path) == database:
                    armed = {"fired": False}

                    def trace(statement):
                        if (
                            not armed["fired"]
                            and " ".join(statement.split()).upper().startswith(
                                "BEGIN IMMEDIATE"
                            )
                        ):
                            armed["fired"] = True
                            connection.set_trace_callback(None)
                            began.set()

                    connection.set_trace_callback(trace)
                return connection

            def invoke():
                with patch.object(sqlite3, "connect", side_effect=traced_connect):
                    with contextlib.redirect_stdout(stdout), \
                            contextlib.redirect_stderr(stderr):
                        outcome["code"] = main([
                            "--database", database, "add-dependency",
                            *REGISTER_ARGS,
                        ])

            cli = threading.Thread(target=invoke)
            cli.start()
            self.assertTrue(began.wait(30))
            replacement.release()
            cli.join(30)
            self.assertFalse(cli.is_alive())

            # Non-zero status, the missing endpoint named in full, and no
            # success line on stdout.
            self.assertEqual(outcome["code"], 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertNotIn("dependency recorded", stdout.getvalue())
            self.assertIn("dependent component is not registered",
                          stderr.getvalue())
            self.assertIn("api/pypi/app/1.0.0", stderr.getvalue())

            check = Catalog(database)
            try:
                self.assertEqual(dependency_rows(check), {})
                self.assertEqual(
                    component_rows(check),
                    {NEW: 0, LIB_OTHER_VERSION: 1, LIB_OTHER_SERVICE: 1},
                )
            finally:
                check.close()

    def test_identities_still_present_after_replacement_still_register(self):
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            setup = build_raced_catalog(database)
            setup.close()

            # The replacement still provides both named full identities (it
            # only drops the declared edge and adds another component).
            replacement = _PausedWorker(
                database,
                lambda cat: cat.import_sbom(
                    SERVICE, SOURCE,
                    cdx([
                        ("build/app", "pkg:pypi/app@1.0.0"),
                        ("build/lib", "pkg:pypi/lib@1.0.0"),
                        ("build/new", "pkg:pypi/new@9.0.0"),
                    ]),
                ),
                lambda sql: sql.upper().startswith("DELETE FROM COMPONENTS"),
            ).start_and_wait_paused()
            registration = _QueuedRegistration(
                database, REGISTER_ARGS
            ).start_and_wait_queued()
            replacement.release()
            registration.wait()
            join_thread(replacement.thread, "replacement")

            self.assertIsNone(registration.error)
            check = Catalog(database)
            try:
                self.assertEqual(dependency_rows(check), {(APP, LIB): 1})
                self.assertEqual(
                    component_rows(check),
                    {APP: 0, LIB: 0, NEW: 0,
                     LIB_OTHER_VERSION: 1, LIB_OTHER_SERVICE: 1},
                )
                # A later withdrawal retains the manually registered edge and
                # both endpoints, while the source-only component leaves.
                check.import_sbom(SERVICE, SOURCE, cdx([]))
                self.assertEqual(dependency_rows(check), {(APP, LIB): 1})
                self.assertEqual(
                    component_rows(check),
                    {APP: 0, LIB: 0,
                     LIB_OTHER_VERSION: 1, LIB_OTHER_SERVICE: 1},
                )
            finally:
                check.close()


class NormalRegistrationBehaviorTests(unittest.TestCase):
    """Existing behavior the fix must preserve."""

    def setUp(self):
        self.catalog = Catalog()

    def tearDown(self):
        self.catalog.close()

    def test_source_provided_endpoints_need_no_manual_component_registration(self):
        self.catalog.import_sbom(
            SERVICE, SOURCE,
            cdx([
                ("build/app", "pkg:pypi/app@1.0.0"),
                ("build/lib", "pkg:pypi/lib@1.0.0"),
            ]),
        )
        self.catalog.add_dependency(*REGISTER_ARGS)
        self.assertEqual(dependency_rows(self.catalog), {(APP, LIB): 1})
        # Neither endpoint is itself manually registered; the edge anchors
        # them, and withdrawing the source keeps the edge and both ends.
        self.catalog.import_sbom(SERVICE, SOURCE, cdx([]))
        self.assertEqual(dependency_rows(self.catalog), {(APP, LIB): 1})
        self.assertEqual(component_rows(self.catalog), {APP: 0, LIB: 0})

    def test_manual_basis_supplements_source_edge_and_dedupes(self):
        self.catalog.import_sbom(SERVICE, SOURCE, manifest_app_to_lib())
        for _ in range(2):
            self.catalog.add_dependency(*REGISTER_ARGS)
        self.assertEqual(dependency_rows(self.catalog), {(APP, LIB): 1})
        # Exactly one relationship row, carrying the one source declaration
        # plus the manual basis - a repeated registration never duplicates it.
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM dependencies"
            ).fetchone()[0],
            1,
        )
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM dependency_sources"
            ).fetchone()[0],
            1,
        )

    def test_direction_is_preserved(self):
        self.catalog.add_component(*APP)
        self.catalog.add_component(*LIB)
        self.catalog.add_dependency(*REGISTER_ARGS)
        ((dependent, dependency), manual) = next(
            iter(dependency_rows(self.catalog).items())
        )
        self.assertEqual(dependent, APP)
        self.assertEqual(dependency, LIB)
        self.assertEqual(manual, 1)
        # The reverse relationship does not silently exist.
        reverse = self.catalog.connection.execute(
            """
            SELECT COUNT(*) FROM dependencies d
            JOIN components c1 ON c1.id = d.dependency_id
            JOIN components c2 ON c2.id = d.dependent_id
            WHERE c1.name = 'app' AND c2.name = 'lib'
            """
        ).fetchone()[0]
        self.assertEqual(reverse, 0)

    def test_empty_self_and_cross_service_rejected_before_any_sql(self):
        cases = [
            (" ", "pypi", "app", "1.0.0") + LIB,
            APP + ("api", "pypi", "app", "1.0.0"),
            APP + LIB_OTHER_SERVICE,
        ]
        for args in cases:
            statements = []
            self.catalog.connection.set_trace_callback(statements.append)
            try:
                with self.assertRaises(ValueError):
                    self.catalog.add_dependency(*args)
            finally:
                self.catalog.connection.set_trace_callback(None)
            self.assertEqual(
                [s for s in statements if s.strip()],
                [],
                "identity validation must run before any SQL",
            )
        self.assertEqual(dependency_rows(self.catalog), {})

    def test_registration_runs_in_one_serialized_write_transaction(self):
        self.catalog.add_component(*APP)
        self.catalog.add_component(*LIB)
        statements = []
        self.catalog.connection.set_trace_callback(statements.append)
        try:
            self.catalog.add_dependency(*REGISTER_ARGS)
        finally:
            self.catalog.connection.set_trace_callback(None)
        normalized = [s.strip().upper() for s in statements]
        begin_index = normalized.index("BEGIN IMMEDIATE")
        commit_index = normalized.index("COMMIT")
        # Both endpoint lookups and the insert happen between the one
        # BEGIN IMMEDIATE and its COMMIT, so no concurrent replacement can
        # fit between the check and the save.
        self.assertLess(begin_index, commit_index)
        selects = [
            i for i, s in enumerate(normalized)
            if s.startswith("SELECT ID FROM COMPONENTS")
        ]
        inserts = [
            i for i, s in enumerate(normalized)
            if s.startswith("INSERT INTO DEPENDENCIES")
        ]
        self.assertEqual(selects, [begin_index + 1, begin_index + 2])
        self.assertEqual(len(inserts), 1)
        self.assertLess(selects[1], inserts[0])
        self.assertLess(inserts[0], commit_index)
        self.assertFalse(self.catalog.connection.in_transaction)


if __name__ == "__main__":
    unittest.main()
