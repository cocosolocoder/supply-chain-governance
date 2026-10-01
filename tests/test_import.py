import io
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from supply_guard.catalog import Catalog, ManifestError
from supply_guard.cli import main


def bom(components, dependencies=None, root=None, fmt="CycloneDX", ver="1.5"):
    doc = {"bomFormat": fmt, "specVersion": ver}
    if components is not None:
        doc["components"] = components
    if dependencies is not None:
        doc["dependencies"] = dependencies
    if root is not None:
        doc["metadata"] = {"component": root}
    return doc


def comp(ref, purl, version=None, nested=None):
    c = {"type": "library", "bom-ref": ref, "purl": purl}
    if version is not None:
        c["version"] = version
    if nested is not None:
        c["components"] = nested
    return c


def write_manifest(directory, name, document):
    path = Path(directory, name)
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


class ImportValidationTests(unittest.TestCase):
    def setUp(self):
        self.catalog = Catalog()
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.catalog.close()
        self.tmp.cleanup()

    def imp(self, doc, service="api", source="s1", name="bom.json"):
        return self.catalog.import_cyclonedx(service, source, write_manifest(self.dir, name, doc))

    def assertRejected(self, doc, *fragments):
        before_components = self.catalog.summary().components
        with self.assertRaises(ManifestError) as ctx:
            self.imp(doc)
        message = str(ctx.exception)
        for fragment in fragments:
            self.assertIn(fragment, message)
        self.assertEqual(self.catalog.summary().components, before_components)

    def test_basic_import_reflects_in_summary_and_impact(self):
        doc = bom(
            [comp("a", "pkg:pypi/app@1.0.0"), comp("b", "pkg:npm/lib@2.0.0")],
            [{"ref": "a", "dependencies": ["b"]}],
        )
        result = self.imp(doc)
        self.assertEqual(result.source_components, 2)
        self.assertEqual(result.components_added, 2)
        self.assertEqual(result.dependencies_added, 1)
        self.catalog.add_vulnerability("CVE-1", "lib", "high")
        self.assertEqual(self.catalog.summary().components, 2)
        self.assertEqual(self.catalog.summary().affected_components, 2)
        records = self.catalog.impact(service="api")
        app = [r for r in records if r["component"]["name"] == "app"][0]
        self.assertEqual([n["name"] for n in app["path"]], ["app", "lib"])
        self.assertFalse(app["direct"])

    def test_format_and_version_and_components_type(self):
        self.assertRejected(bom([], fmt="SPDX"), "bomFormat")
        self.assertRejected(bom([], ver="1.4"), "specVersion")
        self.assertRejected(
            {"bomFormat": "CycloneDX", "specVersion": "1.5"}, "components"
        )
        self.assertRejected(
            {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": {}},
            "array",
        )
        self.assertRejected([], "object")

    def test_bom_ref_rules(self):
        self.assertRejected(bom([comp("", "pkg:pypi/a@1")]), "bom-ref")
        self.assertRejected(bom([{"purl": "pkg:pypi/a@1"}]), "bom-ref")
        self.assertRejected(
            bom([comp("x", "pkg:pypi/a@1"), comp("x", "pkg:pypi/b@1")]),
            "duplicate bom-ref",
        )

    def test_purl_rules(self):
        self.assertRejected(bom([comp("a", "pkg:maven/x/y@1")]), "pypi")
        self.assertRejected(bom([comp("a", "pkg:pypi/a")]), "version")
        self.assertRejected(bom([comp("a", "not-a-purl")]), "pkg:")
        self.assertRejected(bom([comp("a", 123)]), "purl")
        self.assertRejected(bom([comp("a", "pkg:pypi/a@%zz1")]), "percent")
        self.assertRejected(
            bom([comp("a", "pkg:pypi/a@1", version="2")]), "does not match"
        )

    def test_nested_components_rejected(self):
        self.assertRejected(
            bom([comp("a", "pkg:pypi/a@1", nested=[comp("n", "pkg:pypi/n@1")])]),
            "nested",
        )

    def test_unknown_dependency_refs(self):
        self.assertRejected(
            bom([comp("a", "pkg:pypi/a@1")], [{"ref": "a", "dependencies": ["ghost"]}]),
            "unknown ref",
        )
        self.assertRejected(
            bom([comp("a", "pkg:pypi/a@1")], [{"ref": "ghost", "dependencies": []}]),
            "unknown ref",
        )

    def test_root_component_rules(self):
        root = {"bom-ref": "root", "purl": "pkg:pypi/root@1"}
        self.assertRejected(
            bom([comp("root", "pkg:pypi/a@1")], root=root),
            "must not be reused",
        )
        self.assertRejected(
            bom([comp("a", "pkg:pypi/a@1")],
                [{"ref": "a", "dependencies": ["root"]}], root=root),
            "manifest root",
        )
        # Root outgoing edges are ignored.
        doc = bom(
            [comp("a", "pkg:pypi/a@1")],
            [{"ref": "root", "dependencies": ["a"]},
             {"ref": "a", "dependencies": []}],
            root=root,
        )
        result = self.imp(doc)
        self.assertEqual(result.source_components, 1)
        self.assertEqual(result.dependencies_added, 0)
        self.assertEqual(self.catalog.summary().components, 1)

    def test_merged_identity_self_dependency_rejected(self):
        self.assertRejected(
            bom(
                [comp("r1", "pkg:pypi/a@1"), comp("r2", "pkg:pypi/a@1")],
                [{"ref": "r1", "dependencies": ["r2"]}],
            ),
            "self-depend",
        )

    def test_identity_merge_and_encoding_and_scope(self):
        doc = bom(
            [
                comp("one", "pkg:pypi/zope%2Einterface@5.0"),
                comp("two", "pkg:npm/%40angular/core@16.0.0"),
                comp("two-again", "pkg:npm/@angular/core@16.0.0", version="16.0.0"),
            ],
            [],
        )
        result = self.imp(doc)
        self.assertEqual(result.source_components, 2)
        self.assertEqual(result.components_added, 2)
        names = sorted(
            (row[0], row[1], row[2])
            for row in self.catalog.connection.execute(
                "SELECT ecosystem, name, version FROM components"
            )
        )
        self.assertEqual(
            names,
            [("npm", "@angular/core", "16.0.0"), ("pypi", "zope.interface", "5.0")],
        )

    def test_cycles_allowed_duplicates_collapse_and_missing_deps_empty(self):
        doc = bom(
            [comp("a", "pkg:pypi/a@1"), comp("b", "pkg:pypi/b@1")],
            [
                {"ref": "a", "dependencies": ["b", "b"]},
                {"ref": "b", "dependencies": ["a"]},
            ],
        )
        result = self.imp(doc)
        self.assertEqual(result.dependencies_added, 2)
        # Importing again adds nothing.
        again = self.imp(doc)
        self.assertEqual((again.components_added, again.dependencies_added,
                          again.components_deleted, again.dependencies_deleted),
                         (0, 0, 0, 0))
        # Missing dependencies key means no relationships.
        self.assertEqual(self.imp(bom([comp("c", "pkg:pypi/c@1")]), source="s2").dependencies_added, 0)

    def test_failure_keeps_old_manifest_and_vulnerabilities(self):
        self.imp(bom([comp("a", "pkg:pypi/a@1"), comp("b", "pkg:pypi/b@1")],
                     [{"ref": "a", "dependencies": ["b"]}]))
        self.catalog.add_vulnerability("CVE-1", "b", "high")
        with self.assertRaises(ManifestError):
            self.imp(bom([comp("a", "pkg:pypi/a@1"), comp("x", "pkg:maven/g/h@9")]))
        self.assertEqual(self.catalog.summary().components, 2)
        self.assertEqual(self.catalog.summary().vulnerabilities, 1)
        self.assertEqual(self.catalog.summary().affected_components, 2)

    def test_unreadable_and_invalid_json(self):
        missing = self.dir / "nope.json"
        with self.assertRaises(ManifestError):
            self.catalog.import_cyclonedx("api", "s1", missing)
        bad = self.dir / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        with self.assertRaises(ManifestError) as ctx:
            self.catalog.import_cyclonedx("api", "s1", bad)
        self.assertIn("invalid JSON", str(ctx.exception))

    def test_empty_service_or_source(self):
        path = write_manifest(self.dir, "b.json", bom([]))
        with self.assertRaises(ManifestError):
            self.catalog.import_cyclonedx(" ", "s", path)
        with self.assertRaises(ManifestError):
            self.catalog.import_cyclonedx("api", "  ", path)

    def test_sources_unique_per_service_but_shared_name_across_services(self):
        doc = bom([comp("a", "pkg:pypi/a@1")])
        self.imp(doc, service="api", source="s1")
        self.imp(doc, service="web", source="s1")
        self.assertEqual(self.catalog.summary().components, 2)
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM sources").fetchone()[0],
            2,
        )


class ReplacementSemanticsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.db = self.dir / "catalog.db"
        self.catalog = Catalog(self.db)

    def tearDown(self):
        self.catalog.close()
        self.tmp.cleanup()

    def path(self, name, doc):
        return write_manifest(self.dir, name, doc)

    def reopen(self):
        self.catalog.close()
        self.catalog = Catalog(self.db)

    def test_reimport_replaces_source_components_and_edges(self):
        v1 = bom(
            [comp("a", "pkg:pypi/a@1"), comp("b", "pkg:pypi/b@1"),
             comp("c", "pkg:pypi/c@1")],
            [{"ref": "a", "dependencies": ["b", "c"]}],
        )
        r1 = self.catalog.import_cyclonedx("api", "s1", self.path("v1.json", v1))
        self.assertEqual((r1.components_added, r1.dependencies_added), (3, 2))
        v2 = bom(
            [comp("a", "pkg:pypi/a@1"), comp("d", "pkg:pypi/d@1")],
            [{"ref": "a", "dependencies": ["d"]}],
        )
        r2 = self.catalog.import_cyclonedx("api", "s1", self.path("v2.json", v2))
        self.assertEqual(r2.source_components, 2)
        self.assertEqual(r2.components_added, 1)       # d
        self.assertEqual(r2.components_deleted, 2)     # b, c
        self.assertEqual(r2.dependencies_added, 1)     # a->d
        self.assertEqual(r2.dependencies_deleted, 2)   # a->b, a->c
        names = {row[0] for row in self.catalog.connection.execute(
            "SELECT name FROM components")}
        self.assertEqual(names, {"a", "d"})

    def test_empty_components_clears_source(self):
        doc = bom([comp("a", "pkg:pypi/a@1")], [])
        self.catalog.import_cyclonedx("api", "s1", self.path("a.json", doc))
        result = self.catalog.import_cyclonedx("api", "s1", self.path("empty.json", bom([])))
        self.assertEqual(result.source_components, 0)
        self.assertEqual(result.components_deleted, 1)
        self.assertEqual(self.catalog.summary().components, 0)
        # Source record still exists for reuse.
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM sources").fetchone()[0], 1
        )

    def test_manual_data_survives_other_source_replacement(self):
        self.catalog.add_component("api", "pypi", "manual", "1")
        self.catalog.add_component("api", "pypi", "a", "1")
        self.catalog.add_dependency("api", "pypi", "manual", "1",
                                    "api", "pypi", "a", "1")
        doc = bom([comp("a", "pkg:pypi/a@1"), comp("b", "pkg:pypi/b@1")],
                  [{"ref": "a", "dependencies": ["b"]}])
        self.catalog.import_cyclonedx("api", "s1", self.path("s1.json", doc))
        # Drop everything from s1; manual component and manual edge endpoints stay.
        self.catalog.import_cyclonedx("api", "s1", self.path("s1empty.json", bom([])))
        names = {row[0] for row in self.catalog.connection.execute(
            "SELECT name FROM components ORDER BY name")}
        self.assertEqual(names, {"a", "manual"})
        edges = self.catalog.connection.execute(
            "SELECT cn.name, dn.name FROM dependencies "
            "JOIN components cn ON cn.id = dependent_id "
            "JOIN components dn ON dn.id = dependency_id"
        ).fetchall()
        self.assertEqual([(r[0], r[1]) for r in edges], [("manual", "a")])

    def test_manual_add_after_import_is_retained(self):
        doc = bom([comp("a", "pkg:pypi/a@1"), comp("b", "pkg:pypi/b@1")],
                  [{"ref": "a", "dependencies": ["b"]}])
        self.catalog.import_cyclonedx("api", "s1", self.path("s1.json", doc))
        self.catalog.add_component("api", "pypi", "extra", "1")
        self.catalog.add_component("api", "pypi", "a", "1")  # idempotent, marks manual
        self.catalog.add_dependency("api", "pypi", "a", "1",
                                    "api", "pypi", "extra", "1")
        self.catalog.import_cyclonedx("api", "s1", self.path("s1empty.json", bom([])))
        names = {row[0] for row in self.catalog.connection.execute(
            "SELECT name FROM components")}
        self.assertEqual(names, {"a", "extra"})
        edges = [(r[0], r[1]) for r in self.catalog.connection.execute(
            "SELECT cn.name, dn.name FROM dependencies "
            "JOIN components cn ON cn.id = dependent_id "
            "JOIN components dn ON dn.id = dependency_id")]
        self.assertEqual(edges, [("a", "extra")])

    def test_remove_dependency_only_revokes_manual_registration(self):
        doc = bom([comp("a", "pkg:pypi/a@1"), comp("b", "pkg:pypi/b@1")],
                  [{"ref": "a", "dependencies": ["b"]}])
        self.catalog.import_cyclonedx("api", "s1", self.path("s1.json", doc))
        self.catalog.add_dependency("api", "pypi", "a", "1",
                                    "api", "pypi", "b", "1")
        self.catalog.remove_dependency("api", "pypi", "a", "1",
                                       "api", "pypi", "b", "1")
        # Edge remains because the source still declares it.
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM dependencies").fetchone()[0], 1
        )
        self.catalog.import_cyclonedx("api", "s1", self.path("s1empty.json", bom([])))
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM dependencies").fetchone()[0], 0
        )

    def test_multiple_sources_union_until_all_drop(self):
        doc1 = bom([comp("a", "pkg:pypi/a@1"), comp("b", "pkg:pypi/b@1")],
                   [{"ref": "a", "dependencies": ["b"]}])
        doc2 = bom([comp("a", "pkg:pypi/a@1"), comp("c", "pkg:pypi/c@1")],
                   [{"ref": "a", "dependencies": ["c"]}])
        self.catalog.import_cyclonedx("api", "s1", self.path("s1.json", doc1))
        self.catalog.import_cyclonedx("api", "s2", self.path("s2.json", doc2))
        self.assertEqual(self.catalog.summary().components, 3)
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM dependencies").fetchone()[0], 2
        )
        self.catalog.import_cyclonedx("api", "s1", self.path("s1empty.json", bom([])))
        names = {row[0] for row in self.catalog.connection.execute("SELECT name FROM components")}
        self.assertEqual(names, {"a", "c"})
        edges = {(r[0], r[1]) for r in self.catalog.connection.execute(
            "SELECT cn.name, dn.name FROM dependencies "
            "JOIN components cn ON cn.id = dependent_id "
            "JOIN components dn ON dn.id = dependency_id")}
        self.assertEqual(edges, {("a", "c")})

    def test_identical_reimport_creates_no_records_and_survives_reopen(self):
        doc = bom(
            [comp("a", "pkg:pypi/a@1"), comp("b", "pkg:pypi/b@1")],
            [{"ref": "a", "dependencies": ["b"]}],
        )
        path = self.path("s1.json", doc)
        self.catalog.import_cyclonedx("api", "s1", path)
        result = self.catalog.import_cyclonedx("api", "s1", path)
        self.assertEqual((result.components_added, result.components_deleted,
                          result.dependencies_added, result.dependencies_deleted),
                         (0, 0, 0, 0))
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM sources").fetchone()[0], 1
        )
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM component_sources").fetchone()[0], 2
        )
        self.reopen()
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM component_sources").fetchone()[0], 2
        )
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM dependency_sources").fetchone()[0], 1
        )
        self.assertEqual(self.catalog.summary().components, 2)

    def test_legacy_database_rows_are_manual(self):
        # Build a database with the old schema/data.
        self.catalog.close()
        self.db.unlink()
        conn = sqlite3.connect(self.db)
        conn.executescript(
            """
            CREATE TABLE components (
                id INTEGER PRIMARY KEY, service TEXT NOT NULL, ecosystem TEXT NOT NULL,
                name TEXT NOT NULL, version TEXT NOT NULL,
                UNIQUE(service, ecosystem, name, version));
            CREATE TABLE vulnerabilities (
                id TEXT NOT NULL, component_name TEXT NOT NULL, severity TEXT NOT NULL
                CHECK (severity IN ('low','medium','high','critical')),
                PRIMARY KEY(id, component_name));
            CREATE TABLE dependencies (
                dependent_id INTEGER NOT NULL, dependency_id INTEGER NOT NULL,
                UNIQUE(dependent_id, dependency_id));
            INSERT INTO components VALUES (1,'api','pypi','a','1'),(2,'api','pypi','b','1');
            INSERT INTO dependencies VALUES (1,2);
            """
        )
        conn.commit()
        conn.close()
        legacy = Catalog(self.db)
        legacy.import_cyclonedx("api", "s1", self.path("empty.json", bom([])))
        names = {row[0] for row in legacy.connection.execute("SELECT name FROM components")}
        self.assertEqual(names, {"a", "b"})
        self.assertEqual(
            legacy.connection.execute("SELECT COUNT(*) FROM dependencies").fetchone()[0], 1
        )
        legacy.close()

    def test_document_order_and_ref_names_do_not_change_identity_or_paths(self):
        v1 = bom(
            [comp("x-ref", "pkg:pypi/app@1"), comp("y-ref", "pkg:pypi/lib@1")],
            [{"ref": "x-ref", "dependencies": ["y-ref"]}],
        )
        v2 = bom(
            [comp("totally-different-ref-name", "pkg:pypi/lib@1"),
             comp("other-ref", "pkg:pypi/app@1")],
            [{"ref": "other-ref", "dependencies": ["totally-different-ref-name"]}],
        )
        self.catalog.import_cyclonedx("api", "s1", self.path("v1.json", v1))
        self.catalog.add_vulnerability("CVE-1", "lib", "high")
        paths_before = [
            [n["name"] for n in r["path"]] for r in self.catalog.impact()
        ]
        result = self.catalog.import_cyclonedx("api", "s1", self.path("v2.json", v2))
        self.assertEqual((result.components_added, result.components_deleted,
                          result.dependencies_added, result.dependencies_deleted),
                         (0, 0, 0, 0))
        paths_after = [
            [n["name"] for n in r["path"]] for r in self.catalog.impact()
        ]
        self.assertEqual(paths_before, paths_after)
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM components").fetchone()[0], 2
        )


class CliImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.db = str(self.dir / "catalog.db")

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_cli_success_statistics(self):
        path = self.dir / "bom.json"
        path.write_text(json.dumps(bom(
            [comp("a", "pkg:pypi/app@1.0.0"), comp("b", "pkg:npm/lib@2.0.0")],
            [{"ref": "a", "dependencies": ["b"]}],
        )))
        code, out, err = self.run_cli(
            "--database", self.db, "import-sbom", "api", "build-42", str(path))
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("清单组件数: 2", out)
        self.assertIn("新增组件: 2", out)
        self.assertIn("删除组件: 0", out)
        self.assertIn("新增依赖: 1", out)
        self.assertIn("删除依赖: 0", out)
        # Summary immediately reflects the new manifest.
        code, out, _ = self.run_cli("--database", self.db, "summary")
        self.assertEqual(code, 0)
        self.assertIn("组件数量: 2", out)
        # Alias works too.
        code, _, _ = self.run_cli(
            "--database", self.db, "import-cyclonedx", "api", "build-42", str(path))
        self.assertEqual(code, 0)

    def test_cli_failures_nonzero_stderr_no_stats_and_unchanged_data(self):
        good = self.dir / "good.json"
        good.write_text(json.dumps(bom([comp("a", "pkg:pypi/app@1")])))
        self.assertEqual(
            self.run_cli("--database", self.db, "import-sbom", "api", "s1", str(good))[0],
            0,
        )
        # Unreadable file.
        code, out, err = self.run_cli(
            "--database", self.db, "import-sbom", "api", "s1", str(self.dir / "missing.json"))
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error:", err)
        # Bad JSON.
        bad = self.dir / "bad.json"
        bad.write_text("{nope")
        code, out, err = self.run_cli(
            "--database", self.db, "import-sbom", "api", "s1", str(bad))
        self.assertEqual(code, 1)
        self.assertIn("error:", err)
        self.assertIn("invalid JSON", err)
        self.assertNotIn("清单组件数", out)
        # Invalid record with location.
        invalid = self.dir / "invalid.json"
        invalid.write_text(json.dumps(bom(
            [comp("a", "pkg:pypi/app@1"), comp("b", "pkg:maven/x/y@1")])))
        code, out, err = self.run_cli(
            "--database", self.db, "import-sbom", "api", "s1", str(invalid))
        self.assertEqual(code, 1)
        self.assertIn("components[1]", err)
        self.assertNotIn("清单组件数", out)
        # Old manifest untouched.
        code, out, _ = self.run_cli("--database", self.db, "summary")
        self.assertIn("组件数量: 1", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
