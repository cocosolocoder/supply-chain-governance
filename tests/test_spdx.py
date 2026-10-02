import json
import tempfile
import unittest
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard.cli import main


def spdx(
    packages,
    relationships=None,
    document_id="SPDXRef-DOCUMENT",
    spdx_version="SPDX-2.3",
):
    document = {
        "spdxVersion": spdx_version,
        "SPDXID": document_id,
        "name": "test-sbom",
        "packages": packages,
    }
    if relationships is not None:
        document["relationships"] = relationships
    return document


def package(spdx_id, purl=None, name=None, version_info=None, external_refs=None):
    entry = {"SPDXID": spdx_id, "name": name if name is not None else spdx_id}
    if external_refs is not None:
        entry["externalRefs"] = external_refs
    elif purl is not None:
        entry["externalRefs"] = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        ]
    if version_info is not None:
        entry["versionInfo"] = version_info
    return entry


def purl_ref(purl):
    return {
        "referenceCategory": "PACKAGE-MANAGER",
        "referenceType": "purl",
        "referenceLocator": purl,
    }


def depends_on(a, b):
    return {
        "spdxElementId": a,
        "relationshipType": "DEPENDS_ON",
        "relatedSpdxElement": b,
    }


def dependency_of(a, b):
    # "a DEPENDENCY_OF b" means b depends on a.
    return {
        "spdxElementId": a,
        "relationshipType": "DEPENDENCY_OF",
        "relatedSpdxElement": b,
    }


def describes(a):
    return {
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": a,
    }


class SpdxImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def test_basic_import_registers_components_and_edges(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [package("SPDXRef-a", "pkg:pypi/foo@1"),
                 package("SPDXRef-b", "pkg:pypi/bar@2")],
                [depends_on("SPDXRef-a", "SPDXRef-b")],
            ),
        )
        self.assertEqual(result.source_components, 2)
        self.assertEqual(result.added_components, 2)
        self.assertEqual(result.added_dependencies, 1)
        rows = self.catalog.connection.execute(
            "SELECT ecosystem, name, version FROM components WHERE service = 'api'"
        ).fetchall()
        self.assertEqual(
            sorted((r["ecosystem"], r["name"], r["version"]) for r in rows),
            [("pypi", "bar", "2"), ("pypi", "foo", "1")],
        )

    def test_dependency_of_direction(self) -> None:
        # "a DEPENDENCY_OF b" means b depends on a.
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [package("SPDXRef-a", "pkg:pypi/foo@1"),
                 package("SPDXRef-b", "pkg:pypi/bar@1")],
                [dependency_of("SPDXRef-a", "SPDXRef-b")],
            ),
        )
        self.assertEqual(result.added_dependencies, 1)
        rows = self.catalog.connection.execute(
            """
            SELECT d.id FROM dependencies d
            JOIN components dep ON dep.id = d.dependent_id
            JOIN components lib ON lib.id = d.dependency_id
            WHERE dep.name = 'bar' AND lib.name = 'foo'
            """
        ).fetchall()
        self.assertEqual(len(rows), 1)

    def test_equivalent_relationship_registered_once(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [package("SPDXRef-a", "pkg:pypi/foo@1"),
                 package("SPDXRef-b", "pkg:pypi/bar@1")],
                [
                    depends_on("SPDXRef-a", "SPDXRef-b"),
                    dependency_of("SPDXRef-b", "SPDXRef-a"),
                ],
            ),
        )
        self.assertEqual(result.added_dependencies, 1)

    def test_npm_scope_and_percent_decoding_preserved(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [
                    package("SPDXRef-a", "pkg:npm/%40scope/pkg@1.0.0"),
                    package("SPDXRef-b", "pkg:pypi/my%2Dpkg@1%2E0%2E0"),
                ]
            ),
        )
        rows = self.catalog.connection.execute(
            "SELECT ecosystem, name FROM components WHERE service = 'api' ORDER BY name"
        ).fetchall()
        self.assertEqual(
            [(r["ecosystem"], r["name"]) for r in rows],
            [("npm", "@scope/pkg"), ("pypi", "my-pkg")],
        )

    def test_display_name_does_not_participate_in_identity(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [
                    package("SPDXRef-a", "pkg:pypi/foo@1", name="Foo Library"),
                    package("SPDXRef-b", "pkg:pypi/foo@1", name="foo"),
                ]
            ),
        )
        self.assertEqual(
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM components WHERE service = 'api'"
            ).fetchone()[0],
            1,
        )

    def test_version_info_must_match_purl(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                spdx([package("SPDXRef-a", "pkg:pypi/foo@1.0.0", version_info="2.0.0")]),
            )

    def test_version_info_matching_is_accepted(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx([package("SPDXRef-a", "pkg:pypi/foo@1.0.0", version_info="1.0.0")]),
        )
        self.assertEqual(result.source_components, 1)

    def test_missing_purl_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                spdx([package("SPDXRef-a", external_refs=[])]),
            )
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                spdx(
                    [
                        package(
                            "SPDXRef-a",
                            external_refs=[
                                {
                                    "referenceCategory": "PACKAGE-MANAGER",
                                    "referenceType": "purl",
                                    "referenceLocator": "pkg:pypi/foo",
                                }
                            ],
                        )
                    ]
                ),
            )

    def test_unsupported_ecosystem_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                spdx([package("SPDXRef-a", "pkg:maven/foo@1")]),
            )

    def test_multiple_purls_same_identity_merge(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [
                    package(
                        "SPDXRef-a",
                        external_refs=[
                            purl_ref("pkg:pypi/foo@1"),
                            purl_ref("pkg:pypi/foo@1"),
                        ],
                    )
                ]
            ),
        )
        self.assertEqual(result.source_components, 1)

    def test_multiple_purls_different_identity_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                spdx(
                    [
                        package(
                            "SPDXRef-a",
                            external_refs=[
                                purl_ref("pkg:pypi/foo@1"),
                                purl_ref("pkg:pypi/bar@1"),
                            ],
                        )
                    ]
                ),
            )

    def test_same_identity_different_spdxids_merge(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [
                    package("SPDXRef-a", "pkg:pypi/foo@1"),
                    package("SPDXRef-b", "pkg:pypi/foo@1"),
                    package("SPDXRef-c", "pkg:pypi/bar@1"),
                ],
                [depends_on("SPDXRef-a", "SPDXRef-c")],
            ),
        )
        self.assertEqual(result.source_components, 2)
        self.assertEqual(result.added_components, 2)
        self.assertEqual(result.added_dependencies, 1)

    def test_self_dependency_after_merge_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                spdx(
                    [
                        package("SPDXRef-a", "pkg:pypi/foo@1"),
                        package("SPDXRef-b", "pkg:pypi/foo@1"),
                    ],
                    [depends_on("SPDXRef-a", "SPDXRef-b")],
                ),
            )

    def test_direct_self_dependency_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                spdx(
                    [package("SPDXRef-a", "pkg:pypi/foo@1")],
                    [depends_on("SPDXRef-a", "SPDXRef-a")],
                ),
            )

    def test_cycles_between_distinct_packages_allowed(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [package("SPDXRef-a", "pkg:pypi/foo@1"),
                 package("SPDXRef-b", "pkg:pypi/bar@1")],
                [depends_on("SPDXRef-a", "SPDXRef-b"),
                 depends_on("SPDXRef-b", "SPDXRef-a")],
            ),
        )
        self.assertEqual(result.added_dependencies, 2)

    def test_unknown_relationship_target_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                spdx(
                    [package("SPDXRef-a", "pkg:pypi/foo@1")],
                    [depends_on("SPDXRef-a", "SPDXRef-ghost")],
                ),
            )

    def test_unknown_relationship_source_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                spdx(
                    [package("SPDXRef-a", "pkg:pypi/foo@1")],
                    [depends_on("SPDXRef-ghost", "SPDXRef-a")],
                ),
            )

    def test_external_document_reference_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                spdx(
                    [package("SPDXRef-a", "pkg:pypi/foo@1")],
                    [depends_on("SPDXRef-a", "DocumentRef-other:SPDXRef-pkg")],
                ),
            )

    def test_document_id_conflict_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                spdx(
                    [package("SPDXRef-DOCUMENT", "pkg:pypi/foo@1")],
                    document_id="SPDXRef-DOCUMENT",
                ),
            )

    def test_duplicate_package_spdxid_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                spdx(
                    [
                        package("SPDXRef-a", "pkg:pypi/foo@1"),
                        package("SPDXRef-a", "pkg:pypi/bar@1"),
                    ]
                ),
            )

    def test_empty_spdxid_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api", "src", spdx([package("", "pkg:pypi/foo@1")])
            )
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                spdx([package("SPDXRef-a", "pkg:pypi/foo@1")], document_id=""),
            )

    def test_spdx_version_must_be_2_3(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api", "src", spdx([], spdx_version="SPDX-2.2")
            )
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api", "src", spdx([], spdx_version="SPDX-3.0")
            )

    def test_packages_must_be_array(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api", "src", {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": "nope"}
            )
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api", "src", {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}
            )

    def test_relationships_omitted_means_empty(self) -> None:
        result = self.catalog.import_sbom(
            "api", "src", spdx([package("SPDXRef-a", "pkg:pypi/foo@1")])
        )
        self.assertEqual(result.added_dependencies, 0)

    def test_relationships_must_be_array(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                spdx(
                    [package("SPDXRef-a", "pkg:pypi/foo@1")],
                    relationships="nope",
                ),
            )

    def test_describes_and_other_relationships_ignored(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [package("SPDXRef-a", "pkg:pypi/foo@1")],
                [
                    describes("SPDXRef-a"),
                    {
                        "spdxElementId": "SPDXRef-a",
                        "relationshipType": "COPY_OF",
                        "relatedSpdxElement": "SPDXRef-other",
                    },
                ],
            ),
        )
        self.assertEqual(result.added_dependencies, 0)
        self.assertEqual(result.source_components, 1)

    def test_document_itself_is_not_a_component(self) -> None:
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [package("SPDXRef-a", "pkg:pypi/foo@1")],
                [describes("SPDXRef-a")],
            ),
        )
        self.assertEqual(result.source_components, 1)

    def test_empty_packages_clears_source(self) -> None:
        self.catalog.import_sbom(
            "api", "src", spdx([package("SPDXRef-a", "pkg:pypi/foo@1")])
        )
        result = self.catalog.import_sbom("api", "src", spdx([]))
        self.assertEqual(result.source_components, 0)
        self.assertEqual(result.deleted_components, 1)
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM components").fetchone()[0],
            0,
        )

    def test_reimport_replaces_source_ownership(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [package("SPDXRef-a", "pkg:pypi/foo@1"),
                 package("SPDXRef-b", "pkg:pypi/bar@1")],
                [depends_on("SPDXRef-a", "SPDXRef-b")],
            ),
        )
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [package("SPDXRef-a", "pkg:pypi/foo@1"),
                 package("SPDXRef-c", "pkg:pypi/baz@1")],
                [depends_on("SPDXRef-a", "SPDXRef-c")],
            ),
        )
        self.assertEqual(result.source_components, 2)
        self.assertEqual(result.added_components, 1)
        self.assertEqual(result.deleted_components, 1)
        self.assertEqual(result.added_dependencies, 1)
        self.assertEqual(result.deleted_dependencies, 1)
        names = [
            r["name"]
            for r in self.catalog.connection.execute(
                "SELECT name FROM components WHERE service = 'api'"
            )
        ]
        self.assertEqual(sorted(names), ["baz", "foo"])

    def test_reimport_identical_is_idempotent(self) -> None:
        document = spdx(
            [package("SPDXRef-a", "pkg:pypi/foo@1"),
             package("SPDXRef-b", "pkg:pypi/bar@1")],
            [depends_on("SPDXRef-a", "SPDXRef-b")],
        )
        first = self.catalog.import_sbom("api", "src", document)
        second = self.catalog.import_sbom("api", "src", document)
        self.assertEqual(second.added_components, 0)
        self.assertEqual(second.deleted_components, 0)
        self.assertEqual(second.added_dependencies, 0)
        self.assertEqual(second.deleted_dependencies, 0)
        self.assertEqual(second.source_components, first.source_components)

    def test_switching_from_cyclonedx_replaces_source(self) -> None:
        cyclonedx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"bom-ref": "a", "purl": "pkg:pypi/foo@1"},
                {"bom-ref": "b", "purl": "pkg:pypi/bar@1"},
            ],
            "dependencies": [{"ref": "a", "dependsOn": ["b"]}],
        }
        self.catalog.import_sbom("api", "src", cyclonedx)
        result = self.catalog.import_sbom(
            "api",
            "src",
            spdx([package("SPDXRef-a", "pkg:pypi/baz@1")]),
        )
        self.assertEqual(result.deleted_components, 2)
        self.assertEqual(result.added_components, 1)
        self.assertEqual(result.deleted_dependencies, 1)
        names = [
            r["name"]
            for r in self.catalog.connection.execute(
                "SELECT name FROM components WHERE service = 'api'"
            )
        ]
        self.assertEqual(names, ["baz"])
        # Exactly one source row, not two lists.
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM sources").fetchone()[0],
            1,
        )

    def test_manual_components_and_edges_survive_replacement(self) -> None:
        self.catalog.add_component("api", "pypi", "manual", "1.0.0")
        self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [package("SPDXRef-a", "pkg:pypi/foo@1"),
                 package("SPDXRef-b", "pkg:pypi/bar@1")],
                [depends_on("SPDXRef-a", "SPDXRef-b")],
            ),
        )
        self.catalog.add_dependency("api", "pypi", "foo", "1", "api", "pypi", "bar", "1")
        self.catalog.import_sbom("api", "src", spdx([]))
        names = [
            r["name"]
            for r in self.catalog.connection.execute(
                "SELECT name FROM components WHERE service = 'api'"
            )
        ]
        self.assertEqual(sorted(names), ["bar", "foo", "manual"])
        self.assertEqual(
            self.catalog.connection.execute("SELECT COUNT(*) FROM dependencies").fetchone()[0],
            1,
        )

    def test_other_sources_are_preserved(self) -> None:
        self.catalog.import_sbom(
            "api",
            "other",
            spdx([package("SPDXRef-x", "pkg:pypi/other@1")]),
        )
        self.catalog.import_sbom(
            "api", "src", spdx([package("SPDXRef-a", "pkg:pypi/foo@1")])
        )
        self.catalog.import_sbom("api", "src", spdx([]))
        names = [
            r["name"]
            for r in self.catalog.connection.execute(
                "SELECT name FROM components WHERE service = 'api'"
            )
        ]
        self.assertEqual(names, ["other"])

    def test_rejection_leaves_catalog_unchanged(self) -> None:
        self.catalog.import_sbom(
            "api", "src", spdx([package("SPDXRef-a", "pkg:pypi/foo@1")])
        )
        with self.assertRaises(ValueError):
            self.catalog.import_sbom(
                "api",
                "src",
                spdx(
                    [package("SPDXRef-x", "pkg:pypi/new@1")],
                    [depends_on("SPDXRef-x", "SPDXRef-ghost")],
                ),
            )
        rows = self.catalog.connection.execute(
            "SELECT name FROM components WHERE service = 'api'"
        ).fetchall()
        self.assertEqual([r["name"] for r in rows], ["foo"])

    def test_order_does_not_change_result(self) -> None:
        document_a = spdx(
            [
                package("SPDXRef-zzz", "pkg:pypi/foo@1"),
                package("SPDXRef-aaa", "pkg:pypi/bar@1"),
                package("SPDXRef-mmm", "pkg:pypi/baz@1"),
            ],
            [
                depends_on("SPDXRef-zzz", "SPDXRef-aaa"),
                depends_on("SPDXRef-aaa", "SPDXRef-mmm"),
            ],
        )
        document_b = spdx(
            [
                package("SPDXRef-1", "pkg:pypi/baz@1"),
                package("SPDXRef-2", "pkg:pypi/foo@1"),
                package("SPDXRef-3", "pkg:pypi/bar@1"),
            ],
            [
                depends_on("SPDXRef-2", "SPDXRef-3"),
                depends_on("SPDXRef-3", "SPDXRef-1"),
            ],
        )
        catalog_a = Catalog()
        catalog_b = Catalog()
        catalog_a.import_sbom("api", "src", document_a)
        catalog_b.import_sbom("api", "src", document_b)
        catalog_a.add_vulnerability("CVE-1", "baz", "high")
        catalog_b.add_vulnerability("CVE-1", "baz", "high")
        self.assertEqual(catalog_a.impact(), catalog_b.impact())
        catalog_a.close()
        catalog_b.close()

    def test_impact_and_summary_reflect_import_immediately(self) -> None:
        self.catalog.import_sbom(
            "api",
            "src",
            spdx(
                [package("SPDXRef-a", "pkg:pypi/foo@1"),
                 package("SPDXRef-b", "pkg:pypi/bar@1")],
                [depends_on("SPDXRef-a", "SPDXRef-b")],
            ),
        )
        self.catalog.add_vulnerability("CVE-1", "bar", "high")
        summary = self.catalog.summary()
        self.assertEqual(summary.components, 2)
        self.assertEqual(summary.affected_components, 2)
        records = self.catalog.impact()
        self.assertEqual(len(records), 2)

    def test_exemption_survives_reimport_and_applies(self) -> None:
        document = spdx(
            [package("SPDXRef-a", "pkg:pypi/foo@1"),
             package("SPDXRef-b", "pkg:pypi/bar@1")],
            [depends_on("SPDXRef-a", "SPDXRef-b")],
        )
        self.catalog.import_sbom("api", "src", document)
        self.catalog.add_vulnerability("CVE-1", "bar", "high")
        record = self.catalog.request_exemption(
            "EXM-1",
            "api",
            "pypi",
            "foo",
            "1",
            "CVE-1",
            "bar",
            None,
            "alice",
            "accepted",
            "2026-12-31T23:59:59+00:00",
        )
        self.catalog.approve_exemption("EXM-1", "bob", "ok")
        # Reimport the same source: the exemption history must remain and the
        # exemption must still cover the impact record.
        self.catalog.import_sbom("api", "src", document)
        report = self.catalog.risk_report(
            evaluated_at="2026-06-01T00:00:00+00:00"
        )
        foo_entry = next(
            entry
            for entry in report["impacts"]
            if entry["component"]["name"] == "foo"
        )
        self.assertTrue(foo_entry["exempted"])
        self.assertEqual(foo_entry["exemption_request"], "EXM-1")
        # The request and its history are still queryable.
        stored = self.catalog.get_exemption("EXM-1")
        self.assertEqual(stored["status"], "approved")
        self.assertEqual(len(stored["events"]), 2)

    def test_empty_service_or_source_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom("", "src", spdx([]))
        with self.assertRaises(ValueError):
            self.catalog.import_sbom("api", "  ", spdx([]))

    def test_unrecognized_format_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.import_sbom("api", "src", {"hello": "world"})


class SpdxCliTests(unittest.TestCase):
    def test_import_spdx_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            path = Path(directory, "sbom.json")
            path.write_text(
                json.dumps(
                    spdx(
                        [package("SPDXRef-a", "pkg:pypi/foo@1"),
                         package("SPDXRef-b", "pkg:pypi/bar@1")],
                        [depends_on("SPDXRef-a", "SPDXRef-b")],
                    )
                )
            )
            self.assertEqual(
                main(["--database", database, "import-sbom", "api", "src", str(path)]),
                0,
            )

    def test_import_cyclonedx_still_works(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            path = Path(directory, "sbom.json")
            path.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.5",
                        "components": [
                            {"bom-ref": "a", "purl": "pkg:pypi/foo@1"}
                        ],
                    }
                )
            )
            self.assertEqual(
                main(["--database", database, "import-sbom", "api", "src", str(path)]),
                0,
            )

    def test_validation_error_returns_nonzero_and_preserves_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            good = Path(directory, "good.json")
            good.write_text(
                json.dumps(spdx([package("SPDXRef-a", "pkg:pypi/foo@1")]))
            )
            bad = Path(directory, "bad.json")
            bad.write_text(
                json.dumps(
                    spdx(
                        [package("SPDXRef-x", "pkg:pypi/new@1")],
                        [depends_on("SPDXRef-x", "SPDXRef-ghost")],
                    )
                )
            )
            self.assertEqual(
                main(["--database", database, "import-sbom", "api", "src", str(good)]),
                0,
            )
            self.assertEqual(
                main(["--database", database, "import-sbom", "api", "src", str(bad)]),
                1,
            )
            catalog = Catalog(database)
            self.assertEqual(
                catalog.connection.execute("SELECT COUNT(*) FROM components").fetchone()[0],
                1,
            )
            catalog.close()


if __name__ == "__main__":
    unittest.main()
