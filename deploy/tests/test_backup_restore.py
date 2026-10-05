"""Archive and restore refusal tests; no Docker or existing services touched."""

import json
import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

from deploy.backup_restore import BackupError, Compose, backup, digest, read_archive, restore


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.engines = {
            "postgres": {"major": 16, "id": "pg-id", "ref": "postgres:16-alpine"},
            "graph": {
                "vendor": "memgraph",
                "version": "3.2.0",
                "id": "graph-id",
                "ref": "memgraph/memgraph:3.2.0",
            },
        }
        self.metadata = {
            "app_version": "0.1.0",
            "schema_head": "0002",
            "schema_revision": "0002",
            "revision_links": [{"tenant": "demo", "revision": "revision-one"}],
            "row_counts": {"ingestion_jobs": 1},
        }
        self.graph = {
            "metadata": self.metadata,
            "snapshots": [
                {
                    "tenant": "demo",
                    "revision": "revision-one",
                    "graph": {"nodes": [], "edges": []},
                    "retention": {"created_at_ms": 123456},
                }
            ],
        }
        self.manifest = {
            "format": "zerograph-compose-backup",
            "version": 1,
            "engines": self.engines,
            "backend_image_id": "backend-id",
            "application": self.metadata,
        }
        self.addCleanup(self.directory.cleanup)

    def stream(self, metadata=None, *, end=True):
        """Version 2 NDJSON graph stream for the synthetic snapshots."""
        lines = [{"format": "zerograph-graph", "version": 2, "metadata": metadata or self.metadata}]
        for item in self.graph["snapshots"]:
            lines.append(
                {
                    "revision": {
                        "tenant": item["tenant"],
                        "revision": item["revision"],
                        "retention": item["retention"],
                        "state": "ready",
                        "source": "snapshot",
                        "warnings": [],
                        "nodes": 0,
                        "edges": 0,
                    }
                }
            )
        if end:
            lines.append({"end": {"revisions": len(self.graph["snapshots"]), "nodes": 0, "edges": 0}})
        return "".join(json.dumps(line, sort_keys=True) + "\n" for line in lines).encode()

    def archive(self, *, mutate=None, extra=None, version=1, stream=None):
        name = "graph.json" if version == 1 else "graph.ndjson"
        graph_file = self.root / name
        dump = self.root / "postgres.dump"
        if version == 1:
            graph_file.write_text(json.dumps(self.graph))
        else:
            graph_file.write_bytes(stream if stream is not None else self.stream())
            self.manifest["version"] = 2
        dump.write_bytes(b"PGDMPsynthetic-test-data")
        self.manifest["checksums"] = {name: digest(graph_file), "postgres.dump": digest(dump)}
        if mutate:
            mutate(self.manifest)
        archive = self.root / "backup.zip"
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.writestr("manifest.json", json.dumps(self.manifest))
            zipped.write(graph_file, name)
            zipped.write(dump, "postgres.dump")
            if extra:
                zipped.writestr(extra, "unexpected")
        return archive

    def unpack(self, archive):
        destination = self.root / "extracted"
        destination.mkdir(mode=0o700)
        return read_archive(archive, destination)

    def test_valid_archive_preserves_revision_links_and_private_permissions(self):
        self.assertEqual(self.unpack(self.archive())["application"], self.metadata)
        for path in (self.root / "extracted").iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_checksum_corruption_refused(self):
        with self.assertRaises(BackupError):
            self.unpack(self.archive(mutate=lambda m: m["checksums"].update({"graph.json": "0" * 64})))

    def test_traversal_or_unexpected_member_refused(self):
        with self.assertRaises(BackupError):
            self.unpack(self.archive(extra="../outside"))
        self.assertFalse((self.root.parent / "outside").exists())

    def test_incompatible_engine_refused(self):
        with self.assertRaises(BackupError):
            self.unpack(self.archive(mutate=lambda m: m["engines"]["graph"].update({"vendor": "neo4j"})))

    def test_missing_graph_pointer_refused_even_with_valid_checksums(self):
        self.graph["snapshots"] = []
        with self.assertRaises(BackupError):
            self.unpack(self.archive())

    def test_duplicate_snapshot_refused(self):
        self.graph["snapshots"].append(self.graph["snapshots"][0])
        with self.assertRaises(BackupError):
            self.unpack(self.archive())

    def test_oversized_member_refused(self):
        archive = self.archive()
        with patch(
            "deploy.backup_restore.LIMITS", {"manifest.json": 1, "postgres.dump": 1000, "graph.json": 1000}
        ):
            with self.assertRaises(BackupError):
                self.unpack(archive)

    def test_corrupt_archive_rejected_before_contacting_docker(self):
        archive = self.root / "broken.zip"
        archive.write_bytes(b"not a zip")
        compose = Mock()
        with self.assertRaises(BackupError):
            restore(compose, archive)
        compose.offline.assert_not_called()

    def test_nonempty_database_refused_before_any_restore_write(self):
        archive = self.archive()
        compose = Mock()
        compose.backend_image.return_value = "backend-id"
        compose.sql.return_value = "1"
        compose.bridge.return_value = self.metadata
        with patch("deploy.backup_restore.engines", return_value=self.engines):
            with self.assertRaises(BackupError):
                restore(compose, archive)
        self.assertNotIn("import", [call.args[0] for call in compose.bridge.call_args_list])
        compose.run.assert_not_called()

    def test_wrong_release_refused_before_any_restore_write(self):
        archive = self.archive()
        compose = Mock()
        compose.backend_image.return_value = "different-release"
        with patch("deploy.backup_restore.engines", return_value=self.engines):
            with self.assertRaises(BackupError):
                restore(compose, archive)
        compose.bridge.assert_not_called()
        compose.run.assert_not_called()

    def test_existing_archive_not_overwritten_or_source_contacted(self):
        archive = self.archive()
        original = archive.read_bytes()
        compose = Mock()
        with self.assertRaises(BackupError):
            backup(compose, archive)
        self.assertEqual(archive.read_bytes(), original)
        compose.offline.assert_not_called()

    def test_backup_publication_and_temporary_files_private(self):
        compose = Mock()
        compose.offline.return_value = {"backend": {"ID": "container-id"}}
        compose.backend_image.return_value = "backend-id"
        compose.image.return_value = {"id": "backend-id"}
        stream = self.stream()

        def bridge(action, data=None, *, stdin=None, output=None):
            if action == "export":
                output.write(stream)
                return None
            return self.metadata

        compose.bridge.side_effect = bridge

        def dump(_args, *, output):
            self.assertEqual(stat.S_IMODE(os.fstat(output.fileno()).st_mode), 0o600)
            folder = next(self.root.glob(".zerograph-backup-*"))
            self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700)
            for file in folder.iterdir():
                self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
            output.write(b"PGDMPsynthetic-test-data")

        compose.run.side_effect = dump
        archive = self.root / "new.zip"
        synced = []
        original_fsync = os.fsync

        def record_fsync(fd):
            synced.append(stat.S_IFMT(os.fstat(fd).st_mode))
            original_fsync(fd)

        with (
            patch("deploy.backup_restore.engines", return_value=self.engines),
            patch("deploy.backup_restore.os.fsync", side_effect=record_fsync),
        ):
            backup(compose, archive)
        self.assertEqual(synced, [stat.S_IFREG, stat.S_IFDIR])
        self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
        manifest = self.unpack(archive)
        self.assertEqual(manifest["application"], self.metadata)
        self.assertEqual(manifest["version"], 2)
        with zipfile.ZipFile(archive) as zipped:
            self.assertEqual(sorted(zipped.namelist()), ["graph.ndjson", "manifest.json", "postgres.dump"])
            self.assertEqual(zipped.read("graph.ndjson"), stream)

    def test_streamed_v2_archive_accepted_and_structurally_checked(self):
        self.assertEqual(self.unpack(self.archive(version=2))["version"], 2)
        for broken in (
            self.stream(end=False),
            self.stream(metadata={**self.metadata, "app_version": "other"}),
            self.stream() + b'{"revision": {}}\n',
        ):
            with self.subTest(broken=broken[-40:]):
                with self.assertRaises(BackupError):
                    archive = self.archive(version=2, stream=broken)
                    destination = self.root / "extracted"
                    if destination.exists():
                        for path in destination.iterdir():
                            path.unlink()
                        destination.rmdir()
                    self.unpack(archive)

    def test_v2_missing_pointer_and_mixed_members_refused(self):
        self.graph["snapshots"] = []
        with self.assertRaises(BackupError):
            self.unpack(self.archive(version=2))
        self.setUp()
        with self.assertRaises(BackupError):  # version 1 manifest naming a v2 member
            self.unpack(self.archive(version=2, mutate=lambda m: m.update({"version": 1})))

    def test_v1_restore_is_converted_then_streamed_and_verified(self):
        archive = self.archive()
        converted = self.stream()
        calls = []

        def bridge(action, data=None, *, stdin=None, output=None):
            calls.append(action)
            if action == "convert-v1":
                self.assertEqual(json.loads(stdin.read()), self.graph)
                output.write(converted)
            elif action == "validate":
                self.assertEqual(stdin.read(), converted)
                return self.metadata
            elif action == "import":
                self.assertEqual(stdin.read(), converted)
            elif action == "export":
                output.write(converted)
            elif action == "metadata":
                return self.metadata
            return None

        compose = Mock()
        compose.backend_image.return_value = "backend-id"
        compose.sql.return_value = "0"
        compose.bridge.side_effect = bridge
        with patch("deploy.backup_restore.engines", return_value=self.engines):
            restore(compose, archive)
        self.assertEqual(calls, ["convert-v1", "validate", "empty", "import", "metadata", "export"])

    def test_restore_refuses_a_graph_that_differs_after_import(self):
        archive = self.archive(version=2)

        def bridge(action, data=None, *, stdin=None, output=None):
            if action == "export":
                output.write(self.stream().replace(b'"source": "snapshot"', b'"source": "changed"'))
            return self.metadata if action in {"validate", "metadata"} else None

        compose = Mock()
        compose.backend_image.return_value = "backend-id"
        compose.sql.return_value = "0"
        compose.bridge.side_effect = bridge
        with patch("deploy.backup_restore.engines", return_value=self.engines):
            with self.assertRaises(BackupError):
                restore(compose, archive)


class OfflineTests(unittest.TestCase):
    def test_running_writer_blocks_backup(self):
        compose = Compose("disposable-test")
        with patch.object(
            compose,
            "run",
            return_value=json.dumps(
                [
                    {"Service": "postgres", "State": "running"},
                    {"Service": "memgraph", "State": "running"},
                    {"Service": "worker", "State": "running"},
                ]
            ).encode(),
        ):
            with self.assertRaises(BackupError):
                compose.offline()

    def test_ndjson_services_and_stopped_writer_accepted(self):
        compose = Compose("disposable-test")
        rows = [
            {"Service": "postgres", "State": "running"},
            {"Service": "memgraph", "State": "running"},
            {"Service": "worker", "State": "exited"},
        ]
        with patch.object(compose, "run", return_value="\n".join(json.dumps(row) for row in rows).encode()):
            self.assertEqual(len(compose.offline()), 3)

    def test_project_name_required_and_never_shell_interpolated(self):
        with self.assertRaises(BackupError):
            Compose("project; malicious-command")
