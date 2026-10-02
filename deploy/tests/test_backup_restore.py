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

    def archive(self, *, mutate=None, extra=None):
        graph_file = self.root / "graph.json"
        dump = self.root / "postgres.dump"
        graph_file.write_text(json.dumps(self.graph))
        dump.write_bytes(b"PGDMPsynthetic-test-data")
        self.manifest["checksums"] = {"graph.json": digest(graph_file), "postgres.dump": digest(dump)}
        if mutate:
            mutate(self.manifest)
        archive = self.root / "backup.zip"
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.writestr("manifest.json", json.dumps(self.manifest))
            zipped.write(graph_file, "graph.json")
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
        compose.bridge.side_effect = [self.graph, self.metadata]

        def dump(_args, *, output):
            self.assertEqual(stat.S_IMODE(os.fstat(output.fileno()).st_mode), 0o600)
            folder = next(self.root.glob(".zerograph-backup-*"))
            self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700)
            for file in folder.iterdir():
                self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
            output.write(b"PGDMPsynthetic-test-data")

        compose.run.side_effect = dump
        archive = self.root / "new.zip"
        with patch("deploy.backup_restore.engines", return_value=self.engines):
            backup(compose, archive)
        self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
        self.assertEqual(self.unpack(archive)["application"], self.metadata)


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
