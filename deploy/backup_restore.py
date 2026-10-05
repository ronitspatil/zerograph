"""Offline, release-bound logical backup/restore for dedicated Compose projects.

Archive format version 2 streams the graph as NDJSON (``graph.ndjson``); version 1
archives (one ``graph.json`` document) are still verified and restored.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BRIDGE = Path(__file__).with_name("_snapshot_bridge.py")
FORMAT_VERSION = 2
GRAPH_MEMBER = {1: "graph.json", 2: "graph.ndjson"}
MEMBERS = {"manifest.json", "postgres.dump", GRAPH_MEMBER[FORMAT_VERSION]}
# Host-side archive bounds. Per-revision node/edge bounds are enforced by the bridge
# from the application's publication caps (ZG_MAX_NODES / ZG_MAX_EDGES).
LIMITS = {
    "manifest.json": 1_000_000,
    "postgres.dump": int(os.environ.get("ZG_BACKUP_MAX_DUMP_BYTES", 20_000_000_000)),
    "graph.json": 100_000_000,
    "graph.ndjson": int(os.environ.get("ZG_BACKUP_MAX_GRAPH_BYTES", 50_000_000_000)),
}
GRAPH_FORMAT = "zerograph-graph"


def stream_header(path):
    """Header metadata of a version 2 graph stream, plus structural checks of the rest."""
    with path.open("rb") as stream:
        header = json.loads(stream.readline())
        if header.get("format") != GRAPH_FORMAT or header.get("version") != 2:
            raise BackupError("Unsupported graph stream")
        identities, ended = [], False
        for raw in stream:
            if ended:
                raise BackupError("Data after graph end marker")
            if raw.startswith(b'{"revision":'):
                entry = json.loads(raw)["revision"]
                identities.append((entry["tenant"], entry["revision"]))
            elif raw.startswith(b'{"end":'):
                end = json.loads(raw)["end"]
                ended = end.get("revisions") == len(identities)
                if not ended:
                    raise BackupError("Graph archive totals do not match")
        if not ended:
            raise BackupError("Truncated graph archive")
    return header["metadata"], identities


class BackupError(Exception):
    pass


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def private_file(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")


def read_archive(archive, destination):
    """Fixed-member extraction: bounded sizes, no traversal, symlinks or overwrite."""
    try:
        with zipfile.ZipFile(archive) as zipped:
            infos = zipped.infolist()
            names = {info.filename for info in infos}
            graph_member = next((GRAPH_MEMBER[v] for v in GRAPH_MEMBER if GRAPH_MEMBER[v] in names), None)
            expected = {"manifest.json", "postgres.dump", graph_member}
            if graph_member is None or len(infos) != 3 or names != expected:
                raise BackupError("Archive must contain only the three expected members")
            for info in infos:
                if (
                    info.file_size > LIMITS[info.filename]
                    or info.flag_bits & 1
                    or stat.S_ISLNK(info.external_attr >> 16)
                    or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                ):
                    raise BackupError("Unsupported or oversized archive member")
                target = destination / info.filename
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as output, zipped.open(info) as source:
                    total = 0
                    while chunk := source.read(1024 * 1024):
                        total += len(chunk)
                        if total > LIMITS[info.filename]:
                            raise BackupError("Oversized archive member")
                        output.write(chunk)
            manifest = json.loads((destination / "manifest.json").read_text())
            if (
                manifest.get("format") != "zerograph-compose-backup"
                or manifest.get("version") not in GRAPH_MEMBER
                or GRAPH_MEMBER[manifest["version"]] != graph_member
            ):
                raise BackupError("Unsupported backup format")
            if manifest.get("checksums", {}).keys() != {"postgres.dump", graph_member}:
                raise BackupError("Missing backup checksums")
            for name, expected in manifest["checksums"].items():
                if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                    raise BackupError("Invalid backup checksum")
                if digest(destination / name) != expected:
                    raise BackupError("Backup checksum mismatch")
            engines = manifest.get("engines", {})
            if engines.get("graph", {}).get("vendor") != "memgraph":
                raise BackupError("Only Memgraph archives are supported")
            if engines["graph"].get("version") != "3.2.0" or engines.get("postgres", {}).get("major") != 16:
                raise BackupError("Unsupported database version")
            if manifest["version"] == 1:
                graph = json.loads((destination / "graph.json").read_text())
                metadata = graph.get("metadata")
                listed = [(item["tenant"], item["revision"]) for item in graph["snapshots"]]
            else:
                metadata, listed = stream_header(destination / "graph.ndjson")
            if metadata != manifest.get("application"):
                raise BackupError("Graph and manifest metadata differ")
            if metadata["schema_revision"] != metadata["schema_head"]:
                raise BackupError("Source schema was not fully migrated")
            identities = set(listed)
            if len(identities) != len(listed):
                raise BackupError("Duplicate archived graph revision")
            for link in metadata["revision_links"]:
                if link["revision"] and (link["tenant"], link["revision"]) not in identities:
                    raise BackupError("Archived SQL pointer has no graph revision")
            return manifest
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        zipfile.BadZipFile,
        RuntimeError,
    ) as exc:
        raise BackupError("Archive is corrupt or incompatible") from exc


class Compose:
    def __init__(self, project):
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project):
            raise BackupError("Specify an explicit valid Compose project name")
        self.command = [
            "docker",
            "compose",
            "--project-name",
            project,
            "-f",
            str(ROOT / "docker-compose.yml"),
        ]

    def run(self, arguments, *, input=None, output=None, stdin=None):
        result = subprocess.run(
            self.command + arguments,
            cwd=ROOT,
            input=input,
            stdin=stdin,
            stdout=output if output is not None else subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=1800,
            check=False,
        )
        if result.returncode:
            # Docker/driver stderr can include deployment configuration. Never echo it.
            raise BackupError("Compose operation failed; inspect the dedicated project's service health")
        return result.stdout if output is None else b""

    def bridge(self, action, data=None, *, stdin=None, output=None):
        """Run a bridge action; with ``output`` its NDJSON stream goes to that file."""
        try:
            result = self.run(
                ["run", "--rm", "--no-deps", "-T", "backend", "python", "-c", BRIDGE.read_text(), action],
                input=data,
                stdin=stdin,
                output=output,
            )
            return None if output is not None else json.loads(result)
        except BackupError as exc:
            raise BackupError(
                f"Snapshot {action} failed; check offline state and release compatibility"
            ) from exc

    def offline(self):
        raw = self.run(["ps", "--all", "--format", "json"]).decode()
        records = (
            json.loads(raw)
            if raw.lstrip().startswith("[")
            else [json.loads(line) for line in raw.splitlines() if line]
        )
        services = {record["Service"]: record for record in records}
        for service, record in services.items():
            if service not in {"postgres", "memgraph", "redis"} and record["State"] in {
                "running",
                "restarting",
                "paused",
            }:
                raise BackupError(
                    "Stop frontend, API, workers, scheduler, migrations and all external writers first"
                )
        if not all(
            services.get(service, {}).get("State") == "running" for service in ("postgres", "memgraph")
        ):
            raise BackupError("The dedicated PostgreSQL and Memgraph stores must be running")
        return services

    def sql(self, query):
        return (
            self.run(
                [
                    "exec",
                    "-T",
                    "postgres",
                    "psql",
                    "-X",
                    "-A",
                    "-t",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-U",
                    "zerograph",
                    "-d",
                    "zerograph",
                    "-c",
                    query,
                ]
            )
            .decode()
            .strip()
        )

    def image(self, container):
        result = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                '{"id":"{{.Image}}","ref":"{{.Config.Image}}"}',
                container,
            ],
            capture_output=True,
            check=False,
            timeout=30,
        )
        if result.returncode:
            raise BackupError("Cannot inspect database release")
        return json.loads(result.stdout)

    def backend_image(self):
        result = subprocess.run(
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                "zerograph-backend:local",
            ],
            capture_output=True,
            check=False,
            timeout=30,
        )
        if result.returncode:
            raise BackupError("Build the matching backend image first")
        return result.stdout.decode().strip()


def engines(compose, services):
    postgres = compose.image(services["postgres"]["ID"])
    graph = compose.image(services["memgraph"]["ID"])
    major = int(compose.sql("SHOW server_version_num")) // 10000
    if major != 16 or graph["ref"] != "memgraph/memgraph:3.2.0":
        raise BackupError("Only PostgreSQL 16 and Memgraph 3.2.0 Compose deployments are supported")
    return {
        "postgres": {**postgres, "major": major},
        "graph": {**graph, "vendor": "memgraph", "version": "3.2.0"},
    }


def backup(compose, archive):
    if archive.exists():
        raise BackupError("Refusing to overwrite an existing backup")
    services = compose.offline()
    source_engines = engines(compose, services)
    backend_image = compose.backend_image()
    if "backend" not in services or compose.image(services["backend"]["ID"])["id"] != backend_image:
        raise BackupError("Backup must use the source application's exact backend image")
    graph_name = GRAPH_MEMBER[FORMAT_VERSION]
    with tempfile.TemporaryDirectory(prefix=".zerograph-backup-", dir=archive.parent) as temporary:
        folder = Path(temporary)
        graph_file = folder / graph_name
        with private_file(graph_file) as output:
            compose.bridge("export", output=output)
        application, _ = stream_header(graph_file)
        with private_file(folder / "postgres.dump") as output:
            compose.run(
                [
                    "exec",
                    "-T",
                    "postgres",
                    "pg_dump",
                    "-U",
                    "zerograph",
                    "-d",
                    "zerograph",
                    "--format=custom",
                    "--no-owner",
                    "--no-acl",
                ],
                output=output,
            )
        if compose.bridge("metadata") != application:
            raise BackupError("Source changed during backup; enforce exclusive offline maintenance")
        compose.offline()
        manifest = {
            "format": "zerograph-compose-backup",
            "version": FORMAT_VERSION,
            "created_at": datetime.now(UTC).isoformat(),
            "engines": source_engines,
            "backend_image_id": backend_image,
            "application": application,
            "checksums": {name: digest(folder / name) for name in ("postgres.dump", graph_name)},
        }
        with private_file(folder / "manifest.json") as output:
            output.write(json.dumps(manifest, sort_keys=True, indent=2).encode())
        candidate = folder / "backup.zip"
        with private_file(candidate) as output:
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as zipped:
                for name in sorted(MEMBERS):
                    if (folder / name).stat().st_size > LIMITS[name]:
                        raise BackupError("Backup exceeds supported archive size")
                    zipped.write(folder / name, arcname=name)
            output.flush()
            os.fsync(output.fileno())
        os.link(candidate, archive)  # Atomic publication, never replace another archive.
        directory_fd = os.open(archive.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def restore(compose, archive):
    with tempfile.TemporaryDirectory(prefix="zerograph-restore-") as temporary:
        folder = Path(temporary)
        manifest = read_archive(archive, folder)  # No Docker or writes to target before archive validation.
        services = compose.offline()
        if (
            engines(compose, services) != manifest["engines"]
            or compose.backend_image() != manifest["backend_image_id"]
        ):
            raise BackupError("Restore requires the original database and backend image IDs")
        graph_file = folder / "graph.ndjson"
        if manifest["version"] == 1:
            # Rewrite the legacy document as the equivalent stream; the rest of the
            # restore (validation, import, final comparison) is format-independent.
            with (folder / "graph.json").open("rb") as legacy, private_file(graph_file) as output:
                compose.bridge("convert-v1", stdin=legacy, output=output)
        with graph_file.open("rb") as stream:
            if compose.bridge("validate", stdin=stream) != manifest["application"]:
                raise BackupError("Application backup metadata is incompatible")
        public_objects = (
            "SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public')"
            "+(SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public')"
            "+(SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public')"
        )
        if compose.sql(public_objects) != "0":
            raise BackupError(
                "Restore requires an empty PostgreSQL database; never restore over existing state"
            )
        compose.bridge("empty")
        # pg_restore verifies the archive before any database mutation.
        with (folder / "postgres.dump").open("rb") as dump:
            compose.run(["exec", "-T", "postgres", "pg_restore", "--list"], stdin=dump)
        compose.offline()
        with graph_file.open("rb") as stream:
            compose.bridge("import", stdin=stream)
        with (folder / "postgres.dump").open("rb") as dump:
            compose.run(
                [
                    "exec",
                    "-T",
                    "postgres",
                    "pg_restore",
                    "-U",
                    "zerograph",
                    "-d",
                    "zerograph",
                    "--single-transaction",
                    "--exit-on-error",
                    "--no-owner",
                    "--no-acl",
                ],
                stdin=dump,
            )
        if compose.bridge("metadata") != manifest["application"]:
            raise BackupError("Restored SQL metadata does not match the archived graph; keep target offline")
        exported = folder / "restored.ndjson"
        with private_file(exported) as output:
            compose.bridge("export", output=output)
        if digest(exported) != digest(graph_file):
            raise BackupError("Restored graph differs from the archive; keep target offline")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["backup", "restore", "verify"])
    parser.add_argument(
        "--project",
        help="Dedicated offline Compose project name (required except verify)",
    )
    parser.add_argument("--archive", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.action == "verify":
            with tempfile.TemporaryDirectory(prefix="zerograph-verify-") as temporary:
                read_archive(args.archive, Path(temporary))
        else:
            if not args.project:
                raise BackupError("Specify --project explicitly")
            action = backup if args.action == "backup" else restore
            action(Compose(args.project), args.archive.resolve())
        print(
            f"{args.action.capitalize()} verified. Keep maintenance exclusive until stores and application are ready."
        )
    except BackupError as exc:
        # BackupError text is authored here, never raw driver/SQL/Docker diagnostics.
        parser.exit(1, f"{exc}. Keep the target offline and preserve state.\n")
    except (OSError, subprocess.SubprocessError, ValueError):
        parser.exit(
            1,
            "Operation refused or failed. Preserve source/target state and inspect archive compatibility, offline state and service health.\n",
        )


if __name__ == "__main__":
    main()
