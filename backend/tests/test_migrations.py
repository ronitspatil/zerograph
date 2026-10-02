from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

import app.db.migrations
from app.core.config import get_settings
from app.db.migrate import main


def test_initial_migration_is_repeatable_and_versioned(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path}/migrations.db"
    monkeypatch.setenv("ZG_DATABASE_URL", url)
    get_settings.cache_clear()
    main()
    main()
    engine = create_engine(url)
    assert set(inspect(engine).get_table_names()) == {
        "tenant_states",
        "ingestion_jobs",
        "source_snapshots",
        "audit_events",
        "remediations",
        "alembic_version",
    }
    engine.dispose()
    get_settings.cache_clear()


def test_upgrade_preserves_existing_jobs_and_snapshot(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path}/upgrade.db"
    monkeypatch.setenv("ZG_DATABASE_URL", url)
    get_settings.cache_clear()
    config = Config()
    config.set_main_option("script_location", str(Path(app.db.migrations.__file__).parent))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "0001")
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO ingestion_jobs "
                "(id,tenant_id,actor,status,source,payload,node_count,created_at,updated_at) "
                "VALUES ('legacy','tenant','actor','running','snapshot','{}',0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"
            )
        )
        connection.execute(
            text("INSERT INTO source_snapshots (tenant_id,source,payload) VALUES ('tenant','snapshot','{}')")
        )
    command.upgrade(config, "head")
    command.upgrade(config, "head")
    with engine.connect() as connection:
        job = connection.execute(text("SELECT * FROM ingestion_jobs WHERE id='legacy'")).mappings().one()
        assert job["status"] == "running"
        assert job["attempt_count"] == 0
        assert job["lease_token"] is None
        assert job["available_at"] == job["updated_at"]
        assert connection.execute(text("SELECT payload FROM source_snapshots")).scalar_one() == "{}"
    assert "ix_ingestion_jobs_dispatch" in {i["name"] for i in inspect(engine).get_indexes("ingestion_jobs")}
    engine.dispose()
    get_settings.cache_clear()
