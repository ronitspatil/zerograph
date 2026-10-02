from sqlalchemy import create_engine, inspect

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
