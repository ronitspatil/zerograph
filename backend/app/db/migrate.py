from pathlib import Path

from alembic import command
from alembic.config import Config

from app.graph.repository import get_graph_store


def main() -> None:
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    command.upgrade(config, "head")
    get_graph_store().migrate()


if __name__ == "__main__":
    main()
