"""Excess-privilege columns on topic members and the usage fingerprint of topic rows."""

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

MEMBER_COLUMNS = (
    ("needed_weight", 0),
    ("needed_weight_excl_hubs", 0),
    ("used_resources", 0),
    ("unused_grants", 0),
    ("unused_restricted", 0),
)


def upgrade() -> None:
    with op.batch_alter_table("revision_topic_summary") as batch:
        batch.add_column(sa.Column("usage_fingerprint", sa.String(32), nullable=False, server_default=""))
    with op.batch_alter_table("revision_topic_members") as batch:
        batch.add_column(sa.Column("basis", sa.String(16), nullable=False, server_default=""))
        for name, default in MEMBER_COLUMNS:
            batch.add_column(sa.Column(name, sa.Integer, nullable=False, server_default=str(default)))


def downgrade() -> None:
    with op.batch_alter_table("revision_topic_members") as batch:
        for name, _ in reversed(MEMBER_COLUMNS):
            batch.drop_column(name)
        batch.drop_column("basis")
    with op.batch_alter_table("revision_topic_summary") as batch:
        batch.drop_column("usage_fingerprint")
