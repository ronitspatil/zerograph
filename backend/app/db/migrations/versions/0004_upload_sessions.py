"""Upload sessions and staged entity rows for chunked ingestion and row-based sources."""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "upload_sessions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("actor", sa.String(256), nullable=False),
        sa.Column("source", sa.String(128), nullable=False),
        sa.Column("origin", sa.String(16), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("node_count", sa.Integer, nullable=False),
        sa.Column("edge_count", sa.Integer, nullable=False),
        sa.Column("warning_count", sa.Integer, nullable=False),
        sa.Column("job_id", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_upload_sessions_tenant_status", "upload_sessions", ["tenant_id", "status", "expires_at"]
    )
    op.create_table(
        "staged_entities",
        sa.Column("session_id", sa.String(64), primary_key=True),
        sa.Column("kind", sa.String(8), primary_key=True),
        sa.Column("entity_id", sa.String(512), primary_key=True),
        sa.Column("chunk", sa.Integer, nullable=False),
        sa.Column("ordinal", sa.Integer, nullable=False),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("source_id", sa.String(512), nullable=True),
        sa.Column("target_id", sa.String(512), nullable=True),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("payload", sa.Text, nullable=False),
    )
    op.create_index("ix_staged_entities_order", "staged_entities", ["session_id", "chunk", "ordinal"])


def downgrade() -> None:
    op.drop_index("ix_staged_entities_order", table_name="staged_entities")
    op.drop_table("staged_entities")
    op.drop_index("ix_upload_sessions_tenant_status", table_name="upload_sessions")
    op.drop_table("upload_sessions")
