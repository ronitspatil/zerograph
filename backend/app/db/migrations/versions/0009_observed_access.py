"""Observed-access store: usage uploads, staged and committed observed access, coverage."""

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "usage_uploads",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("actor", sa.String(256), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("revision", sa.String(64), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attested_services", sa.JSON, nullable=False),
        sa.Column("stats", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("committed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_usage_uploads_tenant_status", "usage_uploads", ["tenant_id", "status", "created_at"])
    op.create_table(
        "usage_upload_chunks",
        sa.Column("upload_id", sa.String(64), primary_key=True),
        sa.Column("chunk", sa.Integer, primary_key=True),
        sa.Column("size_bytes", sa.Integer, nullable=False),
        sa.Column("stats", sa.JSON, nullable=False),
    )

    def access():
        return [
            sa.Column("principal_id", sa.String(512), primary_key=True),
            sa.Column("resource_id", sa.String(512), primary_key=True),
            sa.Column("action_class", sa.String(16), primary_key=True),
            sa.Column("service", sa.String(32), primary_key=True),
            sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
            sa.Column("count", sa.Integer, nullable=False),
        ]

    op.create_table(
        "usage_staged",
        sa.Column("upload_id", sa.String(64), primary_key=True),
        sa.Column("chunk", sa.Integer, primary_key=True),
        *access(),
    )
    op.create_table(
        "observed_access",
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("upload_id", sa.String(64), primary_key=True),
        *access(),
        sa.Column("source", sa.String(32), nullable=False),
    )
    op.create_index("ix_observed_access_tenant", "observed_access", ["tenant_id", "principal_id"])
    op.create_table(
        "usage_coverage",
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("upload_id", sa.String(64), primary_key=True),
        sa.Column("service", sa.String(32), primary_key=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attested", sa.Boolean, nullable=False),
        sa.Column("events", sa.Integer, nullable=False),
        sa.Column("unmapped", sa.Integer, nullable=False),
        sa.Column("complete", sa.Boolean, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("usage_coverage")
    op.drop_index("ix_observed_access_tenant", table_name="observed_access")
    op.drop_table("observed_access")
    op.drop_table("usage_staged")
    op.drop_table("usage_upload_chunks")
    op.drop_index("ix_usage_uploads_tenant_status", table_name="usage_uploads")
    op.drop_table("usage_uploads")
