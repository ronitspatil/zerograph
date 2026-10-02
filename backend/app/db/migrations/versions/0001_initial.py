"""Initial tenant state, ingestion outbox, source snapshots, audit and remediation schema."""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenant_states",
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("revision", sa.String(64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "ingestion_jobs",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("actor", sa.String(256), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("source", sa.String(128), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("node_count", sa.Integer, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_ingestion_jobs_tenant_id", "ingestion_jobs", ["tenant_id"])
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("actor", sa.String(256), nullable=False),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("detail", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_events_tenant_id", "audit_events", ["tenant_id"])
    op.create_table(
        "remediations",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("actor", sa.String(256), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("identity_id", sa.String(512), nullable=False),
        sa.Column("original", sa.JSON, nullable=False),
        sa.Column("optimized", sa.JSON, nullable=False),
        sa.Column("evidence", sa.JSON, nullable=False),
        sa.Column("pr_url", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_remediations_tenant_id", "remediations", ["tenant_id"])
    op.create_table(
        "source_snapshots",
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("source", sa.String(128), primary_key=True),
        sa.Column("payload", sa.JSON, nullable=False),
    )


def downgrade() -> None:
    for table in ["source_snapshots", "remediations", "audit_events", "ingestion_jobs", "tenant_states"]:
        op.drop_table(table)
