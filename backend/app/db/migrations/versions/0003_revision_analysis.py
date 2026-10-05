"""Per-revision analysis rows written at publication time."""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "revision_analysis",
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("revision", sa.String(64), primary_key=True),
        sa.Column("analysis_version", sa.Integer, nullable=False),
        sa.Column("overview", sa.JSON, nullable=False),
        sa.Column("total_nodes", sa.Integer, nullable=False),
        sa.Column("total_edges", sa.Integer, nullable=False),
        sa.Column("total_roles", sa.Integer, nullable=False),
        sa.Column("total_role_edges", sa.Integer, nullable=False),
        sa.Column("total_findings", sa.Integer, nullable=False),
        sa.Column("total_asset_weight", sa.Integer, nullable=False),
        sa.Column("high_blast_ids", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "revision_findings",
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("revision", sa.String(64), primary_key=True),
        sa.Column("ordinal", sa.Integer, primary_key=True),
        sa.Column("finding_id", sa.String(64), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
    )
    op.create_index(
        "ux_revision_findings_finding",
        "revision_findings",
        ["tenant_id", "revision", "finding_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ux_revision_findings_finding", table_name="revision_findings")
    op.drop_table("revision_findings")
    op.drop_table("revision_analysis")
