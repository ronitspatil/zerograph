"""Optimizer proposals per revision, their what-if model, and per-tenant decisions."""

import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def scope():
    return [
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("revision", sa.String(64), primary_key=True),
    ]


def upgrade() -> None:
    op.create_table(
        "revision_proposal_summary",
        *scope(),
        sa.Column("proposal_version", sa.Integer, nullable=False),
        sa.Column("usage_fingerprint", sa.String(32), nullable=False, server_default=""),
        sa.Column("total", sa.Integer, nullable=False),
        sa.Column("totals", sa.JSON, nullable=False),
        sa.Column("compute_ms", sa.Integer, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "revision_proposal_models",
        *scope(),
        sa.Column("proposal_version", sa.Integer, nullable=False),
        sa.Column("model", sa.LargeBinary, nullable=False),
    )
    op.create_table(
        "revision_proposals",
        *scope(),
        sa.Column("proposal_id", sa.String(32), primary_key=True),
        sa.Column("ordinal", sa.Integer, nullable=False),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("tier", sa.String(16), nullable=False),
        sa.Column("base_tier", sa.String(16), nullable=False),
        sa.Column("topic_id", sa.String(32), nullable=False),
        sa.Column("subject_id", sa.String(512), nullable=False),
        sa.Column("subject_name", sa.String(256), nullable=False),
        sa.Column("subject_type", sa.String(32), nullable=False),
        sa.Column("target_id", sa.String(512), nullable=False),
        sa.Column("target_name", sa.String(256), nullable=False),
        sa.Column("weight", sa.Integer, nullable=False),
        sa.Column("identities", sa.Integer, nullable=False),
        sa.Column("epi_before", sa.Float, nullable=True),
        sa.Column("epi_after", sa.Float, nullable=True),
        sa.Column("reasons", sa.JSON, nullable=False),
        sa.Column("evidence", sa.JSON, nullable=False),
        sa.Column("changes", sa.JSON, nullable=False),
        sa.Column("digest", sa.String(16), nullable=False),
    )
    op.create_index(
        "ux_revision_proposals_order", "revision_proposals", ["tenant_id", "revision", "ordinal"], unique=True
    )
    for name, column in (("tier", "tier"), ("type", "type"), ("topic", "topic_id")):
        op.create_index(
            f"ix_revision_proposals_{name}",
            "revision_proposals",
            ["tenant_id", "revision", column, "ordinal"],
        )
    op.create_index(
        "ix_revision_proposals_subject", "revision_proposals", ["tenant_id", "revision", "subject_id"]
    )
    op.create_index(
        "ix_revision_proposals_target", "revision_proposals", ["tenant_id", "revision", "target_id"]
    )
    op.create_table(
        "proposal_decisions",
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("proposal_id", sa.String(32), primary_key=True),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("actor", sa.String(256), nullable=False),
        sa.Column("revision", sa.String(64), nullable=False),
        sa.Column("digest", sa.String(16), nullable=False),
        sa.Column("note", sa.String(500), nullable=False, server_default=""),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("proposal_decisions")
    for name in ("target", "subject", "topic", "type", "tier"):
        op.drop_index(f"ix_revision_proposals_{name}", table_name="revision_proposals")
    op.drop_index("ux_revision_proposals_order", table_name="revision_proposals")
    op.drop_table("revision_proposals")
    op.drop_table("revision_proposal_models")
    op.drop_table("revision_proposal_summary")
