"""Optimizer rollout: least-privilege changes (PRs, canary, rollback) and AccessDenied evidence."""

import sqlalchemy as sa
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "access_denials",
        sa.Column("upload_id", sa.String(64), primary_key=True),
        sa.Column("chunk", sa.Integer, primary_key=True),
        sa.Column("principal_id", sa.String(512), primary_key=True),
        sa.Column("resource_id", sa.String(512), primary_key=True),
        sa.Column("service", sa.String(32), primary_key=True),
        sa.Column("error_code", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer, nullable=False),
    )
    op.create_index("ix_access_denials_principal", "access_denials", ["tenant_id", "principal_id"])
    op.create_table(
        "rollout_changes",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("topic_id", sa.String(32), nullable=False),
        sa.Column("subject_id", sa.String(512), nullable=False),
        sa.Column("subject_name", sa.String(256), nullable=False),
        sa.Column("proposal_ids", sa.JSON, nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("canary", sa.Boolean, nullable=False),
        sa.Column("revision", sa.String(64), nullable=False),
        sa.Column("remediation_ids", sa.JSON, nullable=False),
        sa.Column("files", sa.JSON, nullable=False),
        sa.Column("summary", sa.JSON, nullable=False),
        sa.Column("watch_days", sa.Integer, nullable=False),
        sa.Column("gitops_scope", sa.JSON, nullable=True),
        sa.Column("pr_url", sa.Text, nullable=True),
        sa.Column("merged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("flagged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("flag", sa.JSON, nullable=True),
        sa.Column("revert_scope", sa.JSON, nullable=True),
        sa.Column("revert_pr_url", sa.Text, nullable=True),
        sa.Column("revert_error", sa.String(256), nullable=True),
        sa.Column("rolled_back_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("actor", sa.String(256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_rollout_changes_tenant_id", "rollout_changes", ["tenant_id"])
    op.create_index("ix_rollout_changes_topic", "rollout_changes", ["tenant_id", "topic_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_rollout_changes_topic", "rollout_changes")
    op.drop_index("ix_rollout_changes_tenant_id", "rollout_changes")
    op.drop_table("rollout_changes")
    op.drop_index("ix_access_denials_principal", "access_denials")
    op.drop_table("access_denials")
