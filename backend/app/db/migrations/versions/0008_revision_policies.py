"""Policy documents per revision (content-hashed) and their principal attachments."""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def scope():
    return [
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("revision", sa.String(64), primary_key=True),
    ]


def upgrade() -> None:
    op.create_table(
        "revision_policy_documents",
        *scope(),
        sa.Column("digest", sa.String(64), primary_key=True),
        sa.Column("size_bytes", sa.Integer, nullable=False),
        sa.Column("document", sa.Text, nullable=False),
    )
    op.create_table(
        "revision_policies",
        *scope(),
        sa.Column("attachment_id", sa.String(32), primary_key=True),
        sa.Column("principal_id", sa.String(512), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("arn", sa.Text, nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
    )
    op.create_index(
        "ix_revision_policies_principal", "revision_policies", ["tenant_id", "revision", "principal_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_revision_policies_principal", table_name="revision_policies")
    op.drop_table("revision_policies")
    op.drop_table("revision_policy_documents")
