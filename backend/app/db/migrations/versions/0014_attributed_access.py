"""Attribute role-session use to the principal that assumed the role.

Staging of role sessions issued and used per uploaded file, the committed
``attributed_access`` rows, and ``usage_uploads.attributed`` (uploads committed before
this migration have no attribution and keep role-level credit).
"""

import sqlalchemy as sa
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "usage_uploads", sa.Column("attributed", sa.Boolean, nullable=False, server_default=sa.false())
    )
    op.create_table(
        "usage_session_issued",
        sa.Column("upload_id", sa.String(64), primary_key=True),
        sa.Column("chunk", sa.Integer, primary_key=True),
        sa.Column("ordinal", sa.Integer, primary_key=True),
        sa.Column("access_key", sa.String(128), nullable=False),
        sa.Column("session_arn", sa.String(512), nullable=False),
        sa.Column("role_id", sa.String(512), nullable=False),
        sa.Column("principal_id", sa.String(512), nullable=False),
        sa.Column("parent_key", sa.String(128), nullable=False),
        sa.Column("parent_role", sa.String(512), nullable=False),
        sa.Column("source_identity", sa.String(128), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "usage_session_staged",
        sa.Column("upload_id", sa.String(64), primary_key=True),
        sa.Column("chunk", sa.Integer, primary_key=True),
        sa.Column("ordinal", sa.Integer, primary_key=True),
        sa.Column("role_id", sa.String(512), nullable=False),
        sa.Column("access_key", sa.String(128), nullable=False),
        sa.Column("session_arn", sa.String(512), nullable=False),
        sa.Column("source_identity", sa.String(128), nullable=False),
        sa.Column("on_behalf_of", sa.String(512), nullable=False),
        sa.Column("resource_id", sa.String(512), nullable=False),
        sa.Column("action_class", sa.String(16), nullable=False),
        sa.Column("service", sa.String(32), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer, nullable=False),
    )
    op.create_table(
        "attributed_access",
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("upload_id", sa.String(64), primary_key=True),
        sa.Column("ordinal", sa.Integer, primary_key=True),
        sa.Column("identity_id", sa.String(512), nullable=False),
        sa.Column("role_id", sa.String(512), nullable=False),
        sa.Column("resource_id", sa.String(512), nullable=False),
        sa.Column("action_class", sa.String(16), nullable=False),
        sa.Column("service", sa.String(32), nullable=False),
        sa.Column("basis", sa.String(16), nullable=False),
        sa.Column("depth", sa.Integer, nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer, nullable=False),
    )
    op.create_index("ix_attributed_access_role", "attributed_access", ["tenant_id", "role_id"])


def downgrade() -> None:
    op.drop_index("ix_attributed_access_role", table_name="attributed_access")
    op.drop_table("attributed_access")
    op.drop_table("usage_session_staged")
    op.drop_table("usage_session_issued")
    op.drop_column("usage_uploads", "attributed")
