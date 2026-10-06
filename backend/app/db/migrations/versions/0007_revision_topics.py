"""Relationship topics and structural privilege analysis per revision."""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def scope():
    return [
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("revision", sa.String(64), primary_key=True),
    ]


def upgrade() -> None:
    op.create_table(
        "revision_topic_summary",
        *scope(),
        sa.Column("topic_version", sa.Integer, nullable=False),
        sa.Column("total_topics", sa.Integer, nullable=False),
        sa.Column("total_links", sa.Integer, nullable=False),
        sa.Column("totals", sa.JSON, nullable=False),
        sa.Column("compute_ms", sa.Integer, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "revision_topics",
        *scope(),
        sa.Column("topic_id", sa.String(32), primary_key=True),
        sa.Column("ordinal", sa.Integer, nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("label", sa.String(256), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False),
        sa.Column("resources", sa.Integer, nullable=False),
        sa.Column("resource_weight", sa.Integer, nullable=False),
        sa.Column("roles", sa.Integer, nullable=False),
        sa.Column("identities", sa.Integer, nullable=False),
        sa.Column("cross_grants_out", sa.Integer, nullable=False),
        sa.Column("cross_grants_in", sa.Integer, nullable=False),
        sa.Column("hub_grants_in", sa.Integer, nullable=False),
        sa.Column("overprivileged_roles", sa.Integer, nullable=False),
        sa.Column("stats", sa.JSON, nullable=False),
    )
    op.create_index("ix_revision_topics_order", "revision_topics", ["tenant_id", "revision", "ordinal"])
    op.create_table(
        "revision_topic_links",
        *scope(),
        sa.Column("source_id", sa.String(32), primary_key=True),
        sa.Column("target_id", sa.String(32), primary_key=True),
        sa.Column("weight", sa.Integer, nullable=False),
    )
    op.create_table(
        "revision_topic_members",
        *scope(),
        sa.Column("entity_id", sa.String(512), primary_key=True),
        sa.Column("topic_id", sa.String(32), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("ordinal", sa.Integer, nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("sensitivity", sa.String(16), nullable=False),
        sa.Column("seed", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(256), nullable=False),
        sa.Column("flags", sa.Integer, nullable=False),
        sa.Column("direct_grants", sa.Integer, nullable=False),
        sa.Column("reach_resources", sa.Integer, nullable=False),
        sa.Column("reach_weight", sa.Integer, nullable=False),
        sa.Column("reach_weight_excl_hubs", sa.Integer, nullable=False),
        sa.Column("cross_topic_grants", sa.Integer, nullable=False),
        sa.Column("restricted_outside", sa.Integer, nullable=False),
        sa.Column("profile", sa.JSON, nullable=False),
    )
    op.create_index(
        "ix_revision_topic_members_page",
        "revision_topic_members",
        ["tenant_id", "revision", "topic_id", "kind", "ordinal"],
    )


def downgrade() -> None:
    op.drop_index("ix_revision_topic_members_page", table_name="revision_topic_members")
    op.drop_table("revision_topic_members")
    op.drop_table("revision_topic_links")
    op.drop_index("ix_revision_topics_order", table_name="revision_topics")
    op.drop_table("revision_topics")
    op.drop_table("revision_topic_summary")
