"""Global-map cluster rows per revision and stored explore sample IDs."""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def scope():
    return [
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("revision", sa.String(64), primary_key=True),
    ]


def upgrade() -> None:
    with op.batch_alter_table("revision_analysis") as batch:
        batch.add_column(sa.Column("sample_ids", sa.JSON, nullable=True))
    op.create_table(
        "revision_cluster_summary",
        *scope(),
        sa.Column("cluster_version", sa.Integer, nullable=False),
        sa.Column("algorithm", sa.String(32), nullable=False),
        sa.Column("seed", sa.Integer, nullable=False),
        sa.Column("total_nodes", sa.Integer, nullable=False),
        sa.Column("total_edges", sa.Integer, nullable=False),
        sa.Column("total_clusters", sa.Integer, nullable=False),
        sa.Column("top_level", sa.Integer, nullable=False),
        sa.Column("max_depth", sa.Integer, nullable=False),
        sa.Column("isolated_nodes", sa.Integer, nullable=False),
        sa.Column("top_links", sa.Integer, nullable=False),
        sa.Column("previous_revision", sa.String(64), nullable=True),
        sa.Column("reused_ids", sa.Integer, nullable=False),
        sa.Column("compute_ms", sa.Integer, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "revision_clusters",
        *scope(),
        sa.Column("cluster_id", sa.String(32), primary_key=True),
        sa.Column("parent_id", sa.String(32), nullable=False),
        sa.Column("depth", sa.Integer, nullable=False),
        sa.Column("ordinal", sa.Integer, nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("label", sa.String(256), nullable=False),
        sa.Column("representative_id", sa.String(512), nullable=False),
        sa.Column("size", sa.Integer, nullable=False),
        sa.Column("child_count", sa.Integer, nullable=False),
        sa.Column("member_count", sa.Integer, nullable=False),
        sa.Column("internal_edges", sa.Integer, nullable=False),
        sa.Column("boundary_edges", sa.Integer, nullable=False),
        sa.Column("types", sa.JSON, nullable=False),
        sa.Column("accounts", sa.JSON, nullable=False),
    )
    op.create_index(
        "ix_revision_clusters_parent", "revision_clusters", ["tenant_id", "revision", "parent_id", "ordinal"]
    )
    op.create_table(
        "revision_cluster_links",
        *scope(),
        sa.Column("parent_id", sa.String(32), primary_key=True),
        sa.Column("source_id", sa.String(32), primary_key=True),
        sa.Column("target_id", sa.String(32), primary_key=True),
        sa.Column("weight", sa.Integer, nullable=False),
    )
    op.create_table(
        "revision_cluster_members",
        *scope(),
        sa.Column("entity_id", sa.String(512), primary_key=True),
        sa.Column("cluster_id", sa.String(32), nullable=False),
        sa.Column("top_id", sa.String(32), nullable=False),
        sa.Column("ordinal", sa.Integer, nullable=False),
        sa.Column("degree", sa.Integer, nullable=False),
        sa.Column("internal_degree", sa.Integer, nullable=False),
    )
    op.create_index(
        "ix_revision_cluster_members_leaf",
        "revision_cluster_members",
        ["tenant_id", "revision", "cluster_id", "ordinal"],
    )


def downgrade() -> None:
    op.drop_index("ix_revision_cluster_members_leaf", table_name="revision_cluster_members")
    op.drop_table("revision_cluster_members")
    op.drop_table("revision_cluster_links")
    op.drop_index("ix_revision_clusters_parent", table_name="revision_clusters")
    op.drop_table("revision_clusters")
    op.drop_table("revision_cluster_summary")
    with op.batch_alter_table("revision_analysis") as batch:
        batch.drop_column("sample_ids")
