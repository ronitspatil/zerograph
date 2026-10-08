"""Fewer indexes on revision_proposals, so a revision's ~92k proposals store faster at publish.

Proposals are stored in their deterministic order (tier, then type), so a tier or type filter
is an ordinal range of the revision derived from the stored summary counts and is served by
``ux_revision_proposals_order``; the per-tier and per-type indexes are no longer read.
"""

from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for name in ("tier", "type"):
        op.drop_index(f"ix_revision_proposals_{name}", table_name="revision_proposals")


def downgrade() -> None:
    for name, column in (("tier", "tier"), ("type", "type")):
        op.create_index(
            f"ix_revision_proposals_{name}",
            "revision_proposals",
            ["tenant_id", "revision", column, "ordinal"],
        )
