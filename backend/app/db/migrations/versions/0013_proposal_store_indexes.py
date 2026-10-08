"""Store a revision's ~92k proposals faster at publish.

* Proposals are stored in their deterministic order (tier, then type), so a tier or type
  filter is an ordinal range of the revision derived from the stored summary counts and is
  served by ``ux_revision_proposals_order``: the per-tier and per-type indexes are dropped.
* The proposal ID columns (and the decision columns joined to them) compare byte-wise
  ("C" collation) on PostgreSQL: they are opaque IDs only ever compared for equality, and
  locale-aware comparison was most of the index insert cost. Results are unchanged.
"""

from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None

BYTE_WISE = {
    "revision_proposals": (
        ("tenant_id", 128),
        ("revision", 64),
        ("proposal_id", 32),
        ("topic_id", 32),
        ("subject_id", 512),
        ("target_id", 512),
    ),
    "proposal_decisions": (("tenant_id", 128), ("proposal_id", 32)),
}


def _collate(collation: str) -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table, columns in BYTE_WISE.items():
        # One statement per table: its indexes are rebuilt once (no table rewrite).
        clauses = ", ".join(
            f'ALTER COLUMN {column} TYPE VARCHAR({length}) COLLATE "{collation}"' for column, length in columns
        )
        op.execute(f"ALTER TABLE {table} {clauses}")


def upgrade() -> None:
    for name in ("tier", "type"):
        op.drop_index(f"ix_revision_proposals_{name}", table_name="revision_proposals")
    _collate("C")


def downgrade() -> None:
    _collate("default")
    for name, column in (("tier", "tier"), ("type", "type")):
        op.create_index(
            f"ix_revision_proposals_{name}",
            "revision_proposals",
            ["tenant_id", "revision", column, "ordinal"],
        )
