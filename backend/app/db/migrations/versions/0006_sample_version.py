"""Version of the stored explore sample, so older ID-sorted samples can be refreshed."""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("revision_analysis") as batch:
        batch.add_column(sa.Column("sample_version", sa.Integer, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("revision_analysis") as batch:
        batch.drop_column("sample_version")
