"""Durable ingestion retry budgets, fenced leases and outbox reservations."""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ingestion_jobs", sa.Column("attempt_count", sa.Integer, nullable=False, server_default="0")
    )
    op.add_column("ingestion_jobs", sa.Column("lease_token", sa.String(64), nullable=True))
    op.add_column("ingestion_jobs", sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("ingestion_jobs", sa.Column("available_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("ingestion_jobs", sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("UPDATE ingestion_jobs SET available_at = updated_at")
    # Legacy running jobs have no lease; recovery will safely requeue them after
    # old workers have been drained during the deployment.
    with op.batch_alter_table("ingestion_jobs") as batch:
        batch.alter_column("available_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        batch.create_index("ix_ingestion_jobs_dispatch", ["status", "available_at", "dispatched_at"])
    op.add_column("source_snapshots", sa.Column("job_created_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("source_snapshots", sa.Column("job_id", sa.String(64), nullable=True))


def downgrade() -> None:
    for column in ["job_id", "job_created_at"]:
        op.drop_column("source_snapshots", column)
    with op.batch_alter_table("ingestion_jobs") as batch:
        batch.drop_index("ix_ingestion_jobs_dispatch")
        for column in ["dispatched_at", "available_at", "lease_expires_at", "lease_token", "attempt_count"]:
            batch.drop_column(column)
