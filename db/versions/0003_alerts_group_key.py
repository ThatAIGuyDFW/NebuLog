"""Add group_key to alerts for correlation deduplication.

Revision ID: 0003
Revises: 0002
"""

from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("alerts", sa.Column("group_key", sa.Text(), nullable=True))
    op.create_index("idx_alerts_group_key", "alerts", ["rule_id", "group_key"])


def downgrade() -> None:
    op.drop_index("idx_alerts_group_key", table_name="alerts")
    op.drop_column("alerts", "group_key")
