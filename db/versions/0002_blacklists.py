"""Add blacklists table.

Revision ID: 0002
Revises: 0001
"""

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "blacklists",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("list_name", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_blacklists_list_name_value",
        "blacklists",
        ["list_name", "value"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_blacklists_list_name_value", table_name="blacklists")
    op.drop_table("blacklists")
