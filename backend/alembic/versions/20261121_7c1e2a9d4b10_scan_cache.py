"""scan_cache table

Revision ID: 7c1e2a9d4b10
Revises: 305f4fdc47ae
Create Date: 2026-11-21 00:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "7c1e2a9d4b10"
down_revision: str | Sequence[str] | None = "305f4fdc47ae"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_cache",
        sa.Column("cache_key", sa.Text(), nullable=False),
        sa.Column("scan_type", sa.Text(), nullable=False),
        sa.Column("result", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("hit_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.PrimaryKeyConstraint("cache_key"),
    )
    op.create_index("ix_scan_cache_expires_at", "scan_cache", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_scan_cache_expires_at", table_name="scan_cache")
    op.drop_table("scan_cache")
