"""scan_cache.entity_tags, so a new report can invalidate cached scans

Revision ID: 9d3f6b8e2a41
Revises: 7c1e2a9d4b10
Create Date: 2026-11-21 12:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "9d3f6b8e2a41"
down_revision: str | Sequence[str] | None = "7c1e2a9d4b10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scan_cache",
        sa.Column(
            "entity_tags",
            postgresql.ARRAY(sa.Text()),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_scan_cache_entity_tags", "scan_cache", ["entity_tags"], postgresql_using="gin"
    )


def downgrade() -> None:
    op.drop_index("ix_scan_cache_entity_tags", table_name="scan_cache")
    op.drop_column("scan_cache", "entity_tags")
