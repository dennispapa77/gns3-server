"""add auth_source to users table

Revision ID: ab9aec245c08
Revises: e2a7c9d4b601
Create Date: 2026-11-09 15:57:12.659920

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "ab9aec245c08"
down_revision = "e2a7c9d4b601"
branch_labels = None
depends_on = None


def upgrade() -> None:
    existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("users")}
    if "auth_source" not in existing:
        op.add_column("users", sa.Column("auth_source", sa.String(), nullable=False, server_default="local"))


def downgrade() -> None:
    op.drop_column("users", "auth_source")
