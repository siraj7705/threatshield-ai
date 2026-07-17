"""add domain age columns to url_analyses

Revision ID: 5a446735f151
Revises: 6b0fc789629c
Create Date: 2026-06-26

"""
from alembic import op
import sqlalchemy as sa

revision = '5a446735f151'
down_revision = '6b0fc789629c'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Plain ADD COLUMN only — safe standalone on both SQLite and Postgres.
    op.add_column('url_analyses', sa.Column('domain_age_checked_url', sa.Text(), nullable=True))
    op.add_column('url_analyses', sa.Column('domain_age_days', sa.Integer(), nullable=True))
    op.add_column('url_analyses', sa.Column('domain_is_newly_registered', sa.Boolean(), nullable=True, server_default=sa.text('false')))


def downgrade() -> None:
    op.drop_column('url_analyses', 'domain_is_newly_registered')
    op.drop_column('url_analyses', 'domain_age_days')
    op.drop_column('url_analyses', 'domain_age_checked_url')