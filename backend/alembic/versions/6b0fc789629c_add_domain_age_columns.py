"""add domain age columns to sender_intelligence

Revision ID: 6b0fc789629c
Revises: bfc36c51e8db
Create Date: 2026-06-26

"""
from alembic import op
import sqlalchemy as sa

revision = '6b0fc789629c'
down_revision = 'bfc36c51e8db'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Plain ADD COLUMN only — no constraint changes, so this is safe
    # standalone on both SQLite and Postgres without batch mode.
    op.add_column('sender_intelligence', sa.Column('domain_age_checked', sa.Boolean(), nullable=True, server_default=sa.text('false')))
    op.add_column('sender_intelligence', sa.Column('domain_registered_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('sender_intelligence', sa.Column('domain_age_days', sa.Integer(), nullable=True))
    op.add_column('sender_intelligence', sa.Column('domain_is_newly_registered', sa.Boolean(), nullable=True, server_default=sa.text('false')))
    op.add_column('sender_intelligence', sa.Column('domain_registrar', sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column('sender_intelligence', 'domain_registrar')
    op.drop_column('sender_intelligence', 'domain_is_newly_registered')
    op.drop_column('sender_intelligence', 'domain_age_days')
    op.drop_column('sender_intelligence', 'domain_registered_at')
    op.drop_column('sender_intelligence', 'domain_age_checked')