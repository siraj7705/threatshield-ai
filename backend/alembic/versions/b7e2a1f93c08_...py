"""add ip_reputations table

Revision ID: b7e2a1f93c08
Revises: a3f9c7d21b4e
Create Date: 2026-06-25

"""
from alembic import op
import sqlalchemy as sa

revision = 'b7e2a1f93c08'
down_revision = 'a3f9c7d21b4e'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'ip_reputations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('email_id', sa.Integer(), nullable=False),
        sa.Column('ip', sa.String(length=45), nullable=True),
        sa.Column('checked', sa.Boolean(), nullable=True, default=False),
        sa.Column('is_vpn', sa.Boolean(), nullable=True, default=False),
        sa.Column('is_tor', sa.Boolean(), nullable=True, default=False),
        sa.Column('is_proxy', sa.Boolean(), nullable=True, default=False),
        sa.Column('is_hosting', sa.Boolean(), nullable=True, default=False),
        sa.Column('isp', sa.String(length=255), nullable=True),
        sa.Column('org', sa.String(length=255), nullable=True),
        sa.Column('country', sa.String(length=100), nullable=True),
        sa.Column('city', sa.String(length=100), nullable=True),
        sa.Column('ip_risk_score', sa.Float(), nullable=True, default=0.0),
        sa.Column('risk_reasons', sa.Text(), nullable=True),
        sa.Column('error', sa.String(length=255), nullable=True),
        sa.Column('checked_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_ip_reputations_email_id', 'ip_reputations', ['email_id'])


def downgrade() -> None:
    op.drop_index('ix_ip_reputations_email_id', table_name='ip_reputations')
    op.drop_table('ip_reputations')