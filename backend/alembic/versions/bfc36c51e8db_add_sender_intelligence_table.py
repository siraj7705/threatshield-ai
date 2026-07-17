"""add sender_intelligence table

Revision ID: bfc36c51e8db
Revises: c1d4e8f02a9b
Create Date: 2026-06-25

"""
from alembic import op
import sqlalchemy as sa

revision = 'bfc36c51e8db'
down_revision = 'c1d4e8f02a9b'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'sender_intelligence',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),

        # Identity
        sa.Column('sender_email', sa.String(length=255), nullable=False),
        sa.Column('sender_domain', sa.String(length=255), nullable=False),

        # Volume history
        sa.Column('total_emails_seen', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('threat_emails_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('safe_emails_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('blocked_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('quarantined_count', sa.Integer(), nullable=False, server_default='0'),

        # Score history
        sa.Column('avg_threat_score', sa.Float(), nullable=True, server_default='0.0'),
        sa.Column('max_threat_score', sa.Float(), nullable=True, server_default='0.0'),
        sa.Column('last_threat_score', sa.Float(), nullable=True, server_default='0.0'),

        # Derived reputation
        sa.Column('reputation_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('reputation_label', sa.String(length=20), nullable=True, server_default='unknown'),

        # Flags
        sa.Column('is_known_malicious', sa.Boolean(), nullable=True, server_default=sa.text('false')),
        sa.Column('is_repeat_offender', sa.Boolean(), nullable=True, server_default=sa.text('false')),
        sa.Column('is_trusted', sa.Boolean(), nullable=True, server_default=sa.text('false')),

        # Domain-level signals
        sa.Column('domain_is_disposable', sa.Boolean(), nullable=True, server_default=sa.text('false')),
        sa.Column('domain_is_typosquat', sa.Boolean(), nullable=True, server_default=sa.text('false')),
        sa.Column('domain_is_lookalike', sa.Boolean(), nullable=True, server_default=sa.text('false')),
        sa.Column('domain_is_suspicious_tld', sa.Boolean(), nullable=True, server_default=sa.text('false')),
        sa.Column('impersonated_brand', sa.String(length=100), nullable=True),

        # Timestamps
        sa.Column('first_seen', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.Column('last_seen', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.Column('last_threat_at', sa.DateTime(timezone=True), nullable=True),

        # Notes
        sa.Column('notes', sa.Text(), nullable=True),

        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('sender_email', name='uq_sender_intelligence_sender_email'),
    )
    op.create_index('ix_sender_intelligence_sender_email', 'sender_intelligence', ['sender_email'])
    op.create_index('ix_sender_intelligence_sender_domain', 'sender_intelligence', ['sender_domain'])


def downgrade() -> None:
    op.drop_index('ix_sender_intelligence_sender_domain', table_name='sender_intelligence')
    op.drop_index('ix_sender_intelligence_sender_email', table_name='sender_intelligence')
    op.drop_table('sender_intelligence')