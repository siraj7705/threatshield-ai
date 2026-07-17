"""add attachment_scans table

Revision ID: c1d4e8f02a9b
Revises: b7e2a1f93c08
Create Date: 2026-06-25

"""
from alembic import op
import sqlalchemy as sa

revision = 'c1d4e8f02a9b'
down_revision = 'b7e2a1f93c08'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'attachment_scans',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('email_id', sa.Integer(), nullable=False),

        # File identity
        sa.Column('filename', sa.String(length=255), nullable=True),
        sa.Column('content_type', sa.String(length=100), nullable=True),
        sa.Column('file_size', sa.Integer(), nullable=True, default=0),

        # Extraction
        sa.Column('extraction_ok', sa.Boolean(), nullable=True, default=False),
        sa.Column('extraction_method', sa.String(length=30), nullable=True),
        sa.Column('extraction_error', sa.Text(), nullable=True),
        sa.Column('extracted_text_preview', sa.Text(), nullable=True),

        # NLP
        sa.Column('threat_detected', sa.Boolean(), nullable=True, default=False),
        sa.Column('threat_type', sa.String(length=50), nullable=True),
        sa.Column('threat_target', sa.Text(), nullable=True),
        sa.Column('threat_description', sa.Text(), nullable=True),
        sa.Column('confidence_score', sa.Float(), nullable=True, default=0.0),
        sa.Column('severity', sa.String(length=20), nullable=True, default='safe'),
        sa.Column('intent_score', sa.Float(), nullable=True, default=0.0),
        sa.Column('urgency_score', sa.Float(), nullable=True, default=0.0),
        sa.Column('keywords_found', sa.Text(), nullable=True),

        # Risk
        sa.Column('attachment_risk_score', sa.Float(), nullable=True, default=0.0),
        sa.Column('risk_reasons', sa.Text(), nullable=True),

        sa.Column('scanned_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),

        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_attachment_scans_email_id', 'attachment_scans', ['email_id'])


def downgrade() -> None:
    op.drop_index('ix_attachment_scans_email_id', table_name='attachment_scans')
    op.drop_table('attachment_scans')