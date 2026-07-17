"""add gmail_accounts table for per-user Gmail OAuth

Revision ID: a3f9c7d21b4e
Revises: 8fb52e39111c
Create Date: 2026-06-23 11:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a3f9c7d21b4e'
down_revision: Union[str, Sequence[str], None] = '8fb52e39111c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'gmail_accounts',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('gmail_address', sa.String(length=255), nullable=False),
        sa.Column('encrypted_access_token', sa.Text(), nullable=True),
        sa.Column('encrypted_refresh_token', sa.Text(), nullable=False),
        sa.Column('token_expiry', sa.DateTime(timezone=True), nullable=True),
        sa.Column('granted_scopes', sa.Text(), nullable=True),
        sa.Column('watch_history_id', sa.String(length=50), nullable=True),
        sa.Column('watch_expiry', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_watching', sa.Boolean(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('last_synced_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('connected_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'gmail_address', name='uq_gmail_account_user_address'),
    )
    op.create_index(op.f('ix_gmail_accounts_user_id'), 'gmail_accounts', ['user_id'], unique=False)
    op.create_index(op.f('ix_gmail_accounts_gmail_address'), 'gmail_accounts', ['gmail_address'], unique=False)

    op.add_column('emails', sa.Column('gmail_account_id', sa.Integer(), nullable=True))
    with op.batch_alter_table('emails', schema=None) as batch_op:
        batch_op.create_index(op.f('ix_emails_gmail_account_id'), ['gmail_account_id'], unique=False)
        batch_op.create_foreign_key(
            'fk_emails_gmail_account_id',
            'gmail_accounts',
            ['gmail_account_id'], ['id'],
            ondelete='SET NULL',
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('emails', schema=None) as batch_op:
        batch_op.drop_constraint('fk_emails_gmail_account_id', type_='foreignkey')
        batch_op.drop_index(op.f('ix_emails_gmail_account_id'))
    op.drop_column('emails', 'gmail_account_id')

    op.drop_index(op.f('ix_gmail_accounts_gmail_address'), table_name='gmail_accounts')
    op.drop_index(op.f('ix_gmail_accounts_user_id'), table_name='gmail_accounts')
    op.drop_table('gmail_accounts')