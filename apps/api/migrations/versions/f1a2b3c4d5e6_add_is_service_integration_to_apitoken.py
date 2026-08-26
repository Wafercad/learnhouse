"""Add is_service_integration to apitoken

Wafercad Cloud Campus: flags an org-scoped API token as a service-integration
token (may reach trails + act on-behalf-of). Gated at runtime by
WAFERCAD_SERVICE_INTEGRATION_ENABLED; the column defaults false so ordinary tokens
and stock CE are unaffected.

Revision ID: f1a2b3c4d5e6
Revises: b8c9d0e1f2a3
Create Date: 2026-08-26 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa  # noqa: F401
import sqlmodel  # noqa: F401

# revision identifiers, used by Alembic.
revision: str = 'f1a2b3c4d5e6'
down_revision: Union[str, None] = 'b8c9d0e1f2a3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    # The apitoken table is created lazily via SQLModel.metadata.create_all() on
    # app startup, so a fresh DB already has the column — skip defensively.
    if 'apitoken' not in inspector.get_table_names():
        return

    existing_columns = {col['name'] for col in inspector.get_columns('apitoken')}
    if 'is_service_integration' in existing_columns:
        return

    op.add_column(
        'apitoken',
        sa.Column(
            'is_service_integration',
            sa.Boolean(),
            nullable=True,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if 'apitoken' not in inspector.get_table_names():
        return
    existing_columns = {col['name'] for col in inspector.get_columns('apitoken')}
    if 'is_service_integration' in existing_columns:
        op.drop_column('apitoken', 'is_service_integration')
