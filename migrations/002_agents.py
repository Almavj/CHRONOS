"""Add agents table

Revision ID: 002
Create Date: 2024-01-15 00:00:00

"""

from alembic import op
import sqlalchemy as sa

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "agents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("agent_id", sa.String(100), unique=True, nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("platform", sa.String(50)),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("os_version", sa.String(100)),
        sa.Column("status", sa.String(20), nullable=False, default="active"),
        sa.Column("tags", sa.JSON()),
        sa.Column("registered_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime()),
        sa.Column("version", sa.String(50)),
        sa.Column("metadata", sa.JSON()),
    )
    op.create_index("idx_agents_hostname", "agents", ["hostname"])
    op.create_index("idx_agents_status", "agents", ["status"])


def downgrade():
    op.drop_table("agents")
