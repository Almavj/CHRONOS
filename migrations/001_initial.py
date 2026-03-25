"""Initial migration - create alerts table

Revision ID: 001
Create Date: 2024-01-01 00:00:00

"""

from alembic import op
import sqlalchemy as sa

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "alerts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, default="new"),
        sa.Column("technique", sa.String(50)),
        sa.Column("ttp", sa.String(50)),
        sa.Column("indicators", sa.JSON()),
        sa.Column("hostname", sa.String(255)),
        sa.Column("user", sa.String(255)),
        sa.Column("destination_ip", sa.String(45)),
        sa.Column("source_ip", sa.String(45)),
        sa.Column("metadata", sa.JSON()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime()),
        sa.Column("acknowledged_at", sa.DateTime()),
        sa.Column("resolved_at", sa.DateTime()),
    )
    op.create_index("idx_alerts_severity", "alerts", ["severity"])
    op.create_index("idx_alerts_status", "alerts", ["status"])
    op.create_index("idx_alerts_created_at", "alerts", ["created_at"])


def downgrade():
    op.drop_table("alerts")
