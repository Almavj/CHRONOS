"""Add response actions table

Revision ID: 004
Create Date: 2024-02-15 00:00:00

"""

from alembic import op
import sqlalchemy as sa

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "response_actions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("alert_id", sa.String(36), sa.ForeignKey("alerts.id")),
        sa.Column("action_type", sa.String(50), nullable=False),
        sa.Column("target", sa.String(500)),
        sa.Column("status", sa.String(20), nullable=False, default="pending"),
        sa.Column("result", sa.JSON()),
        sa.Column("executed_at", sa.DateTime()),
        sa.Column("executed_by", sa.String(255)),
    )
    op.create_index("idx_response_alert_id", "response_actions", ["alert_id"])


def downgrade():
    op.drop_table("response_actions")
