"""Add hunting hypotheses table

Revision ID: 003
Create Date: 2024-02-01 00:00:00

"""

from alembic import op
import sqlalchemy as sa

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "hypotheses",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("category", sa.String(100)),
        sa.Column("mitre_techniques", sa.JSON()),
        sa.Column("hypothesis", sa.Text(), nullable=False),
        sa.Column("indicators", sa.JSON()),
        sa.Column("data_sources", sa.JSON()),
        sa.Column("query_template", sa.Text()),
        sa.Column("priority", sa.String(20)),
        sa.Column("status", sa.String(20), nullable=False, default="active"),
        sa.Column("last_run", sa.DateTime()),
        sa.Column("findings", sa.Integer(), default=0),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime()),
    )
    op.create_index("idx_hypotheses_status", "hypotheses", ["status"])
    op.create_index("idx_hypotheses_priority", "hypotheses", ["priority"])


def downgrade():
    op.drop_table("hypotheses")
