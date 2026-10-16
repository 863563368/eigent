# ========= Copyright 2025-2026 @ Eigent.ai All Rights Reserved. =========
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ========= Copyright 2025-2026 @ Eigent.ai All Rights Reserved. =========

"""自托管账户授权、管理审计与任务统计。"""

import sqlalchemy as sa

from alembic import op

revision: str = "self_hosted_accounts_telemetry"
down_revision: str | None = "provider_execution_revision"
branch_labels = None
depends_on = None


def upgrade():
    """保留已有账户可用状态，新增版本撤销与独立的幂等任务统计表。"""
    op.add_column("user", sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column("user", sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"))
    op.add_column(
        "user",
        sa.Column(
            "permissions",
            sa.JSON(),
            nullable=False,
            server_default='["tasks:execute", "models:use", "sync:write", "remote:control"]',
        ),
    )
    op.add_column("admin", sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"))
    op.create_index("uq_admin_email_lower", "admin", [sa.text("lower(email)")], unique=True)
    op.create_index("uq_user_email_lower", "user", [sa.text("lower(email)")], unique=True)
    op.create_table(
        "admin_audit",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("admin_id", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target_id", sa.String(128), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_admin_audit_admin_id", "admin_audit", ["admin_id"])
    op.create_index("ix_admin_audit_created_at", "admin_audit", ["created_at"])
    op.create_table(
        "synced_run",
        sa.Column("run_id", sa.String(128), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.String(128), nullable=False),
        sa.Column("desktop_instance_id", sa.String(128), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("expected_next_run_sequence", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    for name in ("user_id", "project_id", "desktop_instance_id", "created_at", "updated_at"):
        op.create_index(f"ix_synced_run_{name}", "synced_run", [name])
    op.create_table(
        "synced_run_event",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.String(128), sa.ForeignKey("synced_run.run_id"), nullable=False),
        sa.Column("event_id", sa.String(128), nullable=False),
        sa.Column("run_sequence", sa.Integer(), nullable=False),
        sa.Column("run_version", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("legacy_step", sa.String(255)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("user_id", "event_id", name="uq_synced_event_identity"),
        sa.UniqueConstraint("run_id", "run_sequence", name="uq_synced_event_sequence"),
    )
    op.create_index("ix_synced_run_event_user_id", "synced_run_event", ["user_id"])
    op.create_index("ix_synced_run_event_run_id", "synced_run_event", ["run_id"])


def downgrade():
    """显式回滚新增管理数据；执行前应先备份审计与统计表。"""
    op.drop_table("synced_run_event")
    op.drop_table("synced_run")
    op.drop_table("admin_audit")
    op.drop_index("uq_user_email_lower", table_name="user")
    op.drop_index("uq_admin_email_lower", table_name="admin")
    op.drop_column("admin", "token_version")
    for name in ("permissions", "token_version", "is_active"):
        op.drop_column("user", name)
