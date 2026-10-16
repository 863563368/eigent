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

"""自托管任务事件与运行汇总，和本机执行记录使用原有标识。"""

from datetime import UTC, datetime

from sqlmodel import JSON, Column, Field, UniqueConstraint

from app.model.abstract.model import AbstractModel


class SyncedRun(AbstractModel, table=True):
    run_id: str = Field(primary_key=True, max_length=128)
    user_id: int = Field(index=True)
    project_id: str = Field(index=True, max_length=128)
    desktop_instance_id: str = Field(index=True, max_length=128)
    status: str = Field(default="pending", max_length=32)
    expected_next_run_sequence: int = Field(default=1)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)


class SyncedRunEvent(AbstractModel, table=True):
    __table_args__ = (
        UniqueConstraint("user_id", "event_id", name="uq_synced_event_identity"),
        UniqueConstraint("run_id", "run_sequence", name="uq_synced_event_sequence"),
    )
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(index=True)
    run_id: str = Field(foreign_key="synced_run.run_id", index=True, max_length=128)
    event_id: str = Field(max_length=128)
    run_sequence: int
    run_version: int
    event_type: str = Field(max_length=128)
    payload: dict = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
    legacy_step: str | None = Field(default=None, max_length=255)
    created_at: datetime
    received_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
