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

"""管理操作审计，不存储密码、令牌或业务内容。"""

from datetime import UTC, datetime

from sqlmodel import JSON, Column, Field

from app.model.abstract.model import AbstractModel


class AdminAudit(AbstractModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    admin_id: int = Field(index=True)
    action: str = Field(max_length=64)
    target_id: str = Field(max_length=128)
    details: dict = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
