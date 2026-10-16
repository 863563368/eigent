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

"""账户级会话撤销，旧 access/refresh token 一并失效。"""

from sqlalchemy import update
from sqlmodel import Session

from app.model.user.user import User


def revoke_account_sessions(user_id: int, db: Session, reason: str) -> None:
    """原子递增令牌版本，再撤销现有远程控制会话；调用方提交业务事务。"""
    from app.domains.remote_control.service.remote_control_service import RemoteControlService

    db.exec(update(User).where(User.id == user_id).values(token_version=User.token_version + 1))
    db.flush()
    RemoteControlService.revoke_user_sessions(user_id, db, reason, commit=False)
