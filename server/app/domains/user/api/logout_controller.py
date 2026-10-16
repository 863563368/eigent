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

"""退出时撤销账户的全部登录与远程控制会话。"""

from fastapi import APIRouter, Depends
from sqlmodel import Session

from app.core.database import session
from app.domains.user.service.session_service import revoke_account_sessions
from app.shared.auth import auth_must
from app.shared.auth.user_auth import V1UserAuth

router = APIRouter(prefix="/user", tags=["V1 Auth"])


@router.post("/logout")
def logout(auth: V1UserAuth = Depends(auth_must), db_session: Session = Depends(session)):
    """通过数据库版本撤销全部 access/refresh token，防止刷新令牌在退出后继续登录。"""
    revoke_account_sessions(auth.id, db_session, "logout")
    db_session.commit()
    return {"success": True, "message": "Logged out"}
