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

"""自托管账户注册；默认关闭，开启后可由管理员审批。"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from app.core.database import session
from app.core.deployment import enabled
from app.model.user.user import RegisterIn, User
from app.shared.auth import create_access_token, create_refresh_token
from app.shared.middleware.rate_limit import register_rate_limiter

router = APIRouter(tags=["Registration"])


class RegistrationOut(BaseModel):
    user_id: int
    email: str
    is_active: bool
    token: str | None = None
    refresh_token: str | None = None


@router.post("/register", response_model=RegistrationOut, status_code=201, dependencies=[register_rate_limiter])
def register(data: RegisterIn, db: Session = Depends(session)):
    """注册仅创建普通账户，密码已由入参模型校验并哈希，永不接受客户端权限。"""
    if not enabled("ALLOW_REGISTRATION"):
        raise HTTPException(status_code=403, detail="Registration is disabled")
    if data.invite_code:
        raise HTTPException(status_code=422, detail="Invite codes are not supported by this deployment")
    email = data.email.lower()
    if db.exec(select(User.id).where(User.email == email)).first() is not None:
        raise HTTPException(status_code=409, detail="Account already exists")
    user = User(email=email, password=data.password, is_active=not enabled("REGISTRATION_REQUIRE_APPROVAL", True))
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Account already exists") from None
    db.refresh(user)
    return RegistrationOut(
        user_id=user.id,
        email=user.email,
        is_active=user.is_active,
        token=create_access_token(user.id) if user.is_active else None,
        refresh_token=create_refresh_token(user.id) if user.is_active else None,
    )
