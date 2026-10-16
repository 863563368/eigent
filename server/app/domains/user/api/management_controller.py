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

"""自托管管理接口：账户、角色、设备与审计。"""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Security
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, update
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from app.core.account_creation import validate_registration
from app.core.account_policy import ADMIN_PERMISSIONS, USER_PERMISSIONS
from app.core.database import session
from app.core.encrypt import password_verify
from app.domains.user.service.session_service import revoke_account_sessions
from app.model.user.admin import Admin, Status as AdminStatus
from app.model.user.admin_role import AdminRole
from app.model.user.management import AdminAudit
from app.model.user.role import Role, RoleIn, RoleOut, RoleType
from app.model.user.user import LoginByPasswordIn, Status, User, UserOut
from app.shared.auth.admin_auth import V1AdminAuth, admin_must
from app.shared.middleware.rate_limit import login_rate_limiter

router = APIRouter(prefix="/admin", tags=["Administration"])
Database = Annotated[Session, Depends(session)]


class UserCreateIn(BaseModel):
    email: str
    password: str = Field(min_length=8, max_length=72)
    is_active: bool = True
    permissions: list[str] | None = None


class UserUpdateIn(BaseModel):
    status: Status | None = None
    is_active: bool | None = None
    permissions: list[str] | None = None
    password: str | None = Field(default=None, min_length=8, max_length=72)


class AdminCreateIn(BaseModel):
    email: str
    password: str = Field(min_length=8, max_length=72)
    name: str = Field(min_length=1, max_length=128)
    role_ids: list[int] = Field(min_length=1, max_length=32)


class AdminUpdateIn(BaseModel):
    status: AdminStatus | None = None
    role_ids: list[int] | None = Field(default=None, min_length=1, max_length=32)
    password: str | None = Field(default=None, min_length=8, max_length=72)


class ManagedRoleIn(RoleIn):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1024)
    permissions: list[str] = Field(max_length=32)

    @field_validator("permissions")
    @classmethod
    def known_permissions(cls, value):
        """权限只能来自固定管理能力目录，拒绝任意通配符授权。"""
        if set(value) - ADMIN_PERMISSIONS:
            raise ValueError("Unknown administrator permission")
        return sorted(set(value))


def audit(db: Session, auth: V1AdminAuth, action: str, target_id, **details) -> None:
    """与业务变更在同一事务写入审计，不记录密码和令牌。"""
    db.add(AdminAudit(admin_id=auth.admin_id, action=action, target_id=str(target_id), details=details))


def validate_permissions(value: list[str] | None) -> list[str] | None:
    """校验普通账户能力，管理员角色权限不能授予普通账户。"""
    if value is not None and (len(value) > 32 or set(value) - USER_PERMISSIONS):
        raise HTTPException(status_code=422, detail="Unknown account permission")
    return sorted(set(value)) if value is not None else None


@router.post("/login", dependencies=[login_rate_limiter])
def login(data: LoginByPasswordIn, db: Database):
    """管理员独立登录，令牌类型与普通用户隔离。"""
    admin = db.exec(select(Admin).where(func.lower(Admin.email) == data.email.lower())).first()
    if (
        not admin
        or not password_verify(data.password, admin.password)
        or admin.status != AdminStatus.Normal
        or admin.deleted_at is not None
    ):
        raise HTTPException(status_code=401, detail="Invalid administrator credentials")
    token = V1AdminAuth.create_access_token(admin.id, token_version=admin.token_version)
    audit(db, V1AdminAuth(admin.id, datetime.now(UTC)), "admin.login", admin.id)
    db.commit()
    return {
        "access_token": token,
        "token_type": "bearer",
        "permissions": sorted({p for role in admin.roles for p in role.permissions}),
    }


@router.post("/logout")
def logout(db: Database, auth: V1AdminAuth = Security(admin_must)):
    """撤销当前管理员全部登录会话。"""
    db.exec(update(Admin).where(Admin.id == auth.admin_id).values(token_version=Admin.token_version + 1))
    audit(db, auth, "admin.logout", auth.admin_id)
    db.commit()
    return {"success": True}


@router.get("/permissions")
def permissions(auth: V1AdminAuth = Security(admin_must)):
    """返回可分配的能力目录，方便后续管理界面接入。"""
    return {"admin": sorted(ADMIN_PERMISSIONS), "user": sorted(USER_PERMISSIONS)}


@router.get("/users", response_model=list[UserOut])
def users(
    db: Database,
    auth: V1AdminAuth = Security(admin_must, scopes=["users:read"]),
    email: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    is_active: bool | None = None,
):
    """分页查询账户，响应模型显式排除密码和内部会话版本。"""
    query = select(User).where(User.deleted_at.is_(None))
    if email:
        query = query.where(func.lower(User.email) == email.lower())
    if is_active is not None:
        query = query.where(User.is_active == is_active)
    return db.exec(query.order_by(User.id).offset(offset).limit(limit)).all()


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(data: UserCreateIn, db: Database, auth: V1AdminAuth = Security(admin_must, scopes=["users:write"])):
    """由管理员创建账户，复用注册密码策略并阻止重复邮箱。"""
    validated = validate_registration(data.email, data.password)
    grants = validate_permissions(data.permissions)
    user = User(email=validated.email.lower(), password=validated.password, is_active=data.is_active)
    if grants is not None:
        user.permissions = grants
    db.add(user)
    try:
        db.flush()
        audit(db, auth, "user.create", user.id, is_active=user.is_active)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Account already exists") from None
    db.refresh(user)
    return user


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: int, data: UserUpdateIn, db: Database, auth: V1AdminAuth = Security(admin_must, scopes=["users:write"])
):
    """审批、封禁、授权或重置密码时撤销账户旧会话，并保留审计。"""
    user = db.exec(select(User).where(User.id == user_id).with_for_update()).first()
    if not user or user.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Account not found")
    if any(getattr(data, field) is None for field in data.model_fields_set):
        raise HTTPException(status_code=422, detail="Explicit null updates are not supported")
    grants = validate_permissions(data.permissions)
    if data.status is not None:
        user.status = data.status
    if data.is_active is not None:
        user.is_active = data.is_active
    if grants is not None:
        user.permissions = grants
    if data.password is not None:
        user.password = validate_registration(user.email, data.password).password
    db.add(user)
    revoke_account_sessions(user.id, db, "admin_update")
    audit(db, auth, "user.update", user.id, fields=sorted(data.model_fields_set))
    db.commit()
    db.refresh(user)
    return user


@router.post("/users/{user_id}/sessions/revoke")
def revoke_sessions(user_id: int, db: Database, auth: V1AdminAuth = Security(admin_must, scopes=["users:write"])):
    """强制退出账户所有设备，不删除任务或业务数据。"""
    if db.get(User, user_id) is None:
        raise HTTPException(status_code=404, detail="Account not found")
    revoke_account_sessions(user_id, db, "admin_revoke")
    audit(db, auth, "user.sessions.revoke", user_id)
    db.commit()
    return {"success": True}


@router.get("/roles", response_model=list[RoleOut])
def roles(
    db: Database,
    auth: V1AdminAuth = Security(admin_must, scopes=["roles:read"]),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    """列出可分配的管理员角色。"""
    return db.exec(select(Role).where(Role.deleted_at.is_(None)).order_by(Role.id).offset(offset).limit(limit)).all()


@router.post("/roles", response_model=RoleOut, status_code=201)
def create_role(data: ManagedRoleIn, db: Database, auth: V1AdminAuth = Security(admin_must, scopes=["roles:write"])):
    """创建角色时禁止授予当前管理员自身不具备的能力。"""
    if not auth.can(*data.permissions):
        raise HTTPException(status_code=403, detail="Cannot delegate unavailable permissions")
    role = Role(**data.model_dump())
    db.add(role)
    db.flush()
    audit(db, auth, "role.create", role.id, permissions=data.permissions)
    db.commit()
    db.refresh(role)
    return role


@router.put("/roles/{role_id}", response_model=RoleOut)
def update_role(
    role_id: int, data: ManagedRoleIn, db: Database, auth: V1AdminAuth = Security(admin_must, scopes=["roles:write"])
):
    """系统管理员角色不可改写，自定义角色变更立即影响下一次鉴权。"""
    role = db.get(Role, role_id)
    if not role or role.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Role not found")
    if role.type == RoleType.System or not auth.can(*role.permissions, *data.permissions):
        raise HTTPException(status_code=403, detail="Role cannot be changed by this administrator")
    for key, value in data.model_dump().items():
        setattr(role, key, value)
    db.add(role)
    audit(db, auth, "role.update", role.id, permissions=data.permissions)
    db.commit()
    db.refresh(role)
    return role


@router.post("/administrators", status_code=201)
def create_admin(
    data: AdminCreateIn, db: Database, auth: V1AdminAuth = Security(admin_must, scopes=["roles:write", "users:write"])
):
    """创建受限管理员，所有角色均需存在且不能超越当前操作者权限。"""
    validated = validate_registration(data.email, data.password)
    roles = db.exec(select(Role).where(Role.id.in_(set(data.role_ids)), Role.deleted_at.is_(None))).all()
    if len(roles) != len(set(data.role_ids)) or any(not auth.can(*role.permissions) for role in roles):
        raise HTTPException(status_code=403, detail="Cannot assign requested roles")
    # 锁定角色行串行化管理账户创建，避免并发创建重复邮箱。
    db.exec(select(Role).where(Role.id.in_(set(data.role_ids))).with_for_update()).all()
    if db.exec(select(Admin.id).where(func.lower(Admin.email) == validated.email.lower())).first() is not None:
        raise HTTPException(status_code=409, detail="Administrator already exists")
    admin = Admin(email=validated.email.lower(), password=validated.password, name=data.name, roles=list(roles))
    db.add(admin)
    db.flush()
    audit(db, auth, "admin.create", admin.id, role_ids=sorted(set(data.role_ids)))
    db.commit()
    return {"id": admin.id, "email": admin.email, "name": admin.name, "role_ids": sorted(set(data.role_ids))}


@router.get("/audit")
def audits(
    db: Database,
    auth: V1AdminAuth = Security(admin_must, scopes=["audit:read"]),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    """分页读取管理审计，按服务端写入顺序倒序返回。"""
    return db.exec(select(AdminAudit).order_by(AdminAudit.id.desc()).offset(offset).limit(limit)).all()


@router.get("/administrators")
def administrators(
    db: Database,
    auth: V1AdminAuth = Security(admin_must, scopes=["users:read", "roles:read"]),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    """管理员列表显式投影安全字段，不返回密码或内部会话版本。"""
    items = db.exec(
        select(Admin).where(Admin.deleted_at.is_(None)).order_by(Admin.id).offset(offset).limit(limit)
    ).all()
    return [
        {
            "id": item.id,
            "email": item.email,
            "name": item.name,
            "status": item.status,
            "role_ids": [role.id for role in item.roles],
        }
        for item in items
    ]


@router.patch("/administrators/{admin_id}")
def update_administrator(
    admin_id: int,
    data: AdminUpdateIn,
    db: Database,
    auth: V1AdminAuth = Security(admin_must, scopes=["users:write", "roles:write"]),
):
    """调整管理员角色或状态并撤销旧会话，同时保留至少一个完整管理账户。"""
    administrators = db.exec(select(Admin).order_by(Admin.id).with_for_update()).all()
    target = next((item for item in administrators if item.id == admin_id and item.deleted_at is None), None)
    if target is None:
        raise HTTPException(status_code=404, detail="Administrator not found")
    if not auth.can(*(permission for role in target.roles for permission in role.permissions)):
        raise HTTPException(status_code=403, detail="Cannot manage a more privileged administrator")
    if any(getattr(data, field) is None for field in data.model_fields_set):
        raise HTTPException(status_code=422, detail="Explicit null updates are not supported")
    if data.role_ids is not None:
        requested = db.exec(select(Role).where(Role.id.in_(set(data.role_ids)), Role.deleted_at.is_(None))).all()
        if len(requested) != len(set(data.role_ids)) or any(not auth.can(*role.permissions) for role in requested):
            raise HTTPException(status_code=403, detail="Cannot assign requested roles")
        target.roles = list(requested)
    if data.status is not None:
        target.status = data.status
    if data.password is not None:
        target.password = validate_registration(target.email, data.password).password
    if not any(
        item.status == AdminStatus.Normal
        and item.deleted_at is None
        and ADMIN_PERMISSIONS.issubset({p for role in item.roles for p in role.permissions})
        for item in administrators
    ):
        raise HTTPException(status_code=409, detail="Keep at least one active administrator with all permissions")
    target.token_version += 1
    db.add(target)
    audit(db, auth, "admin.update", target.id, fields=sorted(data.model_fields_set))
    db.commit()
    return {"success": True}


@router.delete("/roles/{role_id}")
def delete_role(role_id: int, db: Database, auth: V1AdminAuth = Security(admin_must, scopes=["roles:write"])):
    """只允许删除未分配的自定义角色，防止意外剥夺现有管理员权限。"""
    role = db.exec(select(Role).where(Role.id == role_id).with_for_update()).first()
    if not role or role.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Role not found")
    if role.type == RoleType.System or not auth.can(*role.permissions):
        raise HTTPException(status_code=403, detail="Role cannot be deleted")
    if db.exec(select(AdminRole).where(AdminRole.role_id == role_id)).first() is not None:
        raise HTTPException(status_code=409, detail="Role is assigned to an administrator")
    db.delete(role)
    audit(db, auth, "role.delete", role_id)
    db.commit()
    return {"success": True}
