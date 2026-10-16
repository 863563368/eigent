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

"""设备归属查询和撤销，普通账户只能访问自己的设备。"""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Security
from sqlmodel import Session, select

from app.core.database import session
from app.domains.user.service.session_service import revoke_account_sessions
from app.model.remote_control.command_control import DesktopDevice
from app.model.user.management import AdminAudit
from app.shared.auth import auth_must
from app.shared.auth.admin_auth import V1AdminAuth, admin_must
from app.shared.auth.user_auth import V1UserAuth

router = APIRouter(tags=["Device management"])
Database = Annotated[Session, Depends(session)]


def list_devices(db: Session, user_id: int, limit: int, offset: int) -> list[dict]:
    """只投影设备状态，避免返回安装密钥和任意 capabilities 数据。"""
    devices = db.exec(
        select(DesktopDevice)
        .where(DesktopDevice.user_id == user_id)
        .order_by(DesktopDevice.created_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    fields = ("id", "app_version", "last_seen_at", "revoked_at", "created_at")
    return [{name: getattr(device, name) for name in fields} for device in devices]


def revoke_device(db: Session, user_id: int, device_id: str) -> None:
    """永久撤销设备登记并撤销账户旧令牌，防止设备重新注册绕过撤销。"""
    device = db.get(DesktopDevice, device_id)
    if not device or device.user_id != user_id:
        raise HTTPException(status_code=404, detail="Device not found")
    device.revoked_at = datetime.now(UTC)
    device.credential_version += 1
    db.add(device)
    revoke_account_sessions(user_id, db, "device_revoke")


@router.get("/user/devices")
def own_devices(
    db: Database,
    auth: V1UserAuth = Depends(auth_must),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    """查询当前账户登记的设备。"""
    return list_devices(db, auth.id, limit, offset)


@router.delete("/user/devices/{device_id}")
def delete_device(device_id: str, db: Database, auth: V1UserAuth = Depends(auth_must)):
    """用户主动撤销设备，需要重新登录后继续使用其他设备。"""
    revoke_device(db, auth.id, device_id)
    db.commit()
    return {"success": True}


@router.get("/admin/users/{user_id}/devices")
def managed_devices(
    user_id: int,
    db: Database,
    auth: V1AdminAuth = Security(admin_must, scopes=["users:read"]),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    """管理员查询指定账户设备。"""
    return list_devices(db, user_id, limit, offset)


@router.delete("/admin/users/{user_id}/devices/{device_id}")
def managed_revoke_device(
    user_id: int, device_id: str, db: Database, auth: V1AdminAuth = Security(admin_must, scopes=["users:write"])
):
    """管理员撤销设备并记录操作者，不允许改变设备所属账户。"""
    revoke_device(db, user_id, device_id)
    db.add(
        AdminAudit(admin_id=auth.admin_id, action="device.revoke", target_id=device_id, details={"user_id": user_id})
    )
    db.commit()
    return {"success": True}


@router.get("/sync/capabilities")
def capabilities(auth: V1UserAuth = Depends(auth_must)):
    """显式声明自托管支持的同步范围，客户端无需依赖官方域名猜测能力。"""
    return {
        "run_event_ingest": 1,
        "command_sync": 1,
        "run_history_restore": 0,
        "memory_sync": 0,
        "artifact_upload": 0,
        "permissions": auth.user.permissions,
    }
