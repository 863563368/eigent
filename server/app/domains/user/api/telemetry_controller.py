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

"""有界、幂等的任务事件接收及按账户聚合统计。"""

import json
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Security
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from app.core.database import session
from app.domains.remote_control.api.command_control_controller import DevicePrincipal, device_principal_must
from app.model.project.project import Project
from app.model.remote_control.command_control import DesktopDevice, ProjectExecutionRoute
from app.model.user.run_telemetry import SyncedRun, SyncedRunEvent
from app.shared.auth import auth_must
from app.shared.auth.admin_auth import V1AdminAuth, admin_must
from app.shared.auth.user_auth import V1UserAuth
from app.shared.middleware.rate_limit import rate_limiter_factory

router = APIRouter(tags=["Run telemetry"])
Database = Annotated[Session, Depends(session)]
TERMINAL_EVENTS = {
    "run.completed": "completed",
    "run.failed": "failed",
    "run.cancelled": "cancelled",
    "run.deadline_reached": "failed",
}


class EventIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    event_id: str = Field(min_length=1, max_length=128)
    run_sequence: int = Field(ge=1, strict=True)
    run_version: int = Field(ge=0, strict=True)
    event_type: str = Field(min_length=1, max_length=128)
    payload: dict = Field(default_factory=dict)
    legacy_step: str | None = Field(default=None, max_length=255)
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def timezone_required(cls, value):
        """禁止无时区时间，避免重试时同一事件的比较结果发生变化。"""
        if value.tzinfo is None:
            raise ValueError("created_at requires a timezone")
        return value.astimezone(UTC)

    @field_validator("payload")
    @classmethod
    def bounded_payload(cls, value):
        """事件只接受有限的 JSON 数据，客户端应继续执行原有隐私投影。"""
        try:
            if len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode()) > 32768:
                raise ValueError("Event payload exceeds 32 KiB")
        except (RecursionError, OverflowError) as exc:
            raise ValueError("Invalid event payload") from exc
        return value


class EventsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=128)
    events: list[EventIn] = Field(min_length=1, max_length=200)


def ingest_events(data: EventsIn, principal: DevicePrincipal, db: Session) -> dict:
    """在一个事务内验证归属、按序接收和去重；失败时不确认任何事件。"""
    project = db.get(Project, data.project_id)
    device = db.get(DesktopDevice, principal.desktop_instance_id)
    route = db.exec(
        select(ProjectExecutionRoute).where(ProjectExecutionRoute.project_id == data.project_id).with_for_update()
    ).first()
    if not project or str(project.user_id) != str(principal.user_id):
        raise HTTPException(status_code=404, detail={"code": "project_not_found"})
    if not device or device.user_id != principal.user_id or device.revoked_at is not None:
        raise HTTPException(status_code=403, detail={"code": "device_not_registered"})
    if not route or route.user_id != principal.user_id or route.target_device_id != device.id:
        raise HTTPException(status_code=409, detail={"code": "execution_route_mismatch"})
    run = db.get(SyncedRun, data.run_id)
    if run is None:
        candidate = SyncedRun(
            run_id=data.run_id, user_id=principal.user_id, project_id=project.id, desktop_instance_id=device.id
        )
        try:
            with db.begin_nested():
                db.add(candidate)
                db.flush()
        except IntegrityError:
            pass
    run = db.exec(select(SyncedRun).where(SyncedRun.run_id == data.run_id).with_for_update()).one()
    if (run.user_id, run.project_id, run.desktop_instance_id) != (principal.user_id, project.id, device.id):
        raise HTTPException(status_code=409, detail={"code": "run_owner_mismatch"})
    items = []
    for event in data.events:
        existing = db.exec(
            select(SyncedRunEvent).where(
                SyncedRunEvent.user_id == principal.user_id, SyncedRunEvent.event_id == event.event_id
            )
        ).first()
        inserted = existing is None
        if existing is not None:
            if (
                existing.run_id,
                existing.run_sequence,
                existing.run_version,
                existing.event_type,
                existing.payload,
                existing.legacy_step,
                existing.created_at.replace(tzinfo=UTC),
            ) != (
                data.run_id,
                event.run_sequence,
                event.run_version,
                event.event_type,
                event.payload,
                event.legacy_step,
                event.created_at,
            ):
                raise HTTPException(status_code=409, detail={"code": "event_identity_conflict"})
            row = existing
        else:
            if event.run_sequence != run.expected_next_run_sequence:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "event_sequence_conflict",
                        "expected_next_run_sequence": run.expected_next_run_sequence,
                    },
                )
            row = SyncedRunEvent(user_id=principal.user_id, run_id=data.run_id, **event.model_dump())
            db.add(row)
            db.flush()
            run.expected_next_run_sequence += 1
            # 终态只接收一次；后续重复或进度事件不能把任务恢复成运行中。
            if run.status not in {"completed", "failed", "cancelled"}:
                if event.event_type in TERMINAL_EVENTS:
                    run.status = TERMINAL_EVENTS[event.event_type]
                elif event.event_type == "run.started":
                    run.status = "running"
            run.updated_at = datetime.now(UTC)
            db.add(run)
        items.append(
            {
                "event_id": event.event_id,
                "run_sequence": event.run_sequence,
                "run_version": event.run_version,
                "cloud_cursor": row.id,
                "inserted": inserted,
            }
        )
    db.flush()
    return {
        "project_id": data.project_id,
        "run_id": data.run_id,
        "items": items,
        "expected_next_run_sequence": run.expected_next_run_sequence,
    }


@router.post("/sync/events:ingest", dependencies=[rate_limiter_factory(times=120, seconds=60)])
def ingest(data: EventsIn, db: Database, principal: Annotated[DevicePrincipal, Depends(device_principal_must)]):
    """响应字段严格匹配当前本地任务引擎的确认协议。"""
    try:
        result = ingest_events(data, principal, db)
        db.commit()
        return result
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail={"code": "event_identity_conflict"}) from None


def aggregate_runs(db: Session, user_id: int | None, since: datetime | None, until: datetime | None) -> dict:
    """按服务端首次收到任务的时间聚合，任务重试上报不重复计数。"""
    query = select(SyncedRun.status, func.count()).group_by(SyncedRun.status)
    if user_id is not None:
        query = query.where(SyncedRun.user_id == user_id)
    if since is not None:
        query = query.where(SyncedRun.created_at >= since)
    if until is not None:
        query = query.where(SyncedRun.created_at < until)
    counts = dict(db.exec(query).all())
    return {
        "total": sum(counts.values()),
        **{state: counts.get(state, 0) for state in ("pending", "running", "completed", "failed", "cancelled")},
    }


@router.get("/user/task-statistics")
def own_statistics(
    db: Database, auth: V1UserAuth = Depends(auth_must), since: datetime | None = None, until: datetime | None = None
):
    """只返回当前账户的任务汇总；该数据为设备上报，不能充当模型计费凭据。"""
    return aggregate_runs(db, auth.id, since, until)


@router.get("/admin/task-statistics")
def statistics(
    db: Database,
    auth: V1AdminAuth = Security(admin_must, scopes=["stats:read"]),
    user_id: int | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
):
    """管理员按账户与时间区间查询任务汇总。"""
    return aggregate_runs(db, user_id, since, until)


@router.get("/user/runs")
def runs(
    db: Database,
    auth: V1UserAuth = Depends(auth_must),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    """分页查询当前账户任务状态，不返回其他账户事件。"""
    return db.exec(
        select(SyncedRun)
        .where(SyncedRun.user_id == auth.id)
        .order_by(SyncedRun.created_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()
