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

"""自托管账户、权限、事件接收和生产配置的针对性回归测试。"""

import importlib.util
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from fastapi_limiter.depends import RateLimiter
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel

from app.core.account_policy import ADMIN_PERMISSIONS
from app.core.database import session
from app.core.deployment import validate_production_settings
from app.domains.chat import private_uploads
from app.domains.remote_control.api.command_control_controller import DevicePrincipal
from app.domains.remote_control.service.remote_control_service import RemoteControlService
from app.domains.user.api import (
    device_controller,
    login_controller,
    logout_controller,
    management_controller,
    registration_controller,
    telemetry_controller,
)
from app.model.project.project import Project
from app.model.chat.chat_snpshot import ChatSnapshot
from app.model.remote_control.command_control import DesktopDevice, ProjectExecutionRoute
from app.model.space.space import Space
from app.model.user.admin import Admin
from app.model.user.admin_role import AdminRole
from app.model.user.management import AdminAudit
from app.model.user.role import Role
from app.model.user.run_telemetry import SyncedRun, SyncedRunEvent
from app.model.user.user import RegisterIn, User
from app.shared.auth import token_blacklist, user_auth
from app.shared.auth.admin_auth import V1AdminAuth


@pytest.fixture
def authority(monkeypatch):
    """仅创建本次涉及的表，使用内存数据库验证实际 HTTP 鉴权边界。"""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    models = (
        User,
        Admin,
        Role,
        AdminRole,
        AdminAudit,
        Space,
        Project,
        DesktopDevice,
        ProjectExecutionRoute,
        SyncedRun,
        SyncedRunEvent,
        ChatSnapshot,
    )
    SQLModel.metadata.create_all(engine, tables=[model.__table__ for model in models])
    with Session(engine) as db:
        credentials = RegisterIn(email="user@example.com", password="Password123")
        db.add(User(id=1, email=credentials.email, password=credentials.password))
        db.add(User(id=2, email="other@example.com"))
        role = Role(name="Administrator", permissions=sorted(ADMIN_PERMISSIONS))
        db.add(Admin(id=1, email="admin@example.com", name="Admin", password=credentials.password, roles=[role]))
        db.add(Space(id="space", user_id="1", name="Space"))
        db.add(Project(id="project", user_id="1", space_id="space", name="Session"))
        db.add(DesktopDevice(id="device", user_id=1))
        db.add(ProjectExecutionRoute(project_id="project", user_id=1, target_device_id="device"))
        db.commit()

    monkeypatch.setattr(user_auth, "is_blacklisted", AsyncMock(return_value=False))
    monkeypatch.setattr(login_controller, "consume_refresh_token", AsyncMock(return_value=True))
    monkeypatch.setattr(login_controller, "_", lambda message: message)
    monkeypatch.setattr(RemoteControlService, "revoke_user_sessions", lambda *_args, **_kwargs: 0)
    app = FastAPI()
    app.include_router(private_uploads.router)
    for module in (
        login_controller,
        logout_controller,
        registration_controller,
        management_controller,
        telemetry_controller,
        device_controller,
    ):
        app.include_router(module.router, prefix="/api/v1")

    def database():
        with Session(engine) as db:
            yield db

    # 测试不依赖真实 Redis；生产路由仍保留原来的限流依赖。
    app.dependency_overrides[session] = database
    for route in app.routes:
        for dependency in getattr(getattr(route, "dependant", None), "dependencies", []):
            if isinstance(dependency.call, RateLimiter):
                app.dependency_overrides[dependency.call] = lambda: None

    @app.exception_handler(user_auth.TokenException)
    async def token_error(_request, exception):
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=401, content={"code": exception.code})

    client = TestClient(app)
    yield engine, client
    engine.dispose()


def bearer(user_id=1, version=0):
    return {"Authorization": "Bearer " + user_auth.create_access_token(user_id, token_version=version)}


def admin_bearer():
    return {"Authorization": "Bearer " + V1AdminAuth.create_access_token(1)}


def test_password_login_and_account_identity(authority):
    _, client = authority
    response = client.post("/api/v1/user/login", json={"email": "USER@example.com", "password": "Password123"})
    assert response.status_code == 200
    assert {"access_token", "refresh_token", "token_type", "email"} == set(response.json())
    response = client.get("/api/v1/user/devices", headers=bearer())
    assert response.status_code == 200 and response.json()[0]["id"] == "device"
    assert "install_public_key" not in response.json()[0]


@pytest.mark.parametrize("production,allow", [(False, False), (True, True)])
def test_auto_login_is_opt_in_and_unavailable_in_production(authority, monkeypatch, production, allow):
    _, client = authority
    monkeypatch.setenv("DEPLOYMENT_ENV", "production" if production else "development")
    monkeypatch.setenv("ALLOW_LOCAL_AUTO_LOGIN", str(allow))
    assert client.post("/api/v1/user/auto-login").status_code == 404


def test_registration_disabled_then_pending_then_admin_approval(authority, monkeypatch):
    _, client = authority
    data = {"email": "new@example.com", "password": "Password123"}
    monkeypatch.setenv("ALLOW_REGISTRATION", "false")
    assert client.post("/api/v1/register", json=data).status_code == 403
    monkeypatch.setenv("ALLOW_REGISTRATION", "true")
    monkeypatch.setenv("REGISTRATION_REQUIRE_APPROVAL", "true")
    response = client.post("/api/v1/register", json=data)
    assert response.status_code == 201
    registered = response.json()
    assert registered["token"] is None and registered["is_active"] is False
    assert client.post("/api/v1/register", json=data).status_code == 409
    response = client.patch(
        f"/api/v1/admin/users/{registered['user_id']}", headers=admin_bearer(), json={"is_active": True}
    )
    assert response.status_code == 200 and response.json()["is_active"] is True
    assert "password" not in response.json()
    assert client.post("/api/v1/user/login", json=data).status_code == 200


def test_block_and_reenable_do_not_resurrect_existing_tokens(authority):
    _, client = authority
    assert client.patch("/api/v1/admin/users/1", headers=admin_bearer(), json={"status": -1}).status_code == 200
    assert client.get("/api/v1/user/devices", headers=bearer()).status_code == 401
    assert client.patch("/api/v1/admin/users/1", headers=admin_bearer(), json={"status": 1}).status_code == 200
    assert client.get("/api/v1/user/devices", headers=bearer()).status_code == 401
    assert client.get("/api/v1/user/devices", headers=bearer(version=2)).status_code == 200


def test_logout_revokes_access_and_refresh(authority):
    _, client = authority
    refresh = user_auth.create_refresh_token(1)
    assert client.post("/api/v1/user/logout", headers=bearer()).status_code == 200
    assert client.get("/api/v1/user/devices", headers=bearer()).status_code == 401
    assert client.post("/api/v1/user/refresh", json={"refresh_token": refresh}).status_code == 401


def test_normal_user_cannot_access_administration(authority):
    _, client = authority
    assert client.get("/api/v1/admin/users", headers=bearer()).status_code == 401
    assert client.get("/api/v1/admin/users", headers=admin_bearer()).status_code == 200


def test_readonly_admin_cannot_modify_roles_or_users(authority):
    engine, client = authority
    with Session(engine) as db:
        db.get(Admin, 1).roles[0].permissions = ["users:read"]
        db.commit()
    assert client.get("/api/v1/admin/users", headers=admin_bearer()).status_code == 200
    # 依赖直接抛出权限异常，单独验证并且无需依赖生产错误信封的 HTTP 状态。
    from app.shared.exception import NoPermissionException

    with pytest.raises(NoPermissionException):
        client.patch("/api/v1/admin/users/1", headers=admin_bearer(), json={"is_active": False})


def test_weak_password_is_a_safe_validation_error(authority):
    _, client = authority
    response = client.post(
        "/api/v1/admin/users", headers=admin_bearer(), json={"email": "new@example.com", "password": "abcdefgh"}
    )
    assert response.status_code == 422
    assert "abcdefgh" not in response.text


def test_device_revoke_cannot_cross_accounts(authority):
    _, client = authority
    assert client.delete("/api/v1/user/devices/device", headers=bearer(2)).status_code == 404
    assert client.delete("/api/v1/user/devices/device", headers=bearer()).status_code == 200
    assert client.get("/api/v1/user/devices", headers=bearer()).status_code == 401


def event_batch(event_id="event-1", sequence=1, event_type="run.completed"):
    return telemetry_controller.EventsIn(
        project_id="project",
        run_id="run",
        events=[
            {
                "event_id": event_id,
                "run_sequence": sequence,
                "run_version": sequence,
                "event_type": event_type,
                "payload": {},
                "legacy_step": None,
                "created_at": "2026-10-16T00:00:00Z",
            }
        ],
    )


def test_event_retry_is_idempotent_and_statistics_count_once(authority):
    engine, _ = authority
    principal = DevicePrincipal(1, "device")
    with Session(engine) as db:
        first = telemetry_controller.ingest_events(event_batch(), principal, db)
        db.commit()
        again = telemetry_controller.ingest_events(event_batch(), principal, db)
        db.commit()
        assert first["items"][0]["inserted"] is True
        assert again["items"][0]["inserted"] is False
        assert first["items"][0]["cloud_cursor"] == again["items"][0]["cloud_cursor"]
        assert again["expected_next_run_sequence"] == 2
        counts = telemetry_controller.aggregate_runs(db, 1, None, None)
        assert counts["total"] == counts["completed"] == 1
        assert telemetry_controller.aggregate_runs(db, 2, None, None)["total"] == 0


def test_conflicting_event_and_sequence_gap_are_rejected(authority):
    engine, _ = authority
    with Session(engine) as db:
        principal = DevicePrincipal(1, "device")
        telemetry_controller.ingest_events(event_batch(), principal, db)
        db.commit()
        with pytest.raises(HTTPException, match="event_identity_conflict"):
            telemetry_controller.ingest_events(event_batch(event_type="run.failed"), principal, db)
        db.rollback()
        with pytest.raises(HTTPException, match="event_sequence_conflict"):
            telemetry_controller.ingest_events(event_batch(event_id="event-3", sequence=3), principal, db)


def test_event_cannot_cross_owner_or_revoked_device(authority):
    engine, _ = authority
    with Session(engine) as db:
        with pytest.raises(HTTPException):
            telemetry_controller.ingest_events(event_batch(), DevicePrincipal(2, "device"), db)
        db.get(DesktopDevice, "device").revoked_at = datetime.now(UTC)
        db.commit()
        with pytest.raises(HTTPException):
            telemetry_controller.ingest_events(event_batch(), DevicePrincipal(1, "device"), db)


@pytest.mark.asyncio
async def test_refresh_token_consumption_is_atomic_and_fails_closed(monkeypatch):
    fake = AsyncMock()
    fake.set.side_effect = [True, False, ConnectionError()]
    monkeypatch.setattr(token_blacklist, "_get_redis", lambda: fake)
    assert await token_blacklist.consume_refresh_token("id", 60) is True
    assert await token_blacklist.consume_refresh_token("id", 60) is False
    assert fake.set.call_args.kwargs["nx"] is True
    with pytest.raises(HTTPException) as failure:
        await token_blacklist.consume_refresh_token("id", 60)
    assert failure.value.status_code == 503


def test_production_rejects_insecure_settings(monkeypatch):
    monkeypatch.setenv("DEPLOYMENT_ENV", "production")
    monkeypatch.setenv("secret_key", "postgres")
    with pytest.raises(RuntimeError):
        validate_production_settings()
    for name in ("secret_key", "CHAT_SHARE_SECRET_KEY", "CHAT_SHARE_SALT"):
        monkeypatch.setenv(name, "test-only-" + "x" * 40)
    monkeypatch.setenv("TOKEN_ISSUER", "https://api.example.com")
    monkeypatch.setenv("CORS_ALLOW_ORIGINS", "https://app.example.com")
    monkeypatch.setenv("debug", "false")
    monkeypatch.setenv("ALLOW_LOCAL_AUTO_LOGIN", "false")
    monkeypatch.setenv("REMOTE_CONTROL_ALLOW_UNSAFE_ORIGINS", "false")
    validate_production_settings()
    monkeypatch.setenv("ALLOW_LOCAL_AUTO_LOGIN", "true")
    with pytest.raises(RuntimeError):
        validate_production_settings()


def test_account_migration_preserves_existing_users(server_root):
    path = server_root / "alembic/versions/2026_10_16_1200-self_hosted_accounts_telemetry.py"
    spec = importlib.util.spec_from_file_location("account_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(text('CREATE TABLE "user" (id INTEGER PRIMARY KEY, email VARCHAR(128))'))
        connection.execute(text("CREATE TABLE admin (id INTEGER PRIMARY KEY, email VARCHAR(128))"))
        connection.execute(text("INSERT INTO \"user\" (id, email) VALUES (1, 'existing@example.com')"))
        migration.op = Operations(MigrationContext.configure(connection))
        migration.upgrade()
        row = connection.execute(text('SELECT is_active, token_version, permissions FROM "user" WHERE id=1')).one()
        assert row[0] == 1 and row[1] == 0 and "tasks:execute" in row[2]
        assert "synced_run_event" in inspect(connection).get_table_names()
        migration.downgrade()
        assert "synced_run_event" not in inspect(connection).get_table_names()
        assert connection.execute(text('SELECT email FROM "user" WHERE id=1')).scalar() == "existing@example.com"


def test_generated_secrets_do_not_overwrite_existing_configuration(tmp_path, monkeypatch, server_root):
    spec = importlib.util.spec_from_file_location("production_initializer", server_root / "scripts/init_production.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (tmp_path / "scripts").mkdir()
    (tmp_path / ".env.production.example").write_text(
        (server_root / ".env.production.example").read_text(), encoding="utf-8"
    )
    monkeypatch.setattr(module, "__file__", str(tmp_path / "scripts/init_production.py"))
    target = module.initialize("https://api.example.com", "https://app.example.com")
    original = target.read_text()
    assert "change-me-generated-by-script" not in original
    with pytest.raises(FileExistsError):
        module.initialize("https://api.example.com", "https://app.example.com")
    assert target.read_text() == original


def test_cannot_disable_last_full_administrator(authority):
    _, client = authority
    response = client.patch("/api/v1/admin/administrators/1", headers=admin_bearer(), json={"status": -1})
    assert response.status_code == 409
    assert client.get("/api/v1/admin/users", headers=admin_bearer()).status_code == 200


def test_role_delegation_and_administrator_revocation(authority):
    _, client = authority
    response = client.post(
        "/api/v1/admin/roles", headers=admin_bearer(), json={"name": "Reader", "permissions": ["users:read"]}
    )
    assert response.status_code == 201
    role_id = response.json()["id"]
    response = client.post(
        "/api/v1/admin/administrators",
        headers=admin_bearer(),
        json={
            "email": "reader@example.com",
            "name": "Reader",
            "password": "Password123",
            "role_ids": [role_id],
        },
    )
    assert response.status_code == 201
    admin_id = response.json()["id"]
    reader_headers = {"Authorization": "Bearer " + V1AdminAuth.create_access_token(admin_id)}
    assert client.get("/api/v1/admin/users", headers=reader_headers).status_code == 200
    assert client.delete(f"/api/v1/admin/roles/{role_id}", headers=admin_bearer()).status_code == 409
    assert (
        client.patch(
            f"/api/v1/admin/administrators/{admin_id}", headers=admin_bearer(), json={"status": -1}
        ).status_code
        == 200
    )
    assert client.get("/api/v1/admin/users", headers=reader_headers).status_code == 401


def test_task_upload_requires_sync_permission(authority):
    engine, client = authority
    with Session(engine) as db:
        db.get(User, 1).permissions = ["models:use"]
        db.commit()
    response = client.post(
        "/api/v1/sync/events:ingest",
        json=event_batch().model_dump(mode="json"),
        headers={**bearer(), "X-Desktop-Instance-ID": "device"},
    )
    assert response.status_code == 403


def test_private_uploads_require_owner_and_never_allow_path_escape(authority, tmp_path, monkeypatch):
    engine, client = authority
    monkeypatch.setenv("PUBLIC_DIR", str(tmp_path))
    monkeypatch.setenv("PRIVATE_UPLOADS", "true")
    (tmp_path / "upload").mkdir()
    (tmp_path / "upload/screenshot.png").write_bytes(b"synthetic image")
    with Session(engine) as db:
        db.add(
            ChatSnapshot(
                user_id=1,
                api_task_id="task",
                camel_task_id="task",
                browser_url="https://example.com",
                image_path="/public/upload/screenshot.png",
            )
        )
        db.commit()
    assert client.get("/public/upload/screenshot.png").status_code == 401
    assert client.get("/public/upload/screenshot.png", headers=bearer(2)).status_code == 404
    assert client.get("/public/upload/screenshot.png", headers=bearer()).status_code == 200
    assert client.get("/public/upload/%2e%2e/secret", headers=bearer()).status_code == 404


@pytest.mark.asyncio
async def test_bridge_rejects_disabled_or_revoked_account(authority, monkeypatch):
    from app.domains.remote_control.api import remote_control_controller

    engine, _ = authority
    monkeypatch.setattr(remote_control_controller, "is_blacklisted", AsyncMock(return_value=False))
    with Session(engine) as db:
        token = user_auth.create_access_token(1)
        assert (await remote_control_controller._auth_token_with_jti(token, db))[0].id == 1
        db.get(User, 1).token_version += 1
        db.commit()
        with pytest.raises(HTTPException) as failure:
            await remote_control_controller._auth_token_with_jti(token, db)
        assert failure.value.status_code == 401
