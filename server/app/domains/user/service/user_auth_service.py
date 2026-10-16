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

"""UserAuthService: login, refresh, logout. Follows CreditsService pattern."""

import time

from app.core.database import session_make
from app.core.encrypt import password_verify
from app.domains.user.schema import AuthResult
from app.model.user.user import Status, User
from app.shared.auth import create_access_token, create_refresh_token
from app.shared.auth.token_blacklist import consume_refresh_token, is_blacklisted
from app.shared.auth.user_auth import (
    decode_refresh_token,
    token_version_from_token,
)


class UserAuthService:
    """User authentication operations - static methods."""

    @staticmethod
    def login(email: str, password: str) -> AuthResult:
        """Password login + credits refresh. Returns tokens or error."""
        with session_make() as s:
            user = User.by(User.email == email.lower(), s=s).one_or_none()

        if not user or not password_verify(password, user.password):
            return AuthResult(success=False, error_code="AUTH_INVALID_CREDENTIALS")
        if user.status == Status.Block or user.deleted_at is not None:
            return AuthResult(success=False, error_code="AUTH_ACCOUNT_BLOCKED")
        if not user.is_active:
            return AuthResult(success=False, error_code="AUTH_ACCOUNT_INACTIVE")

        # No credits refresh in eigent (no billing domain)

        access_token = create_access_token(user.id, token_version=user.token_version)
        refresh_token = create_refresh_token(user.id, token_version=user.token_version)
        return AuthResult(
            success=True,
            access_token=access_token,
            refresh_token=refresh_token,
            email=user.email,
        )

    @staticmethod
    async def refresh(refresh_token_str: str) -> AuthResult:
        """Exchange valid refresh_token for new token pair."""
        if not refresh_token_str:
            return AuthResult(success=False, error_code="AUTH_REFRESH_TOKEN_REQUIRED")

        user_id, jti, exp_ts = await decode_refresh_token(refresh_token_str)
        if jti and await is_blacklisted(jti):
            return AuthResult(success=False, error_code="AUTH_TOKEN_REVOKED")

        with session_make() as s:
            user = s.get(User, user_id)

        if not user:
            return AuthResult(success=False, error_code="AUTH_USER_NOT_FOUND")
        if user.status == Status.Block or user.deleted_at is not None:
            return AuthResult(success=False, error_code="AUTH_ACCOUNT_BLOCKED")
        if not user.is_active:
            return AuthResult(success=False, error_code="AUTH_ACCOUNT_INACTIVE")

        # Blacklist old refresh token
        if token_version_from_token(refresh_token_str) != user.token_version:
            return AuthResult(success=False, error_code="AUTH_TOKEN_REVOKED")
        if not jti or not await consume_refresh_token(jti, exp_ts - int(time.time())):
            return AuthResult(success=False, error_code="AUTH_TOKEN_REVOKED")

        access_token = create_access_token(user.id, token_version=user.token_version)
        new_refresh_token = create_refresh_token(user.id, token_version=user.token_version)
        return AuthResult(
            success=True,
            access_token=access_token,
            refresh_token=new_refresh_token,
            email=user.email,
        )

    @staticmethod
    async def logout(token: str) -> bool:
        """校验当前用户令牌后撤销全部会话，不吞掉数据库或撤销故障。"""
        if not token:
            return True
        from app.domains.user.service.session_service import revoke_account_sessions
        from app.shared.auth.user_auth import V1UserAuth, validate_account_session

        auth = V1UserAuth.decode_token(token)
        with session_make() as db:
            validate_account_session(db.get(User, auth.id), auth)
            revoke_account_sessions(auth.id, db, "logout")
            db.commit()
        return True
