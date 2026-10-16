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

"""自托管部署开关与启动配置校验。"""

import os
from urllib.parse import urlparse


def enabled(name: str, default: bool = False) -> bool:
    """统一解析环境开关，避免字符串 false 被当作真值。"""
    return os.getenv(name, str(default)).strip().lower() in {"true", "1", "yes", "on"}


def validate_production_settings() -> None:
    """生产环境在启动前拒绝示例密钥和不安全的免密入口。"""
    if os.getenv("DEPLOYMENT_ENV", "development") != "production":
        return
    for name in ("secret_key", "CHAT_SHARE_SECRET_KEY", "CHAT_SHARE_SALT"):
        value = os.getenv(name, "")
        if len(value) < 32 or value.startswith(("put-your-", "change-me")):
            raise RuntimeError(f"Production requires a random {name} of at least 32 characters")
    if enabled("ALLOW_LOCAL_AUTO_LOGIN") or os.getenv("debug", "").lower() in {"on", "true", "1"}:
        raise RuntimeError("Production cannot enable debug or ALLOW_LOCAL_AUTO_LOGIN")
    if enabled("REMOTE_CONTROL_ALLOW_UNSAFE_ORIGINS"):
        raise RuntimeError("Production cannot enable unsafe CORS/WebSocket origins")
    issuer = urlparse(os.getenv("TOKEN_ISSUER", ""))
    if issuer.scheme != "https" or not issuer.netloc:
        raise RuntimeError("Production TOKEN_ISSUER must be an HTTPS origin")
    origins = os.getenv("CORS_ALLOW_ORIGINS", "").split(",")
    if not origins or any(not origin.strip() or origin.strip() == "*" for origin in origins):
        raise RuntimeError("Production requires explicit CORS_ALLOW_ORIGINS")
