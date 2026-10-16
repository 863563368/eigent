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

"""服务端账户能力授权；本机操作仍需客户端独立审批。"""

from fastapi import HTTPException

DEFAULT_PERMISSIONS = ["tasks:execute", "models:use", "sync:write", "remote:control"]
USER_PERMISSIONS = frozenset(DEFAULT_PERMISSIONS)
ADMIN_PERMISSIONS = frozenset({"users:read", "users:write", "roles:read", "roles:write", "stats:read", "audit:read"})


def require_user_permission(user, permission: str) -> None:
    """只接受服务端持久化的授权，客户端传来的权限列表不参与判断。"""
    if permission not in user.permissions:
        raise HTTPException(status_code=403, detail={"code": "permission_denied", "permission": permission})
