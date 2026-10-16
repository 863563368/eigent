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

"""账户创建和改密共用的输入验证边界。"""

from fastapi import HTTPException
from pydantic import ValidationError

from app.model.user.user import RegisterIn


def validate_registration(email: str, password: str) -> RegisterIn:
    """把内部模型校验转换为无敏感输入的 422 响应，而不是未处理的 500。"""
    try:
        return RegisterIn(email=email, password=password)
    except ValidationError:
        raise HTTPException(
            status_code=422, detail="Use a valid email and a password of 8–72 UTF-8 bytes containing letters and digits"
        ) from None
