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

"""上传快照的私有文件读取边界，先验证归属再打开磁盘文件。"""

import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlmodel import Session, select

from app.core.database import session
from app.core.deployment import enabled
from app.model.chat.chat_snpshot import ChatSnapshot
from app.shared.auth.user_auth import auth_must, oauth2_scheme

router = APIRouter()


@router.get("/public/upload/{file_path:path}", include_in_schema=False)
async def read_upload(file_path: str, db: Session = Depends(session), token: str | None = Depends(oauth2_scheme)):
    """生产环境不允许通过猜测 URL 匿名读取其他账户截图。"""
    root = (Path(os.getenv("PUBLIC_DIR", "app/public")) / "upload").resolve()
    target = (root / file_path).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    if enabled("PRIVATE_UPLOADS", os.getenv("DEPLOYMENT_ENV") == "production"):
        auth = await auth_must(token=token, db_session=db)
        snapshot = db.exec(
            select(ChatSnapshot.id).where(
                ChatSnapshot.user_id == auth.id, ChatSnapshot.image_path == f"/public/upload/{file_path}"
            )
        ).first()
        if snapshot is None:
            raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(target, headers={"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff"})
