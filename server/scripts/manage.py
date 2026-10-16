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

"""自托管运维命令；密码从终端读取，不进入命令行和历史。"""

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import func
from sqlmodel import select

from app.core.account_policy import ADMIN_PERMISSIONS
from app.core.database import session_make
from app.core.environment import auto_import
from app.model.user.admin import Admin
from app.model.user.management import AdminAudit
from app.model.user.role import Role, RoleType
from app.model.user.user import RegisterIn


def bootstrap_admin(email: str) -> None:
    """仅在不存在管理员时创建首个系统管理员，不提供默认账户或密码。"""
    password = getpass.getpass("Administrator password: ")
    if password != getpass.getpass("Confirm password: "):
        raise SystemExit("Passwords do not match")
    data = RegisterIn(email=email, password=password)
    auto_import("app.model.user")
    with session_make() as db:
        # 锁住 PostgreSQL 管理表，阻止两个部署进程并发初始化管理员。
        if db.bind.dialect.name == "postgresql":
            from sqlalchemy import text

            db.exec(text("LOCK TABLE admin IN EXCLUSIVE MODE"))
        if db.exec(select(func.count()).select_from(Admin)).one() != 0:
            raise SystemExit("An administrator already exists; use the administration API")
        role = Role(
            name="Self-hosted administrator",
            description="Bootstrap administrator",
            type=RoleType.System,
            permissions=sorted(ADMIN_PERMISSIONS),
        )
        admin = Admin(email=data.email.lower(), password=data.password, name="Administrator", roles=[role])
        db.add(admin)
        db.flush()
        db.add(AdminAudit(admin_id=admin.id, action="admin.bootstrap", target_id=str(admin.id), details={}))
        db.commit()
        print("Administrator created")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    bootstrap = commands.add_parser("bootstrap-admin")
    bootstrap.add_argument("--email", required=True)
    args = parser.parse_args()
    bootstrap_admin(args.email)
