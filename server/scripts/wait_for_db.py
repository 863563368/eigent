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

"""启动前校验配置，并有界等待数据库，避免容器永久挂起。"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import create_engine, text

from app.core.deployment import validate_production_settings
from app.core.environment import env_or_fail


def wait_for_database() -> None:
    """在最多两分钟内检查数据库连接，错误不输出包含密码的连接串。"""
    validate_production_settings()
    engine = create_engine(env_or_fail("database_url"), connect_args={"connect_timeout": 5})
    try:
        for attempt in range(60):
            try:
                with engine.connect() as connection:
                    connection.execute(text("SELECT 1"))
                return
            except Exception:
                if attempt == 59:
                    raise SystemExit("Database did not become ready") from None
                time.sleep(2)
    finally:
        engine.dispose()


if __name__ == "__main__":
    wait_for_database()
