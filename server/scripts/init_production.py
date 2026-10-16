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

"""生成私有生产配置，拒绝覆盖已有密钥。"""

import argparse
import os
import secrets
from pathlib import Path
from urllib.parse import urlparse


def initialize(api_origin: str, web_origin: str) -> Path:
    """仅接受 HTTPS origin，使用独立随机值生成所有服务密钥。"""
    for origin in (api_origin, web_origin):
        parsed = urlparse(origin)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.port is not None
        ):
            raise ValueError("Supply HTTPS origins without credentials, ports, paths or query strings")
    directory = Path(__file__).resolve().parents[1]
    target = directory / ".env.production"
    content = (directory / ".env.production.example").read_text(encoding="utf-8")
    for name in ("POSTGRES_PASSWORD", "secret_key", "CHAT_SHARE_SECRET_KEY", "CHAT_SHARE_SALT"):
        content = content.replace(f"{name}=change-me-generated-by-script", f"{name}={secrets.token_hex(32)}")
    content = content.replace("https://api.example.com", api_origin.rstrip("/"))
    content = content.replace("https://app.example.com", web_origin.rstrip("/"))
    content += f"\nAPI_DOMAIN={urlparse(api_origin).hostname}\n"
    # O_EXCL 防止重跑部署命令时覆盖线上数据库密码及令牌签名密钥。
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    return target


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-origin", required=True)
    parser.add_argument("--web-origin", required=True)
    args = parser.parse_args()
    print(f"Created {initialize(args.api_origin, args.web_origin)} (secrets are not printed)")
