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
import ipaddress
import os
import secrets
from pathlib import Path
from urllib.parse import urlparse


def initialize(api_origin: str, web_origin: str, *, http_ip: bool = False) -> Path:
    """默认生成 HTTPS 配置；显式 IP 模式允许受控网络中的 HTTP 部署。"""
    for origin in (api_origin, web_origin):
        parsed = urlparse(origin)
        if http_ip:
            address = ipaddress.IPv4Address(parsed.hostname or "")
            if address.is_unspecified or address.is_multicast:
                raise ValueError("Supply a reachable server IPv4 address")
        if (
            parsed.scheme != ("http" if http_ip else "https")
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or (parsed.port != 3001 if http_ip else parsed.port is not None)
        ):
            raise ValueError("Supply HTTPS origins, or explicitly select HTTP IPv4 deployment on port 3001")
    directory = Path(__file__).resolve().parents[1]
    target = directory / ".env.production"
    content = (directory / ".env.production.example").read_text(encoding="utf-8")
    for name in ("POSTGRES_PASSWORD", "secret_key", "CHAT_SHARE_SECRET_KEY", "CHAT_SHARE_SALT"):
        content = content.replace(f"{name}=change-me-generated-by-script", f"{name}={secrets.token_hex(32)}")
    content = content.replace("https://api.example.com", api_origin.rstrip("/"))
    content = content.replace("https://app.example.com", web_origin.rstrip("/"))
    content += f"\nAPI_DOMAIN={urlparse(api_origin).hostname}\n"
    if http_ip:
        # IP 模式直接暴露 API，不启动 Caddy，也不信任外部转发头。
        content = content.replace("ALLOW_HTTP_IP_DEPLOYMENT=false", "ALLOW_HTTP_IP_DEPLOYMENT=true")
        content = content.replace("API_BIND_ADDRESS=127.0.0.1", "API_BIND_ADDRESS=0.0.0.0")
        content = content.replace(
            "REMOTE_CONTROL_TRUSTED_PROXY_HOSTS=172.30.21.10", "REMOTE_CONTROL_TRUSTED_PROXY_HOSTS=127.0.0.1"
        )
        content = content.replace("FORWARDED_ALLOW_IPS=172.30.21.10", "FORWARDED_ALLOW_IPS=127.0.0.1")
    # O_EXCL 防止重跑部署命令时覆盖线上数据库密码及令牌签名密钥。
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    return target


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-origin")
    parser.add_argument("--web-origin")
    parser.add_argument("--http-ip", help="Server IPv4 address for HTTP deployment on port 3001")
    args = parser.parse_args()
    if args.http_ip:
        if args.api_origin or args.web_origin:
            parser.error("Use --http-ip alone, without origin arguments")
        origin = f"http://{args.http_ip}:3001"
        result = initialize(origin, origin, http_ip=True)
    else:
        if not args.api_origin or not args.web_origin:
            parser.error("Supply --http-ip or both --api-origin and --web-origin")
        result = initialize(args.api_origin, args.web_origin)
    print(f"Created {result} (secrets are not printed)")
