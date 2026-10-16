#!/bin/sh
# 同时备份数据库和上传文件；备份目录包含私有数据，默认仅当前用户可读。
set -eu
umask 077
cd "$(dirname "$0")/.."
destination="${1:-./backups/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$destination"
docker compose --env-file .env.production -f docker-compose.production.yml exec -T postgres \
  pg_dump -U eigent -d eigent --format=custom > "$destination/database.dump"
docker compose --env-file .env.production -f docker-compose.production.yml exec -T api \
  tar -C /app/app/public -czf - upload > "$destination/uploads.tar.gz"
printf 'Backup saved to %s\n' "$destination"
