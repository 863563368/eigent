#!/bin/sh
set -eu

# wait for database to be ready
echo "Waiting for database to be ready..."
python scripts/wait_for_db.py
echo "Database is ready!"

# run database migrations
echo "Running database migrations..."
if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
  alembic upgrade head
fi

# start application
echo "Starting application..."
exec uvicorn main:api --host 0.0.0.0 --port 5678 --proxy-headers --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-127.0.0.1}"
