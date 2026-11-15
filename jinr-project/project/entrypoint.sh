#!/bin/sh
set -e

# wait for postgres
until python -c "import psycopg2, os; psycopg2.connect(os.environ['DATABASE_URL'].replace('+psycopg2',''))" 2>/dev/null; do
  echo "waiting for db..."
  sleep 2
done

exec uvicorn app.main:app --host 0.0.0.0 --port 8000
