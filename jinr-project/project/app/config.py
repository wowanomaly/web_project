import os

LOG_URL       = os.getenv("LOG_URL", "http://158.160.148.0:9000/jcount.log.gz")
LOG_LOCAL     = os.getenv("LOG_LOCAL", "/app/data/jcount.log")
GEOIP_DB      = os.getenv("GEOIP_DB", "/app/data/GeoLite2-City.mmdb")
DATABASE_URL  = os.getenv("DATABASE_URL", "postgresql+psycopg2://jinr:jinr@db:5432/jinr")
CURL_HAMMER_IP = os.getenv("CURL_HAMMER_IP", "159.93.25.196")
