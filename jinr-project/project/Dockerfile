# ---------- build stage ----------
FROM python:3.12-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src

COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt

# ---------- runtime stage ----------
FROM python:3.12-slim AS run

RUN groupadd -r www && useradd -r -g www -d /app -s /usr/sbin/nologin www

WORKDIR /app

COPY --from=build /install /usr/local
COPY app ./app
COPY entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh && mkdir -p /app/data && chown -R www:www /app

USER www

EXPOSE 8000
ENTRYPOINT ["/app/entrypoint.sh"]
