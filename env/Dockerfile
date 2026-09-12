FROM python:3.11-slim

WORKDIR /srv

# 先装依赖，利用层缓存
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY wsgi.py .

# 租约/世代号/审计全部持久化在这个目录，必须挂卷
RUN mkdir -p /data
VOLUME ["/data"]

ENV DB_PATH=/data/leases.db \
    LEASE_TTL_MS=15000 \
    LEASE_MAX_TTL_MS=60000 \
    LEASE_HARD_TTL_MS=60000 \
    LOGICAL_GRACE_TICKS=3 \
    LOGICAL_TICK_INTERVAL_S=1 \
    ENABLE_DEBUG_API=1

EXPOSE 8080

# 单 worker + 多线程：进程内互斥锁串行化状态变更，SQLite 也不支持多进程并发写
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", \
     "--threads", "8", "--timeout", "60", "wsgi:app"]

HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/debug/now').status==200 else 1)"
