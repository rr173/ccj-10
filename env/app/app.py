"""HTTP 接口 + 后台逻辑钟 ticker。

租约语义速览：
  POST   /leases/acquire       获取（新世代号）
  POST   /leases/renew         续约（世代号不变，软 TTL 顺延）
  POST   /leases/release       释放
  POST   /leases/transfer      安全转移（原子交接：旧持有者即刻失效，
                               新持有者拿更大世代号；transfer_id 幂等）
  POST   /resources/<r>/writes 受租约保护的写入（栅栏校验点）
  GET    /resources/<r>        查资源当前世代/值
  GET    /resources/<r>/leases 查当前租约
  GET    /resources/<r>/writes 查某次/每次写入是哪一代租约放行的
  GET    /resources/<r>/history 完整租约历史（获取/续约/释放/转移/写入，
                               含被拒绝的操作，按审计顺序排列）
  GET    /writes/<id>          按写入 ID 反查放行世代
调试/演练故障用（生产可通过 ENABLE_DEBUG_API=0 关闭）：
  POST   /debug/tick           手动推进逻辑钟
  POST   /debug/wall-shift     拨墙钟（可正可负）
  GET    /debug/now            看两种时钟读数
"""

from __future__ import annotations

import os
import threading
import time

from flask import Flask, jsonify, request

from .store import (
    Conflict,
    GenerationTooSmall,
    LeaseGone,
    Store,
)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw not in (None, "") else default


def create_app(
    db_path: str | None = None,
    *,
    start_ticker: bool = True,
    enable_debug_api: bool | None = None,
) -> Flask:
    app = Flask(__name__)

    db_path = db_path or os.environ.get("DB_PATH", "/data/leases.db")
    store = Store(
        db_path,
        ttl_ms=_env_int("LEASE_TTL_MS", 15_000),
        max_ttl_ms=_env_int("LEASE_MAX_TTL_MS", 60_000),
        hard_ttl_ms=_env_int("LEASE_HARD_TTL_MS", 60_000),
        logical_grace=_env_int("LOGICAL_GRACE_TICKS", 3),
    )
    app.extensions["store"] = store
    if enable_debug_api is None:
        enable_debug_api = os.environ.get("ENABLE_DEBUG_API", "1") == "1"

    tick_interval = float(os.environ.get("LOGICAL_TICK_INTERVAL_S", "1"))
    stop_event = threading.Event()

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------
    def body() -> dict:
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}

    def require(data: dict, key: str):
        value = data.get(key)
        if value in (None, ""):
            raise Conflict(f"缺少必填参数: {key}")
        return value

    # ------------------------------------------------------------------
    # 租约
    # ------------------------------------------------------------------
    @app.post("/leases/acquire")
    def acquire():
        data = body()
        resource = require(data, "resource")
        holder = require(data, "holder")
        ttl_ms = data.get("ttl_ms")
        view, created = store.acquire(resource, holder, ttl_ms)
        return jsonify({"acquired": created, "lease": view}), 201 if created else 200

    @app.post("/leases/renew")
    def renew():
        data = body()
        resource = require(data, "resource")
        holder = require(data, "holder")
        generation = int(require(data, "generation"))
        return jsonify({"lease": store.renew(resource, holder, generation)})

    @app.post("/leases/release")
    def release():
        data = body()
        resource = require(data, "resource")
        holder = require(data, "holder")
        generation = int(require(data, "generation"))
        store.release(resource, holder, generation)
        return jsonify({"released": True, "resource": resource})

    @app.post("/leases/transfer")
    def transfer():
        data = body()
        resource = require(data, "resource")
        holder = require(data, "holder")
        generation = int(require(data, "generation"))
        # to_holder 的校验放在 store 层，不合格接收者也会记入历史
        result = store.transfer(
            resource, holder, generation,
            to_holder=data.get("to_holder"),
            transfer_id=data.get("transfer_id"),
            ttl_ms=data.get("ttl_ms"),
        )
        return jsonify(result), 200 if result["replayed"] else 201

    # ------------------------------------------------------------------
    # 受保护写入
    # ------------------------------------------------------------------
    @app.post("/resources/<resource>/writes")
    def write(resource):
        data = body()
        holder = require(data, "holder")
        generation = int(require(data, "generation"))
        value = data.get("value")
        result = store.write(resource, holder, generation, value)
        return jsonify(result), 201

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    @app.get("/resources/<resource>")
    def get_resource(resource):
        res = store.get_resource(resource)
        if res is None:
            return jsonify({"error": "not_found", "resource": resource}), 404
        return jsonify(res)

    @app.get("/resources/<resource>/leases")
    def get_lease(resource):
        lease = store.get_lease(resource)
        if lease is None:
            return jsonify({"resource": resource, "state": "none"}), 404
        return jsonify(lease)

    @app.get("/resources/<resource>/writes")
    def list_writes(resource):
        limit = min(int(request.args.get("limit", 100)), 1000)
        return jsonify(
            {"resource": resource, "writes": store.list_writes(resource, limit)}
        )

    @app.get("/resources/<resource>/history")
    def get_history(resource):
        limit = min(int(request.args.get("limit", 200)), 1000)
        return jsonify(
            {"resource": resource, "events": store.list_history(resource, limit)}
        )

    @app.get("/writes/<int:write_id>")
    def get_write(write_id):
        w = store.get_write(write_id)
        if w is None:
            return jsonify({"error": "not_found", "write_id": write_id}), 404
        return jsonify(w)

    # ------------------------------------------------------------------
    # 调试：手动驱动两种时钟，演练"拨表/逻辑卡死"故障
    # ------------------------------------------------------------------
    @app.post("/debug/tick")
    def debug_tick():
        steps = int(body().get("steps", 1))
        return jsonify({"logical": store.tick(steps)})

    @app.post("/debug/wall-shift")
    def debug_wall_shift():
        delta_ms = int(require(body(), "delta_ms"))
        return jsonify({"wall_ms": store.shift_wall(delta_ms)})

    @app.get("/debug/now")
    def debug_now():
        return jsonify(
            {
                "wall_ms": store.clock.wall_ms(),
                "logical": store.clock.logical(),
            }
        )

    @app.before_request
    def _guard_debug():
        if request.path.startswith("/debug") and not enable_debug_api:
            return jsonify({"error": "debug_api_disabled"}), 403
        return None

    # ------------------------------------------------------------------
    # 错误处理
    # ------------------------------------------------------------------
    @app.errorhandler(GenerationTooSmall)
    def _gen_conflict(exc):
        return jsonify({"error": "generation_fence", "message": str(exc)}), 409

    @app.errorhandler(LeaseGone)
    def _gone(exc):
        # 412：前提（存在生效租约）不满足
        return jsonify({"error": "no_active_lease", "message": str(exc)}), 412

    @app.errorhandler(Conflict)
    def _conflict(exc):
        return jsonify({"error": "conflict", "message": str(exc)}), 409

    @app.errorhandler(404)
    def _not_found(exc):
        return jsonify({"error": "not_found"}), 404

    @app.errorhandler(Exception)
    def _internal(exc):
        if isinstance(exc, (ValueError, TypeError)):
            return jsonify({"error": "bad_request", "message": str(exc)}), 400
        raise exc

    # ------------------------------------------------------------------
    # 后台逻辑钟：每秒 +1 并顺带收割双时钟一致认定过期的租约
    # ------------------------------------------------------------------
    def _run_ticker():
        while not stop_event.wait(tick_interval):
            try:
                store.tick(1)
            except Exception:  # noqa: BLE001 - 后台线程不能因单次异常退出
                app.logger.exception("逻辑钟 tick 失败")

    if start_ticker:
        t = threading.Thread(target=_run_ticker, name="logical-ticker", daemon=True)
        t.start()

    def _stop(*_):
        stop_event.set()

    import atexit

    atexit.register(_stop)
    return app
