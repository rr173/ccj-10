"""HTTP 接口 + 后台逻辑钟 ticker。

租约语义速览：
  POST   /leases/acquire       获取（新世代号）
  POST   /leases/renew         续约（世代号不变，软 TTL 顺延）
  POST   /leases/release       释放
  POST   /leases/transfer      安全转移（原子交接：旧持有者即刻失效，
                               新持有者拿更大世代号；transfer_id 幂等）
  POST   /resources/<r>/writes 受租约保护的写入（栅栏校验点）；
                               请求体带 credential_id 即走限时委托路径
委托语义速览：
  POST   /leases/delegations    持有者向指定协作者发放针对某资源的短期凭证
  POST   /leases/delegations/revoke  授权者提前撤销
  GET    /delegations/<id>      按凭证号查授权者/协作者/有效期/世代号/状态
  GET    /resources/<r>/delegations  列某资源的全部委托
  GET    /resources/<r>/history?credential_id=<id>
                               按凭证号过滤：发放/每次使用结果/撤销/过期/失效
  GET    /resources/<r>        查资源当前世代/值
  GET    /resources/<r>/leases 查当前租约
  GET    /resources/<r>/writes 查某次/每次写入是哪一代租约放行的
  GET    /resources/<r>/history 完整租约历史（获取/续约/释放/转移/写入/委托，
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
    DelegationNotFound,
    DelegationRejected,
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
        delegation_ttl_ms=_env_int("DELEGATION_TTL_MS", 15_000),
        delegation_max_ttl_ms=_env_int("DELEGATION_MAX_TTL_MS", 60_000),
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
    # 限时委托
    # ------------------------------------------------------------------
    @app.post("/leases/delegations")
    def grant_delegation():
        data = body()
        resource = require(data, "resource")
        holder = require(data, "holder")
        generation = int(require(data, "generation"))
        # collaborator 的资格校验放在 store 层，不合格也会记入历史
        result = store.grant_delegation(
            resource, holder, generation,
            collaborator=data.get("collaborator"),
            ttl_ms=data.get("ttl_ms"),
            credential_id=data.get("credential_id"),
        )
        return jsonify({"delegation": result}), 201

    @app.post("/leases/delegations/revoke")
    def revoke_delegation():
        data = body()
        resource = require(data, "resource")
        holder = require(data, "holder")
        generation = int(require(data, "generation"))
        credential_id = require(data, "credential_id")
        result = store.revoke_delegation(
            resource, holder, generation, credential_id
        )
        return jsonify({"delegation": result, "revoked": True})

    # ------------------------------------------------------------------
    # 受保护写入
    # ------------------------------------------------------------------
    @app.post("/resources/<resource>/writes")
    def write(resource):
        data = body()
        holder = require(data, "holder")
        credential_id = data.get("credential_id")
        # 持有者直写必须出示世代号；委托写入世代号由凭证锚定，可省
        if credential_id:
            raw_gen = data.get("generation")
            generation = int(raw_gen) if raw_gen not in (None, "") else None
        else:
            generation = int(require(data, "generation"))
        value = data.get("value")
        result = store.write(
            resource, holder, generation, value,
            credential_id=credential_id,
        )
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

    @app.get("/resources/<resource>/delegations")
    def list_delegations(resource):
        limit = min(int(request.args.get("limit", 100)), 1000)
        return jsonify(
            {"resource": resource,
             "delegations": store.list_delegations(resource, limit)}
        )

    @app.get("/resources/<resource>/history")
    def get_history(resource):
        limit = min(int(request.args.get("limit", 200)), 1000)
        # ?credential_id=<id>：只看这张凭证的授权者/协作者/有效期/世代号
        # 与每次使用结果
        credential_id = request.args.get("credential_id")
        return jsonify(
            {"resource": resource,
             "events": store.list_history(
                 resource, limit, credential_id=credential_id)}
        )

    @app.get("/delegations/<credential_id>")
    def get_delegation(credential_id):
        d = store.get_delegation(credential_id)
        if d is None:
            return jsonify(
                {"error": "not_found", "credential_id": credential_id}
            ), 404
        return jsonify(d)

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

    @app.errorhandler(DelegationRejected)
    def _delegation_rejected(exc):
        # 409：凭证已撤销/过期/随租约失效，或协作者不符
        return jsonify({"error": "delegation_rejected",
                        "message": str(exc)}), 409

    @app.errorhandler(DelegationNotFound)
    def _delegation_not_found(exc):
        return jsonify({"error": "not_found", "message": str(exc)}), 404

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
