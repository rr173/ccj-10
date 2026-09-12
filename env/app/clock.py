"""时间抽象：真实墙钟 + 可调偏移 + 单调递增并持久化的逻辑钟。

- 墙上时间(wall time)：物理时钟，运维/NTP 可能把它拨快或拨慢。
- 逻辑时间(logical time)：一个只增不减的整数计数器，每次 tick +1，
  持有者续约/心跳即留下"我还在干活"的证据。逻辑钟与墙钟无关，
  拨表不会改变它；它被持久化，重启不丢。
"""

from __future__ import annotations

import threading
import time


class Clock:
    def __init__(self, get_wall_offset_ms):
        # 通过回调读取墙钟偏移，偏移量由 Store 持久化，重启后依然生效
        self._get_wall_offset_ms = get_wall_offset_ms
        self._lock = threading.Lock()
        self._logical = 0

    # ---- 墙上时间 -------------------------------------------------------
    def wall_ms(self) -> int:
        return int(time.time() * 1000) + self._get_wall_offset_ms()

    # ---- 逻辑时间 -------------------------------------------------------
    def set_logical(self, value: int) -> None:
        """启动/重启时从持久化存储装载。"""
        with self._lock:
            self._logical = value

    def logical(self) -> int:
        with self._lock:
            return self._logical

    def advance_logical(self, delta: int = 1) -> int:
        if delta < 1:
            raise ValueError("逻辑时间只能向前推进")
        with self._lock:
            self._logical += delta
            return self._logical
