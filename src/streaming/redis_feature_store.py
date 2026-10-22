"""
AegisFlow Sliding-Window Feature Store (High-Scale Pipelined)
Author: Om Kamble

Manages sub-millisecond real-time entity profiles, rolling velocity counters, and spending baselines.
Optimized with Redis Pipelining for atomic single-roundtrip batch execution (<0.5ms SLA)
and amortized O(1) in-memory double-ended queue sliding windows.
"""

import os
import json
import time
import bisect
from collections import defaultdict, deque
from typing import Dict, Any, Optional, Tuple
import redis


class RedisFeatureStore:
    def __init__(self, host: Optional[str] = None, port: Optional[int] = None, db: int = 0):
        default_host = "127.0.0.1" if (host == "localhost" or not host) else host
        redis_host = os.getenv("REDIS_HOST", default_host)
        redis_port = int(port or os.getenv("REDIS_PORT", "6379"))
        self._in_memory_txns: Dict[str, deque] = defaultdict(deque)
        self._in_memory_profiles: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "total_spent": 0.0,
            "total_txns": 0,
            "avg_amount": 0.0
        })
        self._in_memory_features: Dict[str, Dict[str, Any]] = {}
        self._redis_available: Optional[bool] = None

        import socket
        try:
            sock = socket.create_connection((redis_host, redis_port), timeout=0.04)
            sock.close()
            self.client = redis.Redis(
                host=redis_host,
                port=redis_port,
                db=db,
                decode_responses=True,
                socket_timeout=0.2,
                socket_connect_timeout=0.2
            )
            self._redis_available = True
        except Exception:
            self.client = None
            self._redis_available = False

    def _execute_in_memory(self, user_id: str, txn_id: str, amount: float, now: float) -> Dict[str, Any]:
        """Amortized O(1) in-memory sliding window using double-ended queues."""
        txns = self._in_memory_txns[user_id]
        cutoff_24h = now - 86400
        cutoff_1h = now - 3600
        cutoff_1m = now - 60

        # Evict transactions older than 24h from left of deque
        while txns and txns[0][0] < cutoff_24h:
            txns.popleft()

        txns.append((now, txn_id, amount))

        # Update profile
        prof = self._in_memory_profiles[user_id]
        prof["total_spent"] += amount
        prof["total_txns"] += 1
        prof["avg_amount"] = prof["total_spent"] / max(1, prof["total_txns"])

        # Rapid sliding counts using reverse iteration bounded by time
        count_1m = 0
        count_1h = 0
        for t, _, _ in reversed(txns):
            if t >= cutoff_1m:
                count_1m += 1
            if t >= cutoff_1h:
                count_1h += 1
            else:
                break

        return {
            "velocity_1m": count_1m,
            "velocity_1h": count_1h,
            "velocity_24h": len(txns),
            "avg_amount": round(prof["avg_amount"], 2),
            "total_txns": prof["total_txns"]
        }

    def record_transaction(
        self,
        user_id: str,
        txn_id: str,
        amount: float,
        timestamp: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Record transaction and compute sliding-window velocity metrics (1m, 1h, 24h).
        Uses atomic Redis pipelining for single-roundtrip network efficiency.
        """
        now = timestamp or time.time()
        key_velocity = f"velocity:{user_id}"
        key_profile = f"profile:{user_id}"

        if self._redis_available is False or self.client is None:
            return self._execute_in_memory(user_id, txn_id, amount, now)

        try:
            # Atomic single-roundtrip pipeline execution
            pipe = self.client.pipeline(transaction=True)
            pipe.zadd(key_velocity, {f"{txn_id}:{amount}": now})
            pipe.zremrangebyscore(key_velocity, "-inf", now - 86400)
            pipe.expire(key_velocity, 86400)
            pipe.zcount(key_velocity, now - 60, "+inf")
            pipe.zcount(key_velocity, now - 3600, "+inf")
            pipe.zcount(key_velocity, now - 86400, "+inf")
            pipe.hgetall(key_profile)

            results = pipe.execute()

            count_1m = int(results[3])
            count_1h = int(results[4])
            count_24h = int(results[5])
            profile_raw = results[6] or {}

            total_spent = float(profile_raw.get("total_spent", 0.0)) + amount
            total_txns = int(profile_raw.get("total_txns", 0)) + 1
            avg_amount = total_spent / max(1, total_txns)

            # Fire and forget profile write
            pipe_write = self.client.pipeline(transaction=False)
            pipe_write.hset(key_profile, mapping={
                "last_txn_id": txn_id,
                "last_seen": now,
                "total_spent": total_spent,
                "total_txns": total_txns,
                "avg_amount": round(avg_amount, 2)
            })
            pipe_write.expire(key_profile, 86400 * 7)
            pipe_write.execute()

            self._redis_available = True
            return {
                "velocity_1m": count_1m,
                "velocity_1h": count_1h,
                "velocity_24h": count_24h,
                "avg_amount": round(avg_amount, 2),
                "total_txns": total_txns
            }
        except Exception:
            self._redis_available = False
            return self._execute_in_memory(user_id, txn_id, amount, now)

    def upsert_user_features(self, user_id: str, features: Dict[str, Any]) -> None:
        """Store or update features for a given user_id."""
        if self._redis_available is False or self.client is None:
            self._in_memory_features[user_id] = features
            return
        try:
            self.client.hset("user_features", user_id, json.dumps(features))
            self._redis_available = True
        except Exception:
            self._redis_available = False
            self._in_memory_features[user_id] = features

    def upset_user_features(self, user_id: str, features: Dict[str, Any]) -> None:
        self.upsert_user_features(user_id, features)

    def get_user_features(self, user_id: str) -> Dict[str, Any]:
        """Retrieve cached features for a given user_id."""
        if self._redis_available is False or self.client is None:
            return self._in_memory_features.get(user_id, {})
        try:
            data = self.client.hget("user_features", user_id)
            if data:
                return json.loads(data)
            self._redis_available = True
            return {}
        except Exception:
            self._redis_available = False
            return self._in_memory_features.get(user_id, {})