"""
AegisFlow Sliding-Window Feature Store
Manages sub-millisecond real-time entity profiles, rolling velocity counters, and spending baselines.
"""

import os
import json
import time
import redis
from typing import Dict, Any, Optional, Tuple


class RedisFeatureStore:
    def __init__(self, host: Optional[str] = None, port: Optional[int] = None, db: int = 0):
        redis_host = host or os.getenv("REDIS_HOST", "localhost")
        redis_port = int(port or os.getenv("REDIS_PORT", "6379"))
        self._in_memory_fallback: Dict[str, Any] = {}
        self._redis_available: Optional[bool] = None
        self.client = redis.Redis(
            host=redis_host,
            port=redis_port,
            db=db,
            decode_responses=True,
            socket_timeout=0.5,
            socket_connect_timeout=0.3
        )

    def _execute_in_memory(self, user_id: str, txn_id: str, amount: float, now: float) -> Dict[str, Any]:
        user_data = self._in_memory_fallback.setdefault(user_id, {
            "txns": [],
            "total_spent": 0.0,
            "total_txns": 0
        })
        user_data["txns"].append((now, txn_id, amount))
        user_data["total_spent"] += amount
        user_data["total_txns"] += 1

        # Prune older than 24h
        user_data["txns"] = [t for t in user_data["txns"] if now - t[0] <= 86400]
        count_1m = sum(1 for t in user_data["txns"] if now - t[0] <= 60)
        count_1h = sum(1 for t in user_data["txns"] if now - t[0] <= 3600)
        avg = user_data["total_spent"] / user_data["total_txns"]

        return {
            "velocity_1m": count_1m,
            "velocity_1h": count_1h,
            "velocity_24h": len(user_data["txns"]),
            "avg_amount": round(avg, 2),
            "total_txns": user_data["total_txns"]
        }

    def record_transaction(self, user_id: str, txn_id: str, amount: float, timestamp: Optional[float] = None) -> Dict[str, Any]:
        """Record transaction and compute sliding-window velocity metrics (1m, 1h, 24h)."""
        now = timestamp or time.time()
        key_velocity = f"velocity:{user_id}"
        key_profile = f"profile:{user_id}"

        if self._redis_available is False:
            return self._execute_in_memory(user_id, txn_id, amount, now)

        try:
            # 1. Sliding window using Redis Sorted Set
            self.client.zadd(key_velocity, {f"{txn_id}:{amount}": now})
            self.client.zremrangebyscore(key_velocity, "-inf", now - 86400)
            self.client.expire(key_velocity, 86400)

            count_1m = self.client.zcount(key_velocity, now - 60, "+inf")
            count_1h = self.client.zcount(key_velocity, now - 3600, "+inf")
            count_24h = self.client.zcount(key_velocity, now - 86400, "+inf")

            profile_raw = self.client.hgetall(key_profile)
            total_spent = float(profile_raw.get("total_spent", 0.0)) + amount
            total_txns = int(profile_raw.get("total_txns", 0)) + 1
            avg_amount = total_spent / total_txns

            self.client.hset(key_profile, mapping={
                "last_txn_id": txn_id,
                "last_seen": now,
                "total_spent": total_spent,
                "total_txns": total_txns,
                "avg_amount": round(avg_amount, 2)
            })
            self.client.expire(key_profile, 86400 * 7)
            self._redis_available = True

            return {
                "velocity_1m": int(count_1m),
                "velocity_1h": int(count_1h),
                "velocity_24h": int(count_24h),
                "avg_amount": round(avg_amount, 2),
                "total_txns": total_txns
            }
        except Exception:
            self._redis_available = False
            return self._execute_in_memory(user_id, txn_id, amount, now)

    def upsert_user_features(self, user_id: str, features: Dict[str, Any]) -> None:
        """Store or update features for a given user_id."""
        if self._redis_available is False:
            self._in_memory_fallback[f"feat:{user_id}"] = features
            return
        try:
            self.client.hset("user_features", user_id, json.dumps(features))
            self._redis_available = True
        except Exception:
            self._redis_available = False
            self._in_memory_fallback[f"feat:{user_id}"] = features

    def upset_user_features(self, user_id: str, features: Dict[str, Any]) -> None:
        self.upsert_user_features(user_id, features)

    def get_user_features(self, user_id: str) -> Dict[str, Any]:
        """Retrieve cached features for a given user_id."""
        if self._redis_available is False:
            return self._in_memory_fallback.get(f"feat:{user_id}", {})
        try:
            data = self.client.hget("user_features", user_id)
            if data:
                return json.loads(data)
            self._redis_available = True
        except Exception:
            self._redis_available = False
            return self._in_memory_fallback.get(f"feat:{user_id}", {})
        return {}