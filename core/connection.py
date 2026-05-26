# agents/connection.py
# Central Redis connection for RealAgentID
# Single source of truth for all Redis access

import redis
import sys

# --- Config ---
REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0

# Agent registry TTL: 24 hours
AGENT_TTL = 86400

# Replay nonce TTL: 5 minutes
REPLAY_TTL = 300

# Valid agent roles
VALID_ROLES = ["admin", "worker", "readonly", "signal_gen", "risk_guard", "order_router", "compliance_log", "blueprint_agent"]

# Role permissions - which roles can send messages on which channels
ROLE_PERMISSIONS = {
    "admin":          ["*"],
    "worker":         ["tasks:*"],
    "readonly":       [],
    "signal_gen":     ["signal:*"],
    "risk_guard":     ["risk:*", "signal:*"],
    "order_router":   ["order:*", "risk:*"],
    "compliance_log": ["audit:*", "order:*", "signal:*", "risk:*"],
    "blueprint_agent":["blueprint:*", "audit:*"],
}

# --- Connection pool ---
_pool = redis.ConnectionPool(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    decode_responses=True,
    max_connections=10
)

def get_redis() -> redis.Redis:
    """
    Return a Redis client from the connection pool.
    Raises RuntimeError if Redis is unreachable.
    """
    try:
        client = redis.Redis(connection_pool=_pool)
        client.ping()
        return client
    except redis.ConnectionError as e:
        print(f"[RealAgentID] CRITICAL - Redis unavailable: {e}", file=sys.stderr)
        raise RuntimeError(f"Redis connection failed: {e}") from e
