import haslib
import time
import sys
import json
import redis
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from core.connection import get_redis, AGENT_TTL, VALID_ROLES
r = get_redis()

def check_registration_rate_limit(
    source_id: str,
    max_registrations: int = 5,
    window_seconds: int = 3600
) -> bool:
    """
    Rate limit agent registrations per source.
    Prevents Sybil attacks — mass fake identity
    registration to overwhelm or poison the registry.
    Max 5 registrations per hour per source by default.
    """
    key = f"reg_rate:{source_id}"
    current = r.get(key)

    if current is None:
        r.setex(key, window_seconds, 1)
        return True

    if int(current) >= max_registrations:
        print(f"[!] Registration rate limit exceeded "
              f"for source '{source_id}'. "
              f"Possible Sybil attack.")
        return False

    r.incr(key)
    return True

def require_human_approval_for_root(
    agent_id: str,
    approved_by: str = None
) -> bool:
    """
    Root agents (generation 0) require explicit
    human approval before registration.
    Prevents automated self-registration at root level.
    """
    if approved_by is None:
        print(f"[!] Root agent '{agent_id}' registration "
              f"denied — human approval required.")
        return False

    if approved_by.lower() == "system" or \
       approved_by.lower() == "agent":
        print(f"[!] Root agent '{agent_id}' registration "
              f"denied — must be approved by a human, "
              f"not '{approved_by}'.")
        return False

    print(f"[+] Root agent '{agent_id}' approved "
          f"by '{approved_by}'.")
    return True

# Registry chain state
_registry_last_hash = "0" * 64

def _compute_registry_hash(entry: dict) -> str:
    """
    Compute SHA256 hash of a registry entry.
    Links entries into a tamper-evident chain.
    """
    encoded = json.dumps(entry, sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()

def _append_registry_chain(agent_id: str, event: str, data: dict) -> str:
    """
    Append a registry event to the hash chain.
    Every registration, revocation, and modification
    is chained — tampering breaks the chain.
    """
    global _registry_last_hash

    entry = {
        "previous_hash": _registry_last_hash,
        "timestamp": int(time.time()),
        "agent_id": agent_id,
        "event": event,
        "data": data
    }

    current_hash = _compute_registry_hash(entry)
    entry["hash"] = current_hash
    _registry_last_hash = current_hash

    # Store chain entry in Redis
    r.lpush("registry_chain", json.dumps(entry))
    return current_hash

def register_agent_from_key(
    agent_id: str,
    public_key_pem_path: str,
    role: str = "worker",
    source_id: str = "default",
    is_root: bool = False,
    approved_by: str = None
):
    # Sybil rate limit check
    if not check_registration_rate_limit(source_id):
        raise ValueError(f"Registration rate limit exceeded "
                        f"for source '{source_id}'")

    # Root agent human approval check
    if is_root and not require_human_approval_for_root(
            agent_id, approved_by):
        raise ValueError(f"Root agent '{agent_id}' requires "
                        f"human approval")
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role: {role}. Must be one of {VALID_ROLES}")
    with open(public_key_pem_path, "rb") as f:
        public_key = load_pem_public_key(f.read())
    public_key_hex = public_key.public_bytes(
        Encoding.Raw, PublicFormat.Raw
    ).hex()
    data = {"public_key": public_key_hex, "role": role}
    r.setex(f"agent:{agent_id}", AGENT_TTL, json.dumps(data))
    _append_registry_chain(agent_id, "registered", {"role": role})
    print(f"[+] Agent '{agent_id}' registered in Redis as role='{role}' (TTL: {AGENT_TTL}s).")

def get_public_key(agent_id):
    data = r.get(f"agent:{agent_id}")
    if data is None:
        return None
    return json.loads(data).get("public_key")

def get_role(agent_id):
    data = r.get(f"agent:{agent_id}")
    if data is None:
        return None
    return json.loads(data).get("role")

def revoke_agent(agent_id):
    key = f"agent:{agent_id}"
    if r.exists(key):
        r.delete(key)
        print(f"[!] Agent '{agent_id}' revoked and removed from registry.")
        _append_registry_chain(agent_id, "revoked", {})
        return True
    return False

def list_agents():
    keys = r.keys("agent:*")
    if not keys:
        print("No agents registered.")
        return
    for key in keys:
        agent_id = key.split(":", 1)[1]
        data = r.get(key)
        if data:
            parsed = json.loads(data)
            pub_key = parsed.get("public_key", "")
            role = parsed.get("role", "unknown")
            ttl = r.ttl(key)
            print(f"  {agent_id} [{role}]: {pub_key[:16]}... (TTL: {ttl}s)")

if __name__ == "__main__":
    list_agents()
