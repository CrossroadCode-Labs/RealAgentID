import json
import time
from core.connection import get_redis, AGENT_TTL

r = get_redis()

MAX_GENERATION = 5

def register_lineage(agent_id: str, parent_id: str = None) -> bool:
    """
    Register an agent's lineage in Redis.
    Root agents have no parent_id (generation 0).
    Child agents must have a verified parent in the registry.
    """
    try:
        if parent_id is None:
            # Root agent — generation 0
            lineage = {
                "agent_id": agent_id,
                "parent_id": None,
                "lineage": [agent_id],
                "generation": 0,
                "root_id": agent_id,
                "registered_at": int(time.time()),
            }
        else:
            # Get parent lineage
            parent_data = r.get(f"lineage:{parent_id}")
            if parent_data is None:
                print(f"[!] Parent agent '{parent_id}' not found in lineage registry.")
                return False

            parent_lineage = json.loads(parent_data)
            parent_generation = parent_lineage["generation"]

            # Enforce generation limit
            if parent_generation >= MAX_GENERATION:
                print(f"[!] Generation limit ({MAX_GENERATION}) reached. Cannot spawn further.")
                return False

            # Build child lineage
            lineage = {
                "agent_id": agent_id,
                "parent_id": parent_id,
                "lineage": parent_lineage["lineage"] + [agent_id],
                "generation": parent_generation + 1,
                "root_id": parent_lineage["root_id"],
                "registered_at": int(time.time()),
            }

        r.setex(
            f"lineage:{agent_id}",
            AGENT_TTL,
            json.dumps(lineage)
        )
        print(f"[+] Lineage registered for '{agent_id}' "
              f"(generation {lineage['generation']}, "
              f"root: {lineage['root_id']})")
        return True

    except Exception as e:
        print(f"[!] Lineage registration failed: {e}")
        return False


def get_lineage(agent_id: str) -> dict:
    """
    Retrieve full lineage for an agent.
    """
    data = r.get(f"lineage:{agent_id}")
    if data is None:
        return None
    return json.loads(data)


def get_generation(agent_id: str) -> int:
    """
    Get the generation number of an agent.
    Returns -1 if not found.
    """
    lineage = get_lineage(agent_id)
    if lineage is None:
        return -1
    return lineage["generation"]


def verify_lineage(agent_id: str) -> bool:
    """
    Verify that an agent has a valid, unbroken lineage
    back to a registered root agent.
    """
    lineage = get_lineage(agent_id)
    if lineage is None:
        return False

    # Check if root is a trusted federated root
    root_id = lineage["root_id"]
    if is_federated_root(root_id):
        print(f"[+] Federated root '{root_id}' verified.")
        return True

    # Walk the lineage chain and verify each ancestor exists
    for ancestor_id in lineage["lineage"]:
        if r.get(f"agent:{ancestor_id}") is None:
            print(f"[!] Broken lineage — ancestor '{ancestor_id}' "
                  f"not found in registry.")
            return False

    return True


def revoke_lineage(agent_id: str) -> bool:
    """
    Revoke an agent's lineage entry.
    Does not cascade — use revoke_tree for full subtree revocation.
    """
    key = f"lineage:{agent_id}"
    if r.exists(key):
        r.delete(key)
        print(f"[!] Lineage revoked for '{agent_id}'.")
        return True
    return False


def revoke_tree(root_id: str) -> int:
    """
    Revoke all lineage entries whose root_id matches.
    Returns count of revoked entries.
    """
    keys = r.keys("lineage:*")
    revoked = 0
    for key in keys:
        data = r.get(key)
        if data:
            lineage = json.loads(data)
            if lineage.get("root_id") == root_id:
                r.delete(key)
                revoked += 1
                print(f"[!] Revoked lineage for '{lineage['agent_id']}'")
    print(f"[!] Tree revocation complete — {revoked} agents revoked.")
    return revoked


def list_lineage() -> None:
    """
    List all registered lineage entries.
    """
    keys = r.keys("lineage:*")
    if not keys:
        print("No lineage entries found.")
        return
    for key in keys:
        data = r.get(key)
        if data:
            lineage = json.loads(data)
            print(f"  {lineage['agent_id']} "
                  f"[gen {lineage['generation']}] "
                  f"root: {lineage['root_id']} "
                  f"lineage: {' -> '.join(lineage['lineage'])}")

def register_federated_root(
    root_id: str,
    org_name: str,
    scope_limit: list,
    approved_by: str = "human"
) -> bool:
    """
    Register a trusted external org's root agent.
    Their spawned agents can pass lineage verification
    within the approved scope limit.
    """
    try:
        entry = {
            "root_id": root_id,
            "org_name": org_name,
            "trust_level": "federated",
            "scope_limit": scope_limit,
            "approved_by": approved_by,
            "registered_at": int(time.time()),
        }
        r.set(
            f"federated_root:{root_id}",
            json.dumps(entry)
        )
        print(f"[+] Federated root '{root_id}' registered "
              f"for org '{org_name}' "
              f"with scope: {scope_limit}")
        return True
    except Exception as e:
        print(f"[!] Federated root registration failed: {e}")
        return False


def is_federated_root(root_id: str) -> bool:
    """
    Check if a root_id belongs to an approved
    federated external org.
    """
    return r.exists(f"federated_root:{root_id}") == 1


def get_federated_root(root_id: str) -> dict:
    """
    Retrieve federated root entry.
    """
    data = r.get(f"federated_root:{root_id}")
    if data is None:
        return None
    return json.loads(data)


def revoke_federated_root(root_id: str) -> bool:
    """
    Revoke a federated root — immediately invalidates
    all agents from that external org.
    """
    key = f"federated_root:{root_id}"
    if r.exists(key):
        r.delete(key)
        print(f"[!] Federated root '{root_id}' revoked. "
              f"All descendant agents now invalid.")
        return True
    return False

if __name__ == "__main__":
    list_lineage()
