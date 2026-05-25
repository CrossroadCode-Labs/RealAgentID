import json
import time
from core.connection import get_redis, AGENT_TTL

r = get_redis()

# Sensitivity levels
STANDARD = "standard"
ELEVATED = "elevated"
RESTRICTED = "restricted"

def register_tool(
    tool_id: str,
    description: str,
    sensitivity: str = STANDARD,
    permitted_roles: list = None,
    permitted_gates: list = None,
    max_generation: int = 5,
    version: str = "1.0.0"
) -> bool:
    """
    Register a tool in the tool registry.
    Defines who can use it, from where, and
    how deep in a lineage tree.
    """
    try:
        entry = {
            "tool_id": tool_id,
            "description": description,
            "sensitivity": sensitivity,
            "permitted_roles": permitted_roles or [],
            "permitted_gates": permitted_gates or [],
            "max_generation": max_generation,
            "version": version,
            "registered_at": int(time.time()),
        }
        r.set(
            f"tool:{tool_id}",
            json.dumps(entry)
        )
        print(f"[+] Tool '{tool_id}' registered "
              f"(sensitivity: {sensitivity}, "
              f"version: {version})")
        return True
    except Exception as e:
        print(f"[!] Tool registration failed: {e}")
        return False


def get_tool(tool_id: str) -> dict:
    """
    Retrieve a tool registry entry.
    """
    data = r.get(f"tool:{tool_id}")
    if data is None:
        return None
    return json.loads(data)


def verify_tool_access(
    tool_id: str,
    agent_role: str,
    agent_gate: str,
    agent_generation: int
) -> tuple:
    """
    Verify an agent can access a tool based on
    role, gate, and lineage generation.
    Returns (allowed: bool, reason: str)
    """
    tool = get_tool(tool_id)

    if tool is None:
        return False, "tool_not_registered"

    # Check role
    if tool["permitted_roles"] and \
            agent_role not in tool["permitted_roles"]:
        return False, "role_not_permitted"

    # Check gate
    if tool["permitted_gates"] and \
            agent_gate not in tool["permitted_gates"]:
        return False, "gate_not_permitted"

    # Check generation limit
    if agent_generation > tool["max_generation"]:
        return False, "generation_exceeded"

    return True, "authorized"


def record_tool_call(
    tool_id: str,
    agent_id: str,
    lineage_root: str,
    result: str
) -> bool:
    """
    Record a tool call to the pattern store.
    Builds behavioral fingerprint per agent
    and per lineage tree.
    """
    try:
        timestamp = int(time.time())

        # Per-agent pattern
        agent_key = f"tool_pattern:agent:{agent_id}"
        agent_data = r.get(agent_key)
        agent_pattern = json.loads(agent_data) \
            if agent_data else []
        agent_pattern.append({
            "tool_id": tool_id,
            "result": result,
            "timestamp": timestamp
        })
        # Keep last 100 calls per agent
        agent_pattern = agent_pattern[-100:]
        r.set(agent_key, json.dumps(agent_pattern))

        # Per-lineage-tree pattern
        tree_key = f"tool_pattern:tree:{lineage_root}"
        tree_data = r.get(tree_key)
        tree_pattern = json.loads(tree_data) \
            if tree_data else []
        tree_pattern.append({
            "tool_id": tool_id,
            "agent_id": agent_id,
            "result": result,
            "timestamp": timestamp
        })
        # Keep last 500 calls per tree
        tree_pattern = tree_pattern[-500:]
        r.set(tree_key, json.dumps(tree_pattern))

        return True

    except Exception as e:
        print(f"[!] Tool call recording failed: {e}")
        return False


def detect_anomaly(
    tool_id: str,
    agent_id: str,
    lineage_root: str,
    threshold: float = 0.1
) -> bool:
    """
    Check if a tool call is anomalous relative
    to the established lineage tree pattern.
    Returns True if anomalous.
    Threshold is the minimum frequency a tool
    must appear in tree history to be considered
    normal. Below threshold = anomaly.
    """
    try:
        tree_key = f"tool_pattern:tree:{lineage_root}"
        tree_data = r.get(tree_key)

        if tree_data is None:
            # No history yet — not anomalous
            return False

        tree_pattern = json.loads(tree_data)

        if len(tree_pattern) < 10:
            # Not enough history to detect anomalies
            return False

        # Calculate frequency of this tool in tree history
        tool_calls = [
            e for e in tree_pattern
            if e["tool_id"] == tool_id
        ]
        frequency = len(tool_calls) / len(tree_pattern)

        if frequency < threshold:
            print(f"[!] Anomaly detected — '{tool_id}' "
                  f"called by '{agent_id}' "
                  f"is below threshold "
                  f"({frequency:.2%} < {threshold:.2%})")
            return True

        return False

    except Exception as e:
        print(f"[!] Anomaly detection failed: {e}")
        return False


def list_tools() -> None:
    """
    List all registered tools.
    """
    keys = r.keys("tool:*")
    if not keys:
        print("No tools registered.")
        return
    for key in keys:
        data = r.get(key)
        if data:
            tool = json.loads(data)
            print(f"  {tool['tool_id']} "
                  f"[{tool['sensitivity']}] "
                  f"v{tool['version']} — "
                  f"{tool['description']}")


if __name__ == "__main__":
    list_tools()
