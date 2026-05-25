import json
import time
import subprocess
import tempfile
import os
from core.connection import get_redis, AGENT_TTL
from core.lineage import get_lineage

r = get_redis()

# Sensitivity level required to trigger sandboxing
SANDBOX_SENSITIVITY_LEVELS = ["restricted"]


def spawn_sandbox(
    agent_id: str,
    task: dict,
    sensitivity: str = "restricted",
    timeout_seconds: int = 300
) -> dict:
    """
    Spawn an isolated execution environment for
    a restricted sensitivity agent task.
    Logs full lifecycle to Redis.
    Returns output after inspection.
    """
    sandbox_id = f"sandbox:{agent_id}:{int(time.time())}"

    try:
        # Log sandbox spawn
        _log_lifecycle(sandbox_id, agent_id, "spawned", task)

        # Verify agent lineage before spawning
        lineage = get_lineage(agent_id)
        if lineage is None:
            _log_lifecycle(sandbox_id, agent_id, "denied", {
                "reason": "lineage_not_found"
            })
            return {
                "sandbox_id": sandbox_id,
                "status": "denied",
                "reason": "lineage_not_found",
                "output": None
            }

        # Write task to temp file — isolated input
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False
        ) as f:
            json.dump(task, f)
            task_file = f.name

        # Log execution start
        _log_lifecycle(sandbox_id, agent_id, "executing", {
            "task_file": task_file,
            "timeout": timeout_seconds
        })

        # Execute in subprocess — isolated process
        result = subprocess.run(
            ["python3", "-c", f"""
import json
with open('{task_file}') as f:
    task = json.load(f)
print(json.dumps({{"status": "completed", "task": task}}))
            """],
            capture_output=True,
            text=True,
            timeout=timeout_seconds
        )

        # Clean up temp file
        os.unlink(task_file)

        # Inspect output before returning
        raw_output = result.stdout.strip()
        inspected = _inspect_output(
            sandbox_id,
            agent_id,
            raw_output
        )

        if not inspected["safe"]:
            _log_lifecycle(sandbox_id, agent_id, "output_blocked", {
                "reason": inspected["reason"]
            })
            return {
                "sandbox_id": sandbox_id,
                "status": "output_blocked",
                "reason": inspected["reason"],
                "output": None
            }

        # Log successful completion
        _log_lifecycle(sandbox_id, agent_id, "completed", {
            "output_length": len(raw_output)
        })

        return {
            "sandbox_id": sandbox_id,
            "status": "completed",
            "output": raw_output
        }

    except subprocess.TimeoutExpired:
        _log_lifecycle(sandbox_id, agent_id, "timeout", {
            "timeout_seconds": timeout_seconds
        })
        return {
            "sandbox_id": sandbox_id,
            "status": "timeout",
            "output": None
        }

    except Exception as e:
        _log_lifecycle(sandbox_id, agent_id, "error", {
            "error": str(e)
        })
        return {
            "sandbox_id": sandbox_id,
            "status": "error",
            "reason": str(e),
            "output": None
        }


def _inspect_output(
    sandbox_id: str,
    agent_id: str,
    output: str
) -> dict:
    """
    Inspect sandbox output before it leaves
    the execution environment.
    Checks for anomalous content patterns.
    """
    if not output:
        return {"safe": False, "reason": "empty_output"}

    # Check output size — oversized output is suspicious
    if len(output) > 1_000_000:
        return {"safe": False, "reason": "output_too_large"}

    # Check for private key patterns in output
    suspicious_patterns = [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
    ]
    for pattern in suspicious_patterns:
        if pattern in output:
            return {
                "safe": False,
                "reason": "private_key_in_output"
            }

    return {"safe": True, "reason": "passed"}


def _log_lifecycle(
    sandbox_id: str,
    agent_id: str,
    event: str,
    details: dict
) -> None:
    """
    Log sandbox lifecycle event to Redis.
    TrailStax integration point.
    """
    entry = {
        "sandbox_id": sandbox_id,
        "agent_id": agent_id,
        "event": event,
        "details": details,
        "timestamp": int(time.time())
    }
    # Append to sandbox log
    log_key = f"sandbox_log:{sandbox_id}"
    existing = r.get(log_key)
    log = json.loads(existing) if existing else []
    log.append(entry)
    r.setex(log_key, AGENT_TTL, json.dumps(log))
    print(f"[sandbox] {event} — {sandbox_id}")


def get_sandbox_log(sandbox_id: str) -> list:
    """
    Retrieve full lifecycle log for a sandbox.
    """
    data = r.get(f"sandbox_log:{sandbox_id}")
    if data is None:
        return []
    return json.loads(data)


def list_sandboxes(agent_id: str) -> list:
    """
    List all sandbox sessions for an agent.
    """
    keys = r.keys(f"sandbox_log:sandbox:{agent_id}:*")
    return [k.replace("sandbox_log:", "") for k in keys]


if __name__ == "__main__":
    print("Sandbox module loaded.")
