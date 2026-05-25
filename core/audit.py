import os
import sys
import json
from datetime import datetime, timezone
from pathlib import Path

# Import core local SQLite db
from core import db as local_db

# Import Neo4j db from root
sys.path.insert(0, str(Path(__file__).parent.parent))
import db as neo4j_db

LOG_FILE = "./logs/realagentid_audit.log"

def write_log(event: str, agent_id: str, channel: str, result: str, reason=None, message_id=None, latency_ms=None):
    os.makedirs("./logs", exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "agent_id": agent_id,
        "channel": channel,
        "result": result,
    }
    if reason:
        entry["reason"] = reason
    if message_id:
        entry["message_id"] = message_id
    if latency_ms is not None:
        entry["latency_ms"] = round(latency_ms, 3)
    line = json.dumps(entry)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")
    local_db.insert_event(
        timestamp=entry["timestamp"],
        event=entry["event"],
        agent_id=entry["agent_id"],
        channel=entry.get("channel"),
        result=entry["result"],
        message_id=entry.get("message_id"),
        reason=entry.get("reason"),
        latency_ms=entry.get("latency_ms")
    )
    try:
        with neo4j_db.driver.session() as session:
            session.run("""
                MERGE (a:Agent {agent_id: $agent_id})
                CREATE (e:AuditEntry {
                    timestamp: $timestamp,
                    event: $event,
                    result: $result,
                    channel: $channel
                })
                CREATE (a)-[:SIGNED]->(e)
            """, **entry)
    except Exception as ex:
        print(f"[Neo4j] Mirror failed: {ex}", file=sys.stderr)
    print(f"[RealAgentID AUDIT] {result} | {event} | agent: {agent_id}", file=sys.stderr)

def read_log():
    if not os.path.exists(LOG_FILE):
        print("No audit log found.")
        return
    with open(LOG_FILE, "r") as f:
        for line in f:
            print(line.strip())

if __name__ == "__main__":
    read_log()
