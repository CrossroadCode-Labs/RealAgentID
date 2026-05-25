import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.keygen import generate_agent_identity
from core.registry import register_agent_from_key
from core.signing import sign_message, verify_message
from core.audit import read_log
from core.lineage import register_lineage, get_lineage, verify_lineage, revoke_tree, register_federated_root, is_federated_root, get_federated_root, revoke_federated_root
from core.tool_registry import register_tool, get_tool, verify_tool_access, record_tool_call, detect_anomaly, list_tools
from core.vault import seal, unseal, revoke_vault, list_vault
from core.sandbox import spawn_sandbox, get_sandbox_log, list_sandboxes

class Agent:
    def __init__(self, name: str, role: str = "worker", keys_dir: str = "./keys"):
        self.name = name
        self.role = role
        self.keys_dir = keys_dir
        self.private_key = f"{keys_dir}/{name}_private.pem"
        self.public_key = f"{keys_dir}/{name}_public.pem"

    def keygen(self):
        return generate_agent_identity(self.name, self.keys_dir)

    def register(self):
        return register_agent_from_key(self.name, self.public_key, self.role)

    def sign(self, payload: dict, channel: str = "default"):
        return sign_message(self.name, self.private_key, channel, payload)

    def verify(self, signed_json: str):
        return verify_message(signed_json, self.public_key)

    def audit(self):
        return read_log()

    def register_lineage(self, parent_id: str = None):
        return register_lineage(self.name, parent_id)

    def get_lineage(self):
        return get_lineage(self.name)

    def verify_lineage(self):
        return verify_lineage(self.name)

    def revoke_tree(self):
        return revoke_tree(self.name)

    def register_federated_root(self, org_name: str, scope_limit: list):
        return register_federated_root(self.name, org_name, scope_limit):

    def is_federated_root(self):
        return is_federated_root(self.name)

    def get_federated_root(self):
        return get_federated_root(self.name)

    def revoke_federated_root(self):
        return revoke_federated_root(self.name)

    def register_tool(self, tool_id: str, description: str, sensitivity: str = "standard", permitted_roles: list = None, permitted_gates: list = None, max_generation: int = 5, version: str = "1.0.0"):
        return register_tool(tool_id, description, sensitivity, permitted_roles, permitted_gates, max_generation, version)

    def verify_tool_access(self, tool_id: str, agent_gate: str):
        return verify_tool_access(tool_id, self.role, agent_gate, self.get_generation())

    def record_tool_call(self, tool_id: str, lineage_root: str, result: str):
        return record_tool_call(tool_id, self.name, lineage_root, result)

    def detect_anomaly(self, tool_id: str, lineage_root: str):
        return detect_anomaly(tool_id, self.name, lineage_root)

    def list_tools(self):
        return list_tools()

    def seal(self, asset_id: str, plaintext: bytes, sensitivity: str = "restricted"):
        return seal(self.name, asset_id, plaintext, sensitivity)

    def unseal(self, asset_id: str):
        return unseal(self.name, asset_id)

    def revoke_vault(self, asset_id: str):
        return revoke_vault(self.name, asset_id)

    def list_vault(self):
        return list_vault(self.name)

    def spawn_sandbox(self, task: dict, sensitivity: str = "restricted", timeout_seconds: int = 300):
        return spawn_sandbox(self.name, task, sensitivity, timeout_seconds)

    def get_sandbox_log(self, sandbox_id: str):
        return get_sandbox_log(sandbox_id)

    def list_sandboxes(self):
        return list_sandboxes(self.name)
