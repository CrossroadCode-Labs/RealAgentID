"""
RealAgentID Attestation Bundle
Generates a cryptographically signed bundle proving agent identity,
code integrity, and runtime state at the moment of action.
"""

import json
import time
import uuid
import hashlib
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import audit
from signing import load_private_key
from registry import get_public_key, get_role


def hash_file(filepath: str) -> str:
    """SHA256 hash of a file — proves code integrity."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return "file_not_found"


def hash_string(data: str) -> str:
    """SHA256 hash of a string."""
    return hashlib.sha256(data.encode()).hexdigest()


def build_attestation_bundle(
    agent_id: str,
    private_key_path: str,
    action: str,
    channel: str,
    payload: dict,
    sbom_path: str = None,
    agent_script_path: str = None,
    ttl_seconds: int = 300,
    permissions: list = None,
) -> str:
    """
    Build and sign an attestation bundle for an agent action.

    The bundle proves:
    - WHO the agent is (identity + registry lookup)
    - WHAT it is (code hash, SBOM reference)
    - WHAT it did (action + payload)
    - WHEN it acted (timestamp + TTL)
    - UNDER WHAT AUTHORITY (role + permissions)

    Returns a JSON string containing the signed bundle.
    """

    # --- Identity layer ---
    agent_role = get_role(agent_id) or "unknown"
    public_key_hex = get_public_key(agent_id)
    registry_verified = public_key_hex is not None

    # --- Integrity layer ---
    code_hash = hash_file(agent_script_path) if agent_script_path else "not_provided"
    sbom_hash = hash_file(sbom_path) if sbom_path else "not_provided"

    # --- Runtime claims ---
    issued_at = time.time()
    expires_at = issued_at + ttl_seconds
    bundle_id = str(uuid.uuid4())

    claims = {
        "bundle_id": bundle_id,
        "agent_id": agent_id,
        "agent_role": agent_role,
        "registry_verified": registry_verified,
        "action": action,
        "channel": channel,
        "payload": payload,
        "permissions": permissions or [],
        "code_hash": code_hash,
        "sbom_hash": sbom_hash,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "ttl_seconds": ttl_seconds,
        "realagentid_version": "0.1.0",
    }

    # --- Sign the claims ---
    claims_bytes = json.dumps(claims, sort_keys=True).encode()
    private_key = load_private_key(private_key_path)
    signature = private_key.sign(claims_bytes)
    signature_b64 = base64.b64encode(signature).decode()

    # --- Assemble bundle ---
    bundle = {
        "claims": claims,
        "signature": signature_b64,
        "signing_key_id": agent_id,
        "bundle_format": "RealAgentID-Attestation-v1",
    }

    # --- Audit log ---
    audit.write_log(
        event="attestation_bundle_created",
        agent_id=agent_id,
        channel=channel,
        result="VALID",
        message_id=bundle_id,
    )

    return json.dumps(bundle, indent=2)


def verify_attestation_bundle(bundle_json: str) -> dict:
    """
    Verify a RealAgentID attestation bundle.

    Checks:
    - Signature validity
    - TTL expiry
    - Registry presence
    - Claims integrity
    """
    bundle = json.loads(bundle_json)
    claims = bundle["claims"]
    signature = base64.b64decode(bundle["signature"])
    agent_id = claims["agent_id"]
    bundle_id = claims["bundle_id"]

    # TTL check
    if time.time() > claims["expires_at"]:
        raise ValueError(
            f"Attestation bundle expired: bundle_id {bundle_id}"
        )

    # Registry check
    public_key_hex = get_public_key(agent_id)
    if not public_key_hex:
        raise ValueError(
            f"Agent not in registry: {agent_id}"
        )

    # Signature check
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    public_key = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(public_key_hex)
    )
    claims_bytes = json.dumps(claims, sort_keys=True).encode()

    try:
        public_key.verify(signature, claims_bytes)
    except Exception:
        audit.write_log(
            event="attestation_bundle_rejected",
            agent_id=agent_id,
            channel=claims.get("channel", "unknown"),
            result="INVALID",
            message_id=bundle_id,
        )
        raise ValueError(
            f"Attestation bundle signature invalid: bundle_id {bundle_id}"
        )

    audit.write_log(
        event="attestation_bundle_verified",
        agent_id=agent_id,
        channel=claims.get("channel", "unknown"),
        result="VALID",
        message_id=bundle_id,
    )

    return claims


if __name__ == "__main__":
    print("--- RealAgentID Attestation Bundle Test ---")

    bundle = build_attestation_bundle(
        agent_id="coordinator",
        private_key_path="./keys/coordinator_private.pem",
        action="analyze_dataset",
        channel="tasks:worker-1",
        payload={"target": "dataset-7"},
        agent_script_path="./core/signing.py",
        ttl_seconds=300,
        permissions=["read", "analyze"],
    )

    print("Bundle created:")
    parsed = json.loads(bundle)
    print(f"  bundle_id:   {parsed['claims']['bundle_id']}")
    print(f"  agent_id:    {parsed['claims']['agent_id']}")
    print(f"  code_hash:   {parsed['claims']['code_hash'][:16]}...")
    print(f"  sbom_hash:   {parsed['claims']['sbom_hash']}")
    print(f"  expires_at:  {parsed['claims']['expires_at']}")

    print("\nVerifying bundle...")
    verified = verify_attestation_bundle(bundle)
    print(f"  [+] Bundle VALID - agent: {verified['agent_id']}")
    print(f"  [+] Action: {verified['action']}")
    print(f"  [+] Role: {verified['agent_role']}")
