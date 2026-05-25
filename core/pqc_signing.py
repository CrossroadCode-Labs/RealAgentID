"""
RealAgentID Post-Quantum Signing Module
ML-DSA (NIST FIPS 204) — drop-in replacement for Ed25519
Quantum-resistant digital signatures for agent identity.
"""

import oqs
import json
import base64
import hashlib
import time
import uuid
import os

# NIST standardized — ML-DSA-65 is the recommended security level
# Equivalent to AES-192 / 3072-bit RSA in classical security
PQC_ALGORITHM = "ML-DSA-65"


def generate_pqc_keypair(agent_id: str, keys_dir: str = "./keys") -> dict:
    """Generate an ML-DSA-65 keypair for an agent."""
    os.makedirs(keys_dir, exist_ok=True)

    with oqs.Signature(PQC_ALGORITHM) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()

    pub_path = os.path.join(keys_dir, f"{agent_id}_pqc_public.key")
    sec_path = os.path.join(keys_dir, f"{agent_id}_pqc_secret.key")

    with open(pub_path, "wb") as f:
        f.write(public_key)
    with open(sec_path, "wb") as f:
        f.write(secret_key)

    print(f"[PQC] ML-DSA-65 keypair generated for agent: {agent_id}")
    print(f"  Public key: {pub_path} ({len(public_key)} bytes)")
    print(f"  Secret key: {sec_path} ({len(secret_key)} bytes)")

    return {"public_key_path": pub_path, "secret_key_path": sec_path}


def pqc_sign_message(
    agent_id: str,
    secret_key_path: str,
    channel: str,
    payload: dict
) -> str:
    """Sign a message using ML-DSA-65."""
    with open(secret_key_path, "rb") as f:
        secret_key = f.read()

    message = {
        "message_id": str(uuid.uuid4()),
        "agent_id": agent_id,
        "channel": channel,
        "payload": payload,
        "timestamp": time.time(),
        "algorithm": PQC_ALGORITHM,
    }

    message_bytes = json.dumps(message, sort_keys=True).encode()

    with oqs.Signature(PQC_ALGORITHM, secret_key=secret_key) as signer:
        signature = signer.sign(message_bytes)

    signature_b64 = base64.b64encode(signature).decode()
    signed = {"message": message, "signature": signature_b64}
    return json.dumps(signed)


def pqc_verify_message(signed_json: str, public_key_path: str) -> dict:
    """Verify an ML-DSA-65 signed message."""
    signed = json.loads(signed_json)
    message = signed["message"]
    signature = base64.b64decode(signed["signature"])

    with open(public_key_path, "rb") as f:
        public_key = f.read()

    message_bytes = json.dumps(message, sort_keys=True).encode()

    with oqs.Signature(PQC_ALGORITHM) as verifier:
        is_valid = verifier.verify(message_bytes, signature, public_key)

    if not is_valid:
        raise ValueError(f"[PQC] Signature INVALID - message rejected")

    return message


def get_public_key_hex(public_key_path: str) -> str:
    """Return public key as hex for registry storage."""
    with open(public_key_path, "rb") as f:
        return f.read().hex()


if __name__ == "__main__":
    print("--- RealAgentID PQC Signing Test ---")
    print(f"Algorithm: {PQC_ALGORITHM} (NIST FIPS 204)")
    print()

    # Generate keypair
    paths = generate_pqc_keypair("pqc_coordinator", "./keys")
    print()

    # Sign a message
    signed = pqc_sign_message(
        agent_id="pqc_coordinator",
        secret_key_path=paths["secret_key_path"],
        channel="tasks:worker-1",
        payload={"task": "analyze", "target": "dataset-7"}
    )
    print(f"[+] Message signed with ML-DSA-65")

    # Verify
    verified = pqc_verify_message(signed, paths["public_key_path"])
    print(f"[+] Signature VALID")
    print(f"  agent_id:  {verified['agent_id']}")
    print(f"  channel:   {verified['channel']}")
    print(f"  algorithm: {verified['algorithm']}")
    print()
    print("[+] RealAgentID is quantum-ready.")
