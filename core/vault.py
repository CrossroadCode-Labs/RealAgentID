import json
import time
import os
import base64
from core.connection import get_redis, AGENT_TTL
from core.lineage import get_lineage, verify_lineage

r = get_redis()

# Try to import post-quantum and crypto libraries
try:
    from oqs import KeyEncapsulation
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False
    print("[vault] Warning: liboqs not available. "
          "Falling back to classical encryption.")

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[vault] Warning: cryptography library not available.")


def seal(
    agent_id: str,
    asset_id: str,
    plaintext: bytes,
    sensitivity: str = "restricted"
) -> dict:
    """
    Encrypt and store an asset in the vault.
    Binds decryption capability to agent identity
    and lineage. TTL-bound — expires with agent session.
    Returns vault entry metadata.
    """
    if not CRYPTO_AVAILABLE:
        return {"status": "error", "reason": "crypto_unavailable"}

    # Verify agent lineage before sealing
    if not verify_lineage(agent_id):
        return {"status": "denied", "reason": "lineage_invalid"}

    try:
        vault_id = f"vault:{asset_id}:{agent_id}"
        timestamp = int(time.time())

        if PQC_AVAILABLE:
            # Post-quantum key encapsulation with Kyber
            kem = KeyEncapsulation("Kyber512")
            public_key = kem.generate_keypair()
            ciphertext_kem, shared_secret = \
                kem.encap_secret(public_key)

            # Store private key bound to agent TTL
            r.setex(
                f"vault_key:{vault_id}",
                AGENT_TTL,
                base64.b64encode(
                    kem.export_secret_key()
                ).decode()
            )
            kem_ciphertext_b64 = base64.b64encode(
                ciphertext_kem
            ).decode()
            algorithm = "Kyber512+AES-256-GCM"

        else:
            # Classical fallback — AES-256-GCM with random key
            shared_secret = os.urandom(32)
            r.setex(
                f"vault_key:{vault_id}",
                AGENT_TTL,
                base64.b64encode(shared_secret).decode()
            )
            kem_ciphertext_b64 = None
            algorithm = "AES-256-GCM"

        # Derive AES key from shared secret using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"vault_encryption",
            backend=default_backend()
        )
        aes_key = hkdf.derive(shared_secret)

        # Encrypt with AES-256-GCM
        nonce = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # Store vault entry
        entry = {
            "vault_id": vault_id,
            "asset_id": asset_id,
            "agent_id": agent_id,
            "sensitivity": sensitivity,
            "algorithm": algorithm,
            "kem_ciphertext": kem_ciphertext_b64,
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(
                ciphertext
            ).decode(),
            "sealed_at": timestamp,
        }

        r.setex(
            vault_id,
            AGENT_TTL,
            json.dumps(entry)
        )

        print(f"[vault] Sealed '{asset_id}' "
              f"for agent '{agent_id}' "
              f"using {algorithm}")

        return {
            "status": "sealed",
            "vault_id": vault_id,
            "algorithm": algorithm,
            "expires_in": AGENT_TTL
        }

    except Exception as e:
        print(f"[vault] Seal failed: {e}")
        return {"status": "error", "reason": str(e)}


def unseal(
    agent_id: str,
    asset_id: str
) -> bytes:
    """
    Decrypt and return a vaulted asset.
    Agent must have valid lineage and the vault
    key must not have expired.
    Returns plaintext bytes or None if denied.
    """
    if not CRYPTO_AVAILABLE:
        return None

    # Verify lineage before unsealing
    if not verify_lineage(agent_id):
        print(f"[vault] Unseal denied — "
              f"lineage invalid for '{agent_id}'")
        return None

    vault_id = f"vault:{asset_id}:{agent_id}"

    try:
        # Get vault entry
        entry_data = r.get(vault_id)
        if entry_data is None:
            print(f"[vault] Asset '{asset_id}' "
                  f"not found or expired.")
            return None

        entry = json.loads(entry_data)

        # Get vault key
        key_data = r.get(f"vault_key:{vault_id}")
        if key_data is None:
            print(f"[vault] Vault key expired "
                  f"for '{asset_id}'. Re-verification required.")
            return None

        raw_key = base64.b64decode(key_data.encode())

        if PQC_AVAILABLE and \
                entry["algorithm"] == "Kyber512+AES-256-GCM":
            # Post-quantum decapsulation
            kem = KeyEncapsulation("Kyber512")
            kem.import_secret_key(raw_key)
            kem_ciphertext = base64.b64decode(
                entry["kem_ciphertext"]
            )
            shared_secret = kem.decap_secret(kem_ciphertext)
        else:
            shared_secret = raw_key

        # Derive AES key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"vault_encryption",
            backend=default_backend()
        )
        aes_key = hkdf.derive(shared_secret)

        # Decrypt
        nonce = base64.b64decode(entry["nonce"])
        ciphertext = base64.b64decode(entry["ciphertext"])
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        print(f"[vault] Unsealed '{asset_id}' "
              f"for agent '{agent_id}'")
        return plaintext

    except Exception as e:
        print(f"[vault] Unseal failed: {e}")
        return None


def revoke_vault(agent_id: str, asset_id: str) -> bool:
    """
    Explicitly revoke a vault entry and its key.
    Data becomes permanently unreadable.
    """
    vault_id = f"vault:{asset_id}:{agent_id}"
    key_deleted = r.delete(f"vault_key:{vault_id}")
    entry_deleted = r.delete(vault_id)

    if key_deleted or entry_deleted:
        print(f"[vault] Revoked '{asset_id}' "
              f"for agent '{agent_id}'. "
              f"Data permanently unreadable.")
        return True
    return False


def list_vault(agent_id: str) -> list:
    """
    List all vault entries for an agent.
    """
    keys = r.keys(f"vault:*:{agent_id}")
    entries = []
    for key in keys:
        data = r.get(key)
        if data:
            entry = json.loads(data)
            entries.append({
                "vault_id": entry["vault_id"],
                "asset_id": entry["asset_id"],
                "algorithm": entry["algorithm"],
                "sensitivity": entry["sensitivity"],
                "sealed_at": entry["sealed_at"]
            })
    return entries


if __name__ == "__main__":
    print(f"Vault module loaded. "
          f"PQC available: {PQC_AVAILABLE}")
