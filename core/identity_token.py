"""
RealAgentID Identity Token Module
Generates deterministic pseudonym tokens from agent credentials.
Raw credentials never travel the wire — only tokens are exposed during verification.
"""

import hashlib
import hmac
import os
import json
import time

TOKEN_VERSION = "v1"

def generate_token(public_key: bytes, agent_id: str) -> str:
    """
    Generate a deterministic pseudonym token from agent credentials.
    Same inputs always produce the same token — no raw credentials exposed.
    """
    salt = f"realagentid:{TOKEN_VERSION}:{agent_id}".encode()
    token = hmac.new(salt, public_key, hashlib.sha3_256).hexdigest()
    return f"rat_{TOKEN_VERSION}_{token}"

def verify_token(token: str, public_key: bytes, agent_id: str) -> bool:
    """
    Verify a token matches the expected credential pseudonym.
    Constant-time comparison prevents timing attacks.
    """
    expected = generate_token(public_key, agent_id)
    return hmac.compare_digest(token, expected)

def rotate_token(public_key: bytes, agent_id: str) -> str:
    """
    Rotate token — call after keypair rotation.
    Returns new token derived from updated credentials.
    """
    return generate_token(public_key, agent_id)
