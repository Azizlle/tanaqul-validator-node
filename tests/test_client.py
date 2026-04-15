"""Tests for src/client.py — request body shapes (no real network)."""
from unittest.mock import patch, MagicMock
import os

# Inject env BEFORE importing config
os.environ.setdefault("TANAQUL_VALIDATOR_ID", "test-id")
os.environ.setdefault("TANAQUL_API_KEY", "test-key")
os.environ.setdefault("TANAQUL_BACKEND_URL", "https://example.test")

from src import client  # noqa: E402


def test_heartbeat_body_shape():
    fake_resp = MagicMock(status_code=200, json=lambda: {"status": "ok"})
    with patch.object(client._S, "post", return_value=fake_resp) as m:
        client.heartbeat(block_height=42, peer_count=0, uptime_seconds=99)
        url, kwargs = m.call_args[0][0], m.call_args[1]
        assert url.endswith("/api/v1/validators/heartbeat")
        body = kwargs["json"]
        assert body["block_height"] == 42
        assert body["uptime_seconds"] == 99
        assert body["api_key"] == "test-key"
        assert body["validator_id"] == "test-id"


def test_sign_block_idempotent_on_already_signed():
    fake_resp = MagicMock(status_code=400, text="Already signed this block")
    with patch.object(client._S, "post", return_value=fake_resp):
        out = client.sign_block(block_number=7, signature_hex="abcd" * 32)
        assert out["already_signed"] is True


def test_auth_failure_raises():
    fake_resp = MagicMock(status_code=401, text="Invalid API key")
    with patch.object(client._S, "post", return_value=fake_resp):
        try:
            client.heartbeat(0, 0, 0)
        except client.BackendError as e:
            assert "auth_failed" in str(e)
        else:
            raise AssertionError("expected BackendError")
