"""Tests for src/client.py — request body shapes (no real network)."""
from unittest.mock import patch, MagicMock
import os

# Inject env BEFORE importing config
os.environ.setdefault("TANAQUL_VALIDATOR_ID", "ci")
os.environ.setdefault("TANAQUL_API_KEY", "ci")
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
        assert body["api_key"] == "ci"
        assert body["validator_id"] == "ci"


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


# ── the batch's new transport: 74 lines with no executed coverage ──────────
#
# ⛔ THE POLLING-LOOP TESTS MONKEYPATCH BOTH OF THESE WITH FAKES, so the real transport for
# the entire new channel was never executed. Four mutations survived the whole suite: a
# signed field dropped from the POSTed body, the auth headers removed, the int coercion
# removed, and — the compounding one — an HTTP error returning `{}` instead of raising.
#
# ⚠️ THAT LAST ONE IS WHY THIS FILE MATTERS. `_do_polling`'s "a fetch failure is not a
# disagreement" guard is well tested, but its PRECONDITION is that this module raises. With
# `{}` returned, `check_block({})` raises KeyError -> CONTENTS_MALFORMED -> the node files a
# SIGNED accusation because the platform returned a 503. Two halves of one guarantee living
# in two files, and only one of them was guarded.

def test_get_block_contents_AUTHENTICATES_and_coerces_the_block_number():
    fake = MagicMock(status_code=200, json=lambda: {"block_number": 7})
    with patch.object(client._S, "get", return_value=fake) as m:
        client.get_block_contents("7")
        url, kwargs = m.call_args[0][0], m.call_args[1]
        assert url.endswith("/api/v1/validators/blocks/7/contents"), url
        h = kwargs["headers"]
        assert h["X-Validator-Id"] == "ci" and h["X-Validator-Api-Key"] == "ci", (
            "the contents fetch went out unauthenticated")


def test_get_block_contents_does_not_build_a_URL_from_UNCOERCED_input():
    """⚠️ `int()` is not decoration: the block number is interpolated into a URL path."""
    fake = MagicMock(status_code=200, json=lambda: {})
    with patch.object(client._S, "get", return_value=fake) as m:
        try:
            client.get_block_contents("7/../../admin")
        except (ValueError, TypeError):
            return
        assert "admin" not in m.call_args[0][0], "an uncoerced path segment reached the URL"


import pytest  # noqa: E402


@pytest.mark.parametrize("status", [400, 403, 404, 500, 503])
def test_an_HTTP_ERROR_from_contents_RAISES_rather_than_returning_an_empty_dict(status):
    """⛔ THE COMPOUNDING ONE. An empty dict is not "no contents" — it is a payload the
    checker cannot read, which becomes a signed CONTENTS_MALFORMED accusation against a
    platform that merely returned a 503."""
    fake = MagicMock(status_code=status, text="boom")
    with patch.object(client._S, "get", return_value=fake):
        with pytest.raises(client.BackendError):
            client.get_block_contents(1)


def test_report_refusal_POSTS_EVERY_FIELD_THE_PRE_IMAGE_COMMITS():
    """⛔ THE ENDPOINT REBUILDS THE SIGNED STRING FROM THIS BODY. A field committed by the
    pre-image and missing from the body does not produce a wrong record — it produces NO
    record, rejected at the door, on the channel that exists because a refusal had nowhere
    to go. Derived from the pre-image's own signature, not from a list typed here."""
    import inspect
    from src import verify

    fake = MagicMock(status_code=200, json=lambda: {"recorded": True})
    committed = set(inspect.signature(verify.refusal_payload).parameters) - {
        "number", "validator_id", "verdict", "reported_at"}
    with patch.object(client._S, "post", return_value=fake) as m:
        client.report_refusal(
            block_number=1, verdict="HASH_MISMATCH", signature_hex="ab",
            reported_at="R", **{k: ("x" if "count" not in k else 1) for k in committed})
        body = m.call_args[1]["json"]

    missing = committed - set(body)
    assert not missing, f"the pre-image commits {sorted(missing)} and the body omits them"
    for k in ("validator_id", "api_key", "block_number", "verdict", "signature"):
        assert k in body, k


# ── round two: a network failure is a BackendError, not a process death ────

@pytest.mark.parametrize("exc_name", ["Timeout", "ReadTimeout", "ConnectTimeout",
                                      "ConnectionError", "RequestException"])
@pytest.mark.parametrize("call", ["get_block_contents", "report_refusal", "sign_block",
                                  "heartbeat"])
def test_a_NETWORK_failure_is_a_BackendError_and_not_a_crash(call, exc_name):
    """⛔ THE NODE DIED ON A NETWORK BLIP. `BackendError` is not a supertype of
    `requests.exceptions.Timeout` or `ConnectionError`, and `_do_polling` catches only
    `BackendError` — so a read timeout on ANY of the four calls escaped to `main()`, which
    has no handler, and the process exited. None of the failure counters ever fired for the
    commonest real failure there is.

    ⚠️ Every caller's careful reasoning — "a fetch failure is not a disagreement", "a
    submit that failed must be retried" — rests on this module raising something the loop
    catches."""
    import requests

    exc = getattr(requests.exceptions, exc_name)("network is down")
    kwargs = {
        "get_block_contents": dict(block_number=1),
        "report_refusal": dict(block_number=1, verdict="HASH_MISMATCH",
                               signature_hex="ab", reported_at="R"),
        "sign_block": dict(block_number=1, signature_hex="ab"),
        "heartbeat": dict(block_height=0, peer_count=0, uptime_seconds=0),
    }[call]
    verb = "get" if call == "get_block_contents" else "post"

    with patch.object(client._S, verb, side_effect=exc):
        with pytest.raises(client.BackendError) as caught:
            getattr(client, call)(**kwargs)
    assert exc_name.lower()[:7] in str(caught.value).lower() or "network" in str(caught.value)


def test_an_INDETERMINATE_WRITE_is_not_replayed_by_the_transport():
    """⛔ A TIMEOUT ON A WRITE IS INDETERMINATE, NOT A FAILURE. The session retried
    `POST` on read timeouts, so a submission that may already have been applied was
    blindly replayed up to three times below the application — where no caller can see it
    and no idempotency reasoning applies. Retrying a GET is free; retrying a write is a
    decision, and it belongs to the caller."""
    methods = client._S.adapters["https://"].max_retries.allowed_methods
    assert "POST" not in methods, (
        f"the transport replays POST ({sorted(methods)}); an indeterminate write is "
        f"repeated where nothing can observe it")
    assert "GET" in methods, "idempotent reads should still retry"
