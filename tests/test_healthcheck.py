"""Tests for src/healthcheck.py — health gating logic."""
import time
from src import healthcheck


def test_initial_health_is_grace_period():
    # Reset state
    healthcheck._LAST_OK_HEARTBEAT = 0.0
    healthcheck._START_TS = time.time()
    assert healthcheck._is_healthy() is True  # grace period


def test_record_heartbeat_makes_healthy():
    healthcheck._LAST_OK_HEARTBEAT = 0.0
    healthcheck._START_TS = time.time() - 120  # past grace
    assert healthcheck._is_healthy() is False
    healthcheck.record_heartbeat_ok()
    assert healthcheck._is_healthy() is True


def test_stale_heartbeat_marks_unhealthy():
    healthcheck._LAST_OK_HEARTBEAT = time.time() - 200  # 200s old
    healthcheck._START_TS = time.time() - 1000
    assert healthcheck._is_healthy() is False
