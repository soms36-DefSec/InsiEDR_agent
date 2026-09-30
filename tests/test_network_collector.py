from __future__ import annotations

import socket
from collections import namedtuple
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from agent.collectors.network_monitor import (
    NetworkMonitor,
    get_process_name,
    is_after_hours,
    is_external_ip,
)


def test_is_external_ip_classification():
    # Internal / Private / Loopback IPs -> False
    assert is_external_ip("127.0.0.1") is False
    assert is_external_ip("::1") is False
    assert is_external_ip("192.168.1.50") is False
    assert is_external_ip("10.0.0.1") is False
    assert is_external_ip("172.16.0.1") is False
    assert is_external_ip("169.254.1.1") is False  # Link local
    assert is_external_ip("224.0.0.1") is False    # Multicast

    # Public Internet IPs -> True
    assert is_external_ip("8.8.8.8") is True
    assert is_external_ip("1.1.1.1") is True
    assert is_external_ip("142.250.190.46") is True

    # Invalid string -> False
    assert is_external_ip("invalid-ip") is False
    assert is_external_ip("") is False


def test_is_after_hours():
    # Wednesday at 14:00 (work hours) -> False
    work_time = datetime(2026, 9, 23, 14, 0, 0)
    assert is_after_hours(work_time) is False

    # Wednesday at 22:00 (after hours) -> True
    night_time = datetime(2026, 9, 23, 22, 0, 0)
    assert is_after_hours(night_time) is True

    # Saturday at 12:00 (weekend) -> True
    weekend_time = datetime(2026, 9, 26, 12, 0, 0)
    assert is_after_hours(weekend_time) is True


def test_network_monitor_feature_extraction():
    monitor = NetworkMonitor()

    # Mock connection objects
    MockAddr = namedtuple("MockAddr", ["ip", "port"])
    MockConn = namedtuple("MockConn", ["laddr", "raddr", "type", "status", "pid"])

    mock_conns = [
        # TCP connection to external Google DNS
        MockConn(
            laddr=MockAddr("192.168.1.100", 50000),
            raddr=MockAddr("8.8.8.8", 443),
            type=socket.SOCK_STREAM,
            status="ESTABLISHED",
            pid=1234,
        ),
        # TCP connection to internal file server
        MockConn(
            laddr=MockAddr("192.168.1.100", 50001),
            raddr=MockAddr("192.168.1.200", 445),
            type=socket.SOCK_STREAM,
            status="ESTABLISHED",
            pid=1234,
        ),
        # UDP connection to external DNS
        MockConn(
            laddr=MockAddr("192.168.1.100", 50002),
            raddr=MockAddr("1.1.1.1", 53),
            type=socket.SOCK_DGRAM,
            status="NONE",
            pid=5678,
        ),
        # Listening TCP socket (no remote address)
        MockConn(
            laddr=MockAddr("0.0.0.0", 8080),
            raddr=None,
            type=socket.SOCK_STREAM,
            status="LISTEN",
            pid=9999,
        ),
    ]

    with patch.object(monitor, "_safe_net_connections", return_value=mock_conns), \
         patch("agent.collectors.network_monitor.get_process_name", side_effect=lambda pid: f"proc_{pid}.exe"):

        events, features = monitor._extract_connections_and_features(mock_conns, "2026-09-22T10:00:00Z")

        # 3 connections with remote addresses
        assert len(events) == 3
        assert features["network_connection_count"] == 3
        assert features["external_connection_count"] == 2  # 8.8.8.8 and 1.1.1.1
        assert features["unique_destination_ips"] == 3
        assert features["unique_external_ips"] == 2
        assert features["unique_destination_ports"] == 3
        assert features["tcp_connection_count"] == 3
        assert features["udp_connection_count"] == 1

        # Check event 5-tuple structure
        first_event = events[0]
        assert first_event["src_ip"] == "192.168.1.100"
        assert first_event["src_port"] == 50000
        assert first_event["dst_ip"] == "8.8.8.8"
        assert first_event["dst_port"] == 443
        assert first_event["protocol"] == "TCP"
        assert first_event["state"] == "ESTABLISHED"
        assert first_event["pid"] == 1234
        assert first_event["process"] == "proc_1234.exe"
        assert first_event["external"] is True


def test_network_monitor_full_collect_success():
    monitor = NetworkMonitor()
    result = monitor.collect()

    assert result.status == "success"
    payload = result.payload
    assert "network_connection_count" in payload
    assert "external_connection_count" in payload
    assert "unique_destination_ips" in payload
    assert "network_connections" in payload
    assert isinstance(payload["network_connections"], list)
    assert "network_bytes_sent" in payload
    assert "network_bytes_recv" in payload
