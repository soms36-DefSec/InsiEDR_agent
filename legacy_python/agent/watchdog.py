"""
agent/watchdog.py — InsiEDR Agent Tamper Watchdog

Runs as a SEPARATE CHILD PROCESS launched by the main agent.

How it works:
1. Agent starts -> spawns this watchdog with args: parent_pid heartbeat_file clean_exit_file server_url aes_key_b64 agent_id hostname username [agent_token]
2. Watchdog polls every 5s:
   a. If clean_exit_file exists -> graceful shutdown -> exit silently.
   b. If parent PID is dead AND clean_exit_file does NOT exist -> TAMPER -> POST payload.
3. Survives TerminateProcess() (Task Manager) because it is a completely separate OS process.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

_LOG_DIR = Path(os.getenv("PROGRAMDATA", r"C:\ProgramData")) / "InsiEDR" / "logs"
_LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s watchdog: %(message)s",
    handlers=[
        logging.FileHandler(_LOG_DIR / "watchdog.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("insiedr.watchdog")

POLL_INTERVAL_SECONDS = 5


def _is_pid_alive(pid: int) -> bool:
    try:
        import psutil
        return psutil.pid_exists(pid)
    except ImportError:
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False


def _fire_tamper_payload(
    server_url: str,
    aes_key_b64: str,
    agent_id: str,
    hostname: str,
    username: str,
    agent_token: str | None,
) -> None:
    log.warning("Tamper detected! Parent agent was forcefully killed. Firing tamper payload.")
    try:
        import requests
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import secrets as _secrets

        aes_key = base64.b64decode(aes_key_b64)
        payload_id = str(uuid.uuid4())
        collected_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        raw_payload = {
            "payload_id": payload_id,
            "agent_id": agent_id,
            "hostname": hostname,
            "username": username,
            "collected_at": collected_at,
            "schema_version": "1.0",
            "summary": {"collector_count": 1, "success_count": 1, "failed_count": 0},
            "collectors": [{
                "collector": "agent-lifecycle",
                "collected_at": collected_at,
                "hostname": hostname,
                "status": "success",
                "quality": "exact",
                "payload": {
                    "manual_agent_stop_flag": 1,
                    "agent_status": "killed_by_task_manager",
                },
                "feature_quality": {
                    "manual_agent_stop_flag": "exact",
                    "agent_status": "exact",
                },
            }],
        }

        scheme = os.environ.get("INSIEDR_CRYPTO_SCHEME", "").lower()
        pub_key = os.environ.get("INSIEDR_SERVER_PUBLIC_KEY")
        if scheme == "hpke" or (pub_key and not aes_key_b64):
            from agent.crypto.hpke import HPKECrypto
            server_key_id = os.environ.get("INSIEDR_SERVER_KEY_ID", "default")
            crypto = HPKECrypto(pub_key or aes_key_b64, key_id=server_key_id)
            envelope = crypto.encrypt_payload(raw_payload)
            headers = {
                "Content-Type": "application/json",
                "X-Crypto-Scheme": "hpke",
                "X-Protocol-Version": "2.0",
                "X-Agent-ID": agent_id,
                "X-Payload-ID": payload_id,
                "X-Key-ID": server_key_id,
            }
        else:
            plaintext = json.dumps(raw_payload).encode("utf-8")
            nonce = _secrets.token_bytes(12)
            aesgcm = AESGCM(aes_key)
            ct_with_tag = aesgcm.encrypt(nonce, plaintext, None)
            ciphertext = ct_with_tag[:-16]
            tag = ct_with_tag[-16:]

            envelope = {
                "payload_id": payload_id,
                "schema_version": "1.0",
                "scheme": "aes-256-gcm",
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "tag": base64.b64encode(tag).decode(),
            }

            headers = {
                "Content-Type": "application/json",
                "X-Crypto-Scheme": "aes-256-gcm",
                "X-Protocol-Version": "2.0",
                "X-Agent-ID": agent_id,
                "X-Payload-ID": payload_id,
            }
        if agent_token:
            headers["X-Agent-Token"] = agent_token

        # Determine TLS verification — match agent behaviour for local HTTP dev
        from urllib.parse import urlparse as _urlparse
        _parsed = _urlparse(server_url)
        verify = _parsed.scheme == "https"

        resp = requests.post(server_url, json=envelope, headers=headers, timeout=5, verify=verify)
        log.info("Tamper payload sent. Server: %s", resp.status_code)
    except Exception as exc:
        log.error("Failed to send tamper payload: %s", exc)


def _watchdog_loop(
    parent_pid: int,
    heartbeat_file: Path,
    clean_exit_file: Path,
    server_url: str,
    aes_key_b64: str,
    agent_id: str,
    hostname: str,
    username: str,
    agent_token: str | None,
) -> None:
    log.info("Watchdog started. Monitoring PID=%d", parent_pid)
    while True:
        time.sleep(POLL_INTERVAL_SECONDS)

        # Graceful shutdown path
        if clean_exit_file.exists():
            log.info("Clean exit marker found. Watchdog exiting normally.")
            return

        # Parent still alive
        if _is_pid_alive(parent_pid):
            continue

        # Race-condition guard: wait briefly then re-check
        time.sleep(1)
        if clean_exit_file.exists():
            log.info("Clean exit marker found (race-check). Watchdog exiting normally.")
            return

        # TAMPER: parent dead, no clean exit marker
        _fire_tamper_payload(
            server_url=server_url,
            aes_key_b64=aes_key_b64,
            agent_id=agent_id,
            hostname=hostname,
            username=username,
            agent_token=agent_token,
        )
        log.info("Watchdog done. Exiting.")
        return


def main() -> int:
    if len(sys.argv) < 9:
        print(
            "Usage: watchdog.py <parent_pid> <heartbeat_file> <clean_exit_file> "
            "<server_url> <aes_key_b64> <agent_id> <hostname> <username> [agent_token]",
            file=sys.stderr,
        )
        return 1

    parent_pid      = int(sys.argv[1])
    heartbeat_file  = Path(sys.argv[2])
    clean_exit_file = Path(sys.argv[3])
    server_url      = sys.argv[4]
    aes_key_b64     = sys.argv[5]
    agent_id        = sys.argv[6]
    hostname        = sys.argv[7]
    username        = sys.argv[8]
    agent_token     = sys.argv[9] if len(sys.argv) > 9 and sys.argv[9] != "NONE" else None

    _watchdog_loop(
        parent_pid=parent_pid,
        heartbeat_file=heartbeat_file,
        clean_exit_file=clean_exit_file,
        server_url=server_url,
        aes_key_b64=aes_key_b64,
        agent_id=agent_id,
        hostname=hostname,
        username=username,
        agent_token=agent_token,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
