from __future__ import annotations

import argparse
import logging
import signal
import time
import sys
import os
import ctypes
import shutil
import platform
import subprocess
import socket
from dataclasses import dataclass
from typing import Any

from agent.collectors import discover_collectors, run_collectors
from agent.config import AgentConfig, ConfigError
from agent.crypto import AESGCMCrypto, HPKECrypto, create_agent_crypto
from agent.payload_builder import build_payload
from agent.queue import LocalEncryptedQueue
from agent.transport import TelemetryTransport
from shared.protocol import encrypted_payload_headers

log = logging.getLogger("insiedr.agent")


@dataclass
class AgentRunSummary:
    payload_id: str
    collectors_total: int
    collectors_success: int
    collectors_failed: int
    queued: bool
    queue_retry: dict[str, int]
    sent: bool


class EndpointAgent:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.queue = LocalEncryptedQueue(config.queue_dir)
        self.crypto = create_agent_crypto(config)
        self.collectors = discover_collectors(config.enabled_collectors, hostname=config.hostname)
        self.transport = TelemetryTransport(
            server_url=config.server_url,
            queue=self.queue,
            timeout_seconds=config.request_timeout_seconds,
            verify_tls=config.verify_tls,
            agent_token=config.agent_token,
        )
        self._stopping = False

    def run_once(self) -> AgentRunSummary:
        retry_summary = self.transport.retry_queued(limit=self.config.queue_retry_limit)
        results = run_collectors(self.collectors)
        payload = build_payload(
            agent_id=self.config.agent_id,
            hostname=self.config.hostname,
            username=self.config.username,
            collector_results=results,
        )
        envelope = self.crypto.encrypt_payload(payload)
        envelope["payload_id"] = payload["payload_id"]
        headers = encrypted_payload_headers(envelope, self.config.agent_id, payload["payload_id"])
        send_result = self.transport.send_or_queue(envelope, headers)
        summary = AgentRunSummary(
            payload_id=payload["payload_id"],
            collectors_total=payload["summary"]["collector_count"],
            collectors_success=payload["summary"]["success_count"],
            collectors_failed=payload["summary"]["failed_count"],
            queued=send_result.queued,
            queue_retry=retry_summary,
            sent=send_result.ok,
        )
        log.info(
            "cycle complete payload=%s collectors=%s/%s queued=%s retry_sent=%s",
            summary.payload_id,
            summary.collectors_success,
            summary.collectors_total,
            summary.queued,
            retry_summary["sent"],
        )
        return summary

    def stop(self, *_args: Any) -> None:
        self._stopping = True

    def run_forever(self) -> None:
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)
        log.info("agent started with %d collector(s)", len(self.collectors))
        while not self._stopping:
            started = time.monotonic()
            try:
                self.run_once()
            except Exception:
                log.exception("agent cycle failed")
            elapsed = time.monotonic() - started
            sleep_for = max(1.0, self.config.interval_seconds - elapsed)
            end = time.monotonic() + sleep_for
            while not self._stopping and time.monotonic() < end:
                time.sleep(min(1.0, end - time.monotonic()))


def configure_logging(level: str) -> None:
    appdata_dir = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "InsiEDR")
    log_file = os.path.join(appdata_dir, "logs", "agent.log")
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    # We configure a file handler and a stream handler
    handlers = [
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers
    )

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="InsiEDR endpoint feature collection agent")
    parser.add_argument("--once", action="store_true", help="run one collection/send cycle and exit")
    return parser.parse_args()


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def show_msg(title, text, style=0):
    try:
        ctypes.windll.user32.MessageBoxW(0, text, title, style)
    except Exception:
        pass

def write_configs(target_dir):
    os.makedirs(target_dir, exist_ok=True)
    os.makedirs(os.path.join(target_dir, "logs"), exist_ok=True)
    os.makedirs(os.path.join(target_dir, "agent_queue"), exist_ok=True)
    
    hostname = socket.gethostname()
    agent_id = f"SASTRA-{hostname}"
    server_url = "http://172.16.22.198/api/logs"
    aes_key = "e548bcb6e1e7da40ccac2adeba65f34554458de520e9a0780f3a5f04f01a72d7"
    
    env_content = f"""INSIEDR_AGENT_SERVER={server_url}
INSIEDR_ALLOW_INSECURE_HTTP=true
INSIEDR_REQUIRE_HTTPS=false
INSIEDR_DISABLE_TLS_VERIFY=true
INSIEDR_AES_KEY={aes_key}
INSIEDR_AGENT_MODE=production
INSIEDR_AGENT_ID={agent_id}
INSIEDR_ENABLED_COLLECTORS=logon,file,device,http,process,keystroke-collector
INSIEDR_COLLECTION_INTERVAL_SECONDS=3
INSIEDR_MAX_QUEUE_ITEMS=1000
INSIEDR_MAX_QUEUE_BYTES=104857600
INSIEDR_MAX_QUEUE_AGE_DAYS=30
INSIEDR_REPLAY_WINDOW_HOURS=720
INSIEDR_ASSUME_UTC_TIMESTAMPS=true
INSIEDR_STORE_PLAINTEXT_PAYLOADS=true
INSIEDR_LOG_LEVEL=INFO
INSIEDR_QUEUE_DIR={os.path.join(target_dir, "agent_queue")}
"""
    env_path = os.path.join(target_dir, ".env")
    if not os.path.exists(env_path):
        with open(env_path, "w", encoding="ascii") as f:
            f.write(env_content)
            
    ini_content = f"""[agent]
server_url = {server_url}
aes_key = {aes_key}
agent_id = {agent_id}
mode = production
allow_insecure_http = true
require_https = false
collection_interval_seconds = 10
enabled_collectors = logon,file,device,http,process,keystroke-collector
allow_synthetic_collector_data = false
max_queue_items = 1000
max_queue_bytes = 104857600
max_queue_age_days = 30
replay_window_hours = 720
assume_utc_timestamps = true
store_plaintext_payloads = true
"""
    ini_path = os.path.join(target_dir, "insiedr_agent.ini")
    if not os.path.exists(ini_path):
        with open(ini_path, "w", encoding="ascii") as f:
            f.write(ini_content)

    return env_path


def main() -> int:
    # --- USER MODE CONFIGURATION ---
    # Store config and queue in local appdata instead of requiring SYSTEM/Admin
    if platform.system() == "Windows":
        # Prompt for Administrator privileges to read Security/USB Event Logs
        if not is_admin():
            current_exe = sys.executable
            if getattr(sys, 'frozen', False):
                res = ctypes.windll.shell32.ShellExecuteW(None, "runas", current_exe, " ".join(sys.argv[1:]), None, 0)
                if res <= 32:
                    show_msg("InsiEDR Agent", "Administrator privileges are required to run collectors. Please click 'Yes' on the security prompt.", 16)
                sys.exit(0)

        appdata_dir = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "InsiEDR")

        env_path = write_configs(appdata_dir)
        
        if env_path and os.path.exists(env_path):
            try:
                import dotenv
                dotenv.load_dotenv(env_path)
            except ImportError:
                pass
    
    args = parse_args()
    try:
        config = AgentConfig.from_env()
    except ConfigError as exc:
        configure_logging("ERROR")
        log.error("configuration error: %s", exc)
        return 2

    configure_logging(config.log_level)
    log.info("configuration loaded: %s", config.safe_summary())
    agent = EndpointAgent(config)
    if args.once or config.run_once:
        agent.run_once()
        return 0
    agent.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

