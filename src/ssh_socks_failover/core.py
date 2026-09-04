"""Configuration, health checks, state handling, and failover decisions."""

from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import re
import socket
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Sequence


class ConfigError(ValueError):
    """Raised when configuration is missing or unsafe."""


@dataclass(frozen=True)
class Node:
    name: str
    host: str
    user: str
    ssh_port: int
    identity_file: Path
    known_hosts_file: Path
    expected_egress_ip: str


@dataclass(frozen=True)
class Config:
    nodes: tuple[Node, ...]
    socks_host: str
    socks_port: int
    health_url: str
    tunnel_service: str
    state_dir: Path
    failure_threshold: int
    switch_cooldown_seconds: int
    settle_seconds: float
    connect_timeout_seconds: int
    command_timeout_seconds: int

    @property
    def state_file(self) -> Path:
        return self.state_dir / "state.json"

    @property
    def lock_file(self) -> Path:
        return self.state_dir / "manager.lock"


def _expand(value: object) -> object:
    if isinstance(value, str):
        expanded = os.path.expanduser(os.path.expandvars(value))
        if re.search(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", expanded):
            raise ConfigError(f"unresolved environment variable in {value!r}")
        return expanded
    if isinstance(value, list):
        return [_expand(item) for item in value]
    if isinstance(value, dict):
        return {key: _expand(item) for key, item in value.items()}
    return value


def _port(value: object, field: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field} must be an integer") from exc
    if not 1 <= parsed <= 65535:
        raise ConfigError(f"{field} must be between 1 and 65535")
    return parsed


def _positive_int(value: object, field: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field} must be an integer") from exc
    if parsed < 1:
        raise ConfigError(f"{field} must be at least 1")
    return parsed


def _safe_token(value: object, field: str) -> str:
    text = str(value or "")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", text):
        raise ConfigError(f"{field} contains unsupported characters")
    return text


def _host(value: object) -> str:
    text = str(value or "")
    if not text or text.startswith("-") or any(char.isspace() for char in text):
        raise ConfigError("node host is missing or unsafe")
    try:
        ipaddress.ip_address(text)
    except ValueError:
        if len(text) > 253 or not re.fullmatch(r"[A-Za-z0-9.-]+", text):
            raise ConfigError("node host is not an IP address or DNS name")
    return text


def load_config(path: Path) -> Config:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot load config: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("configuration root must be an object")
    raw = _expand(raw)
    assert isinstance(raw, dict)
    if raw.get("version") != 1:
        raise ConfigError("version must be 1")
    nodes_raw = raw.get("nodes")
    if not isinstance(nodes_raw, list) or len(nodes_raw) < 2:
        raise ConfigError("nodes must contain at least two entries")
    nodes: list[Node] = []
    names: set[str] = set()
    for index, item in enumerate(nodes_raw):
        if not isinstance(item, dict):
            raise ConfigError(f"nodes[{index}] must be an object")
        name = _safe_token(item.get("name"), f"nodes[{index}].name")
        if name in names:
            raise ConfigError(f"duplicate node name: {name}")
        names.add(name)
        expected = str(item.get("expected_egress_ip") or "")
        try:
            ipaddress.ip_address(expected)
        except ValueError as exc:
            raise ConfigError(f"nodes[{index}].expected_egress_ip must be an IP address") from exc
        nodes.append(Node(
            name=name,
            host=_host(item.get("host")),
            user=_safe_token(item.get("user"), f"nodes[{index}].user"),
            ssh_port=_port(item.get("ssh_port", 22), f"nodes[{index}].ssh_port"),
            identity_file=Path(str(item.get("identity_file") or "")),
            known_hosts_file=Path(str(item.get("known_hosts_file") or "")),
            expected_egress_ip=expected,
        ))
    local = raw.get("local", {})
    policy = raw.get("policy", {})
    if not isinstance(local, dict) or not isinstance(policy, dict):
        raise ConfigError("local and policy must be objects")
    socks_host = str(local.get("socks_host", "127.0.0.1"))
    if not ipaddress.ip_address(socks_host).is_loopback:
        raise ConfigError("local.socks_host must be a loopback address")
    health_url = str(raw.get("health_url", ""))
    if not health_url.startswith("https://"):
        raise ConfigError("health_url must use HTTPS")
    service = str(raw.get("tunnel_service", ""))
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", service):
        raise ConfigError("tunnel_service must be a simple .service unit name")
    state_dir = Path(str(raw.get("state_dir") or ""))
    if not state_dir.is_absolute():
        raise ConfigError("state_dir must be absolute after expansion")
    for node in nodes:
        if not node.identity_file.is_absolute() or not node.known_hosts_file.is_absolute():
            raise ConfigError("identity_file and known_hosts_file must be absolute after expansion")
    return Config(
        nodes=tuple(nodes),
        socks_host=socks_host,
        socks_port=_port(local.get("socks_port", 1080), "local.socks_port"),
        health_url=health_url,
        tunnel_service=service,
        state_dir=state_dir,
        failure_threshold=_positive_int(policy.get("failure_threshold", 3), "policy.failure_threshold"),
        switch_cooldown_seconds=_positive_int(policy.get("switch_cooldown_seconds", 900), "policy.switch_cooldown_seconds"),
        settle_seconds=float(policy.get("settle_seconds", 3)),
        connect_timeout_seconds=_positive_int(policy.get("connect_timeout_seconds", 8), "policy.connect_timeout_seconds"),
        command_timeout_seconds=_positive_int(policy.get("command_timeout_seconds", 20), "policy.command_timeout_seconds"),
    )


def run(argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(list(argv), text=True, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(list(argv), 124, "", type(exc).__name__)


def atomic_write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def read_state(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("another manager operation is active") from exc
        yield


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def current_node(config: Config, state: dict[str, object]) -> Node:
    selected = state.get("active_node")
    return next((node for node in config.nodes if node.name == selected), config.nodes[0])


def next_nodes(config: Config, current: Node) -> tuple[Node, ...]:
    index = config.nodes.index(current)
    return tuple(config.nodes[(index + offset) % len(config.nodes)] for offset in range(1, len(config.nodes)))


def ssh_command(config: Config, node: Node, *, tunnel: bool) -> list[str]:
    command = [
        "ssh", "-p", str(node.ssh_port), "-i", str(node.identity_file),
        "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={node.known_hosts_file}",
        "-o", f"ConnectTimeout={config.connect_timeout_seconds}",
        "-o", "ConnectionAttempts=1", "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
    ]
    if tunnel:
        command.extend(["-N", "-D", f"{config.socks_host}:{config.socks_port}"])
    command.append(f"{node.user}@{node.host}")
    if not tunnel:
        command.append("true")
    return command


def node_reachable(config: Config, node: Node) -> bool:
    return run(ssh_command(config, node, tunnel=False), config.command_timeout_seconds).returncode == 0


def tunnel_health(config: Config, node: Node, *, check_service: bool = True) -> tuple[bool, dict[str, bool]]:
    service = True
    if check_service:
        service = run(
            ["systemctl", "--user", "is-active", "--quiet", config.tunnel_service], 5
        ).returncode == 0
    listener = False
    try:
        with socket.create_connection((config.socks_host, config.socks_port), timeout=3):
            listener = True
    except OSError:
        pass
    result = run([
        "curl", "-4", "-fsS", "--connect-timeout", str(config.connect_timeout_seconds),
        "--max-time", str(config.command_timeout_seconds), "--socks5-hostname",
        f"{config.socks_host}:{config.socks_port}", config.health_url,
    ], config.command_timeout_seconds + 2)
    egress = result.returncode == 0 and result.stdout.strip() == node.expected_egress_ip
    checks = {"service": service, "listener": listener, "egress": egress}
    return all(checks.values()), checks


def restart_service(config: Config) -> bool:
    return run(["systemctl", "--user", "restart", config.tunnel_service], 45).returncode == 0


def switch_to(config: Config, state: dict[str, object], target: Node, reason: str) -> tuple[bool, dict[str, bool]]:
    previous = current_node(config, state)
    state["active_node"] = target.name
    state["switch_reason"] = reason
    state["updated_at"] = utc_now()
    atomic_write_json(config.state_file, state)
    restarted = restart_service(config)
    if restarted:
        time.sleep(config.settle_seconds)
        healthy, checks = tunnel_health(config, target)
    else:
        healthy, checks = False, {"service": False, "listener": False, "egress": False}
    if healthy:
        state.update({"failures": 0, "last_switch_at": int(time.time()), "healthy": True, "checks": checks})
        atomic_write_json(config.state_file, state)
        return True, checks
    state["active_node"] = previous.name
    state["healthy"] = False
    state["checks"] = checks
    atomic_write_json(config.state_file, state)
    if previous.name != target.name:
        restart_service(config)
    return False, checks
