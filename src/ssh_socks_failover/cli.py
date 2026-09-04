"""Command-line interface for SSH SOCKS5 tunnel failover."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Sequence

from .core import (
    ConfigError,
    atomic_write_json,
    current_node,
    exclusive_lock,
    load_config,
    next_nodes,
    node_reachable,
    read_state,
    restart_service,
    run,
    ssh_command,
    switch_to,
    tunnel_health,
    utc_now,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--config", type=Path, default=Path(os.environ.get("SSHF_CONFIG", "config.json")))
    sub = result.add_subparsers(dest="command", required=True)
    sub.add_parser("tunnel", help="run the selected node's SSH dynamic tunnel")
    sub.add_parser("check", help="perform one read-only tunnel health check")
    guard = sub.add_parser("guard", help="debounce failures and optionally switch nodes")
    guard.add_argument("--authorize-switch", action="store_true")
    rotate = sub.add_parser("rotate", help="select the next reachable node")
    rotate.add_argument("--authorize-switch", action="store_true")
    return result


def emit(value: dict[str, object]) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))


def check(config: object) -> int:
    state = read_state(config.state_file)
    node = current_node(config, state)
    healthy, checks = tunnel_health(config, node)
    emit({"ok": healthy, "active_node": node.name, "checks": checks, "checked_at": utc_now()})
    return 0 if healthy else 1


def guard(config: object, authorize: bool) -> int:
    with exclusive_lock(config.lock_file):
        state = read_state(config.state_file)
        node = current_node(config, state)
        healthy, checks = tunnel_health(config, node)
        if healthy:
            state.update({"active_node": node.name, "healthy": True, "failures": 0, "checks": checks, "updated_at": utc_now()})
            atomic_write_json(config.state_file, state)
            emit({"ok": True, "decision": "healthy", "active_node": node.name})
            return 0
        failures = int(state.get("failures", 0)) + 1
        state.update({"active_node": node.name, "healthy": False, "failures": failures, "checks": checks, "updated_at": utc_now()})
        atomic_write_json(config.state_file, state)
        if failures < config.failure_threshold:
            emit({"ok": False, "decision": "debouncing", "failures": failures})
            return 1
        confirmed, confirmation = tunnel_health(config, node)
        if confirmed:
            state.update({"healthy": True, "failures": 0, "checks": confirmation, "updated_at": utc_now()})
            atomic_write_json(config.state_file, state)
            emit({"ok": True, "decision": "recovered_before_switch", "active_node": node.name})
            return 0
        if not authorize:
            emit({"ok": False, "decision": "switch_not_authorized", "failures": failures})
            return 1
        last_switch = int(state.get("last_switch_at", 0))
        if int(time.time()) - last_switch < config.switch_cooldown_seconds:
            emit({"ok": False, "decision": "switch_cooldown", "failures": failures})
            return 1
        for candidate in next_nodes(config, node):
            if not node_reachable(config, candidate):
                continue
            switched, switch_checks = switch_to(config, state, candidate, "health_failure")
            if switched:
                emit({"ok": True, "decision": "switched", "active_node": candidate.name, "checks": switch_checks})
                return 0
        emit({"ok": False, "decision": "no_healthy_alternate", "active_node": node.name})
        return 1


def rotate(config: object, authorize: bool) -> int:
    if not authorize:
        emit({"ok": False, "decision": "switch_not_authorized"})
        return 2
    with exclusive_lock(config.lock_file):
        state = read_state(config.state_file)
        node = current_node(config, state)
        for candidate in next_nodes(config, node):
            if not node_reachable(config, candidate):
                continue
            switched, checks = switch_to(config, state, candidate, "scheduled_rotation")
            if switched:
                emit({"ok": True, "decision": "rotated", "active_node": candidate.name, "checks": checks})
                return 0
        emit({"ok": False, "decision": "rotation_skipped", "active_node": node.name})
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "tunnel":
            state = read_state(config.state_file)
            node = current_node(config, state)
            if not state.get("active_node"):
                state.update({"active_node": node.name, "updated_at": utc_now()})
                atomic_write_json(config.state_file, state)
            completed = run(ssh_command(config, node, tunnel=True), 365 * 24 * 60 * 60)
            return completed.returncode
        if args.command == "check":
            return check(config)
        if args.command == "guard":
            return guard(config, args.authorize_switch)
        if args.command == "rotate":
            return rotate(config, args.authorize_switch)
    except (ConfigError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
