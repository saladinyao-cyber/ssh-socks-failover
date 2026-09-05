from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ssh_socks_failover.core import (
    ConfigError,
    atomic_write_json,
    current_node,
    load_config,
    next_nodes,
    read_state,
    ssh_command,
)


def config_document(root: Path) -> dict:
    return {
        "version": 1,
        "nodes": [
            {
                "name": "one", "host": "192.0.2.1", "user": "alice", "ssh_port": 22,
                "identity_file": str(root / "key"), "known_hosts_file": str(root / "known_hosts"),
                "expected_egress_ip": "192.0.2.1",
            },
            {
                "name": "two", "host": "198.51.100.2", "user": "bob", "ssh_port": 2222,
                "identity_file": str(root / "key"), "known_hosts_file": str(root / "known_hosts"),
                "expected_egress_ip": "198.51.100.2",
            },
        ],
        "local": {"socks_host": "127.0.0.1", "socks_port": 1080},
        "health_url": "https://api.ipify.org",
        "tunnel_service": "ssh-socks-failover-tunnel.service",
        "state_dir": str(root / "state"),
        "policy": {"failure_threshold": 3, "switch_cooldown_seconds": 60},
    }


class CoreTests(unittest.TestCase):
    def write_config(self, root: Path, document: dict) -> Path:
        path = root / "config.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_load_config_and_rotation_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = load_config(self.write_config(root, config_document(root)))
            current = current_node(config, {"active_node": "two"})
            self.assertEqual(current.name, "two")
            self.assertEqual([node.name for node in next_nodes(config, current)], ["one"])

    def test_atomic_state_round_trip_and_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private" / "state.json"
            atomic_write_json(target, {"active_node": "one", "healthy": True})
            self.assertEqual(read_state(target)["active_node"], "one")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_rejects_non_loopback_listener(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = config_document(root)
            document["local"]["socks_host"] = "0.0.0.0"
            with self.assertRaises(ConfigError):
                load_config(self.write_config(root, document))

    def test_rejects_shell_metacharacters_in_user(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = config_document(root)
            document["nodes"][0]["user"] = "user;command"
            with self.assertRaises(ConfigError):
                load_config(self.write_config(root, document))

    def test_unresolved_environment_variable_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = config_document(root)
            document["state_dir"] = "${SSHF_TEST_MISSING_VALUE}"
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaises(ConfigError):
                    load_config(self.write_config(root, document))

    def test_ssh_command_enforces_host_key_checking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = load_config(self.write_config(root, config_document(root)))
            command = ssh_command(config, config.nodes[0], tunnel=True)
            self.assertIn("StrictHostKeyChecking=yes", command)
            self.assertIn("ExitOnForwardFailure=yes", command)
            self.assertNotIn("shell=True", command)


if __name__ == "__main__":
    unittest.main()
