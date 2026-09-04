# ssh-socks-failover

A small, provider-neutral Linux tool for maintaining one local SSH dynamic
SOCKS5 endpoint across two or more remote SSH nodes. It performs layered health
checks, debounces transient failures, fails over with rollback, writes state
atomically, and can rotate nodes daily.

The project has no cloud provisioning code, notification integration, or
third-party Python dependencies. Every host, user, port, filesystem path, and
policy value comes from JSON configuration or environment expansion.

## Safety model

- The SOCKS listener must use a loopback address; public binding is rejected.
- SSH always uses batch mode, an explicit identity, a dedicated known-hosts
  file, strict host-key checking, and argument arrays rather than a shell.
- A switch requires both `--authorize-switch` and a reachable candidate.
- Automatic failover requires consecutive failures plus a confirmation check.
- A cooldown prevents switch flapping; a failed switch restores the prior node.
- State uses mode `0600`, file `fsync`, atomic replacement, and directory
  `fsync`; manager operations use a non-blocking process lock.
- The repository validator rejects files outside an exact allowlist, symlinks,
  credential-like text, private keys, email addresses, private user paths,
  environment-specific terms, and IPv4 literals outside loopback/unspecified
  or the RFC 5737 documentation ranges.

## Requirements

- Linux with a user systemd instance
- Python 3.10 or newer
- OpenSSH client and `curl`
- Two or more SSH nodes configured for key-based login

## Install

```console
python3 -m pip install --user .
mkdir -p ~/.config/ssh-socks-failover
cp examples/config.example.json ~/.config/ssh-socks-failover/config.json
cp examples/runtime.env.example ~/.config/ssh-socks-failover/runtime.env
cp systemd/* ~/.config/systemd/user/
```

Edit the two private files. Replace all placeholders, add each node's host key
to the dedicated known-hosts file, and keep the environment file out of this
repository. The addresses in the example are RFC 5737 documentation addresses
and cannot be used as real endpoints.

Then reload and enable the units:

```console
systemctl --user daemon-reload
systemctl --user enable --now ssh-socks-failover-tunnel.service
systemctl --user enable --now ssh-socks-failover-guard.timer
systemctl --user enable --now ssh-socks-failover-rotate.timer
```

## Commands

The global `--config` option must precede the subcommand.

```console
ssh-socks-failover --config /path/to/config.json check
ssh-socks-failover --config /path/to/config.json guard
ssh-socks-failover --config /path/to/config.json guard --authorize-switch
ssh-socks-failover --config /path/to/config.json rotate --authorize-switch
ssh-socks-failover --config /path/to/config.json tunnel
```

`check` is read-only. `guard` records health and failure count but cannot change
nodes unless explicitly authorized. `rotate` refuses to act without explicit
authorization. The systemd templates include that authorization for unattended
operation; remove it if you want monitor-only behavior.

## Configuration

`examples/config.example.json` shows three nodes to demonstrate that selection
is not limited to a primary/standby pair. Node order defines failover and daily
rotation order. `${NAME}` strings are expanded from the process environment;
unresolved variables fail closed.

The health URL must use HTTPS and return only the caller's public IP address.
`expected_egress_ip` binds a successful proxy request to the selected node,
preventing a merely-open local port from being treated as healthy.

## Development and privacy validation

```console
python3 -m py_compile src/ssh_socks_failover/*.py tests/*.py tools/*.py
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 tools/validate_public_repo.py
git diff --check
```

The validator is intentionally fail closed. Update its exact file allowlist as
part of any deliberate repository-layout change. CI runs compilation, tests,
and the same public-safety validation on every push and pull request.

## License

MIT
