#!/usr/bin/env python3
"""Login shell that only allows SSH connections to approved hosts.

This script is designed to be installed as the login shell for restricted
users.  It reads a configuration file that enumerates the SSH destinations the
user is allowed to reach and provides a minimal interactive prompt that
accepts only the ``ssh`` command.  The user is unable to execute arbitrary
programs or spawn a conventional shell.

The script expects a JSON configuration file located at
``/etc/ssh-lockdown/<username>.json`` by default.  The path can be overridden
with the ``LOCKED_SSH_CONFIG_DIR`` environment variable.  A configuration file
must have the following structure::

    {
        "hosts": [
            {
                "name": "prod",
                "hostname": "prod.example.com",
                "username": "deploy",
                "port": 22,
                "options": ["-i", "/path/to/key"]
            }
        ]
    }

Each host entry describes a single SSH destination.  The ``name`` field is
used as the label that users reference at the prompt.  The ``username`` field
is optional; if omitted the SSH command does not include a user component and
the system's login name is used instead.

When a user chooses a host, the script invokes ``ssh`` and attaches the
current terminal to the remote session.  After the SSH process exits the user
is returned to the restricted prompt.
"""

from __future__ import annotations

import json
import os
import pwd
import shlex
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable, List, Sequence


CONFIG_ENV_VAR = "LOCKED_SSH_CONFIG_DIR"
DEFAULT_CONFIG_DIR = "/etc/ssh-lockdown"


class ConfigurationError(RuntimeError):
    """Raised when the login shell configuration is invalid."""


@dataclass(frozen=True)
class HostEntry:
    """Representation of an allowed SSH destination."""

    name: str
    hostname: str
    username: str | None = None
    port: int = 22
    options: Sequence[str] = ()

    @property
    def display_target(self) -> str:
        """Human readable identifier for menus and logs."""

        if self.username:
            base = f"{self.username}@{self.hostname}"
        else:
            base = self.hostname
        if self.port != 22:
            base += f":{self.port}"
        return base

    def build_ssh_command(self, additional_args: Iterable[str] = ()) -> List[str]:
        """Construct the SSH command for this host.

        ``additional_args`` can be used to forward any extra arguments that are
        allowed by the login shell (currently there are none, but the hook
        exists so that a future manager could safely whitelist additional
        behaviour).
        """

        target = self.display_target
        base_cmd = ["ssh"]
        if self.port != 22:
            # ``ssh`` expects the port to be passed with ``-p``
            base_cmd += ["-p", str(self.port)]
            # ``display_target`` already has :port appended; rebuild target
            if self.username:
                target = f"{self.username}@{self.hostname}"
            else:
                target = self.hostname
        base_cmd.extend(self.options)
        base_cmd.extend(additional_args)
        base_cmd.append(target)
        return base_cmd


def load_config(username: str) -> List[HostEntry]:
    """Load the allowed host list for *username*.

    The configuration format is intentionally simple to make the policy easy
    to audit.  Every host entry is validated to ensure it contains the fields
    required by :class:`HostEntry`.
    """

    config_dir = os.environ.get(CONFIG_ENV_VAR, DEFAULT_CONFIG_DIR)
    config_path = os.path.join(config_dir, f"{username}.json")

    try:
        with open(config_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError as exc:  # pragma: no cover - exercised at runtime
        raise ConfigurationError(
            f"Configuration file not found: {config_path}. Contact your administrator."
        ) from exc
    except json.JSONDecodeError as exc:  # pragma: no cover
        raise ConfigurationError(
            f"Configuration file {config_path} is not valid JSON: {exc}"
        ) from exc

    hosts_raw = data.get("hosts")
    if not isinstance(hosts_raw, list) or not hosts_raw:
        raise ConfigurationError(
            "Configuration must contain a non-empty 'hosts' list."
        )

    entries: List[HostEntry] = []
    for index, entry in enumerate(hosts_raw, start=1):
        if not isinstance(entry, dict):
            raise ConfigurationError(
                f"Host entry #{index} must be an object with host details."
            )

        try:
            name = str(entry["name"]).strip()
            hostname = str(entry["hostname"]).strip()
        except KeyError as exc:
            raise ConfigurationError(
                f"Host entry #{index} is missing required field: {exc.args[0]}"
            ) from exc

        if not name:
            raise ConfigurationError(f"Host entry #{index} has an empty 'name'.")
        if not hostname:
            raise ConfigurationError(
                f"Host entry #{index} has an empty 'hostname'."
            )

        username_value = entry.get("username")
        if username_value is not None:
            username_value = str(username_value).strip() or None

        port_value = entry.get("port", 22)
        try:
            port = int(port_value)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(
                f"Host entry #{index} has an invalid 'port' value: {port_value!r}"
            ) from exc
        if port < 1 or port > 65535:
            raise ConfigurationError(
                f"Host entry #{index} has a port outside the valid range (1-65535)."
            )

        raw_options = entry.get("options", [])
        if raw_options is None:
            options: Sequence[str] = ()
        elif isinstance(raw_options, list) and all(
            isinstance(item, str) for item in raw_options
        ):
            options = tuple(raw_options)
        else:
            raise ConfigurationError(
                f"Host entry #{index} contains a non-list 'options' value."
            )

        entries.append(
            HostEntry(
                name=name,
                hostname=hostname,
                username=username_value,
                port=port,
                options=options,
            )
        )

    return entries


def render_host_table(hosts: Sequence[HostEntry]) -> str:
    """Format the host list for the ``list`` command."""

    lines = ["Available SSH destinations:"]
    width = max(len(host.name) for host in hosts)
    for host in hosts:
        padding = " " * (width - len(host.name))
        lines.append(f"  {host.name}{padding}  ->  {host.display_target}")
    return "\n".join(lines)


def run_shell() -> int:
    """Main entry point for the restricted shell."""

    # ``os.getlogin`` may fail for daemonised processes; ``pwd`` is safer.
    username = pwd.getpwuid(os.getuid()).pw_name

    try:
        hosts = load_config(username)
    except ConfigurationError as exc:
        print(f"[locked-ssh] {exc}", file=sys.stderr)
        return os.EX_CONFIG

    host_map = {host.name: host for host in hosts}
    print("Welcome to the restricted SSH shell.")
    print("Type 'list' to view allowed destinations or 'exit' to disconnect.")
    print("Only the 'ssh <name>' command is permitted.\n")

    while True:
        try:
            raw = input("locked-ssh> ")
        except EOFError:
            print()
            return 0
        except KeyboardInterrupt:
            print()
            continue

        command = raw.strip()
        if not command:
            continue

        if command.lower() in {"exit", "quit"}:
            return 0

        if command.lower() == "list":
            print(render_host_table(hosts))
            continue

        if command.startswith("ssh "):
            _, _, remainder = command.partition(" ")
            target_name = remainder.strip()
            if not target_name:
                print("Usage: ssh <name>")
                continue

            host_entry = host_map.get(target_name)
            if host_entry is None:
                print(
                    f"'{target_name}' is not an approved host. Type 'list' for the available names."
                )
                continue

            ssh_cmd = host_entry.build_ssh_command()
            print(f"Connecting to {host_entry.display_target}...\n")
            try:
                subprocess.run(ssh_cmd, check=False)
            except FileNotFoundError:
                print("The 'ssh' binary is not installed on this system.")
                return os.EX_UNAVAILABLE
            except Exception as exc:  # pragma: no cover - defensive
                print(f"Failed to launch ssh: {exc}")
                continue

            print()  # ensure prompt starts on a new line
            continue

        # Reject any other commands explicitly to avoid silently ignoring them.
        tokens = shlex.split(command)
        print(
            "Command not permitted in restricted shell: "
            + " ".join(shlex.quote(token) for token in tokens)
        )


def main() -> int:
    try:
        return run_shell()
    except Exception as exc:  # pragma: no cover - last resort error handling
        print(f"[locked-ssh] unexpected error: {exc}", file=sys.stderr)
        return os.EX_SOFTWARE


if __name__ == "__main__":
    sys.exit(main())
