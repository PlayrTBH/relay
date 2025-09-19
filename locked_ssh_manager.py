#!/usr/bin/env python3
"""Utility for creating and maintaining restricted SSH-only user accounts.

The script automates the workflow required to provision accounts that are
limited to a curated set of SSH destinations.  It performs three key tasks:

* Ensures the restricted login shell (:mod:`locked_ssh_shell`) is installed.
* Creates a local user account bound to that shell.
* Writes a per-user configuration file describing the allowed SSH targets.

The tool is designed to be executed with root privileges since it shells out to
``useradd`` and manipulates files under ``/etc``.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import List, Sequence


DEFAULT_SHELL_PATH = Path("/usr/local/bin/locked_ssh_shell")
DEFAULT_CONFIG_DIR = Path("/etc/ssh-lockdown")


class ManagerError(RuntimeError):
    """Base class for management related errors."""


def check_root() -> None:
    """Ensure the script runs with sufficient privileges."""

    if os.geteuid() != 0:
        raise ManagerError("This command must be run as root.")


def ensure_shell_script(shell_path: Path) -> None:
    """Copy the restricted shell script to ``shell_path`` if required."""

    source = Path(__file__).resolve().with_name("locked_ssh_shell.py")
    if not source.exists():
        raise ManagerError(
            f"Unable to locate locked_ssh_shell.py next to {__file__}."
        )

    shell_path = shell_path.resolve()
    shell_path.parent.mkdir(parents=True, exist_ok=True)

    needs_copy = True
    if shell_path.exists():
        try:
            needs_copy = shell_path.read_text(encoding="utf-8") != source.read_text(
                encoding="utf-8"
            )
        except OSError as exc:
            raise ManagerError(f"Unable to read {shell_path}: {exc}") from exc

    if needs_copy:
        try:
            shutil.copy2(source, shell_path)
        except OSError as exc:
            raise ManagerError(
                f"Failed to install shell script to {shell_path}: {exc}"
            ) from exc

    shell_path.chmod(
        stat.S_IRUSR
        | stat.S_IWUSR
        | stat.S_IXUSR
        | stat.S_IRGRP
        | stat.S_IXGRP
        | stat.S_IROTH
        | stat.S_IXOTH
    )


def ensure_config_dir(config_dir: Path) -> None:
    """Create the configuration directory with conservative permissions."""

    try:
        config_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ManagerError(
            f"Unable to create configuration directory {config_dir}: {exc}"
        ) from exc

    # Restrict to root access by default; administrators can relax this if
    # desired but we do not do so automatically.
    config_dir.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)


def parse_host_entry(raw: str) -> dict:
    """Parse ``raw`` into the JSON structure expected by the shell."""

    if "=" in raw:
        label, remainder = raw.split("=", 1)
    else:
        label, remainder = raw, raw

    label = label.strip()
    if not label:
        raise ManagerError(f"Invalid host entry '{raw}': empty name")

    username = None
    if "@" in remainder:
        username_part, remainder = remainder.split("@", 1)
        username_part = username_part.strip()
        if username_part:
            username = username_part

    port = 22
    hostname = remainder
    if ":" in remainder:
        hostname, port_part = remainder.rsplit(":", 1)
        hostname = hostname.strip()
        port_part = port_part.strip()
        if port_part:
            try:
                port = int(port_part)
            except ValueError as exc:
                raise ManagerError(
                    f"Invalid port '{port_part}' in host entry '{raw}'."
                ) from exc
            if port < 1 or port > 65535:
                raise ManagerError(
                    f"Port {port} in host entry '{raw}' is outside the 1-65535 range."
                )

    hostname = hostname.strip()
    if not hostname:
        raise ManagerError(f"Host entry '{raw}' is missing a hostname.")

    return {
        "name": label,
        "hostname": hostname,
        "username": username,
        "port": port,
        "options": [],
    }


def write_user_config(config_dir: Path, username: str, hosts: Sequence[dict]) -> Path:
    """Write the JSON configuration file for ``username``."""

    ensure_config_dir(config_dir)
    path = config_dir / f"{username}.json"
    payload = {"hosts": list(hosts)}
    try:
        content = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise ManagerError(f"Unable to write configuration file {path}: {exc}") from exc
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
    return path


def create_user(
    username: str,
    shell_path: Path,
    create_home: bool = True,
    comment: str | None = None,
    groups: Sequence[str] | None = None,
    password_hash: str | None = None,
) -> None:
    """Create a system user bound to ``shell_path``."""

    try:
        pwd.getpwnam(username)
    except KeyError:
        pass
    else:
        raise ManagerError(f"User '{username}' already exists.")

    cmd: List[str] = ["useradd", "--shell", str(shell_path)]
    cmd.append("--create-home" if create_home else "--no-create-home")
    if comment:
        cmd.extend(["--comment", comment])
    if groups:
        cmd.extend(["--groups", ",".join(groups)])
    if password_hash:
        cmd.extend(["--password", password_hash])
    cmd.append(username)

    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError as exc:
        raise ManagerError("The 'useradd' command is not available on this system.") from exc
    except subprocess.CalledProcessError as exc:
        raise ManagerError(
            f"useradd failed with exit code {exc.returncode}."
        ) from exc


def set_hosts(username: str, config_dir: Path, hosts: Sequence[dict]) -> Path:
    """Update the allowed host list for an existing restricted user."""

    try:
        pwd.getpwnam(username)
    except KeyError as exc:
        raise ManagerError(f"User '{username}' does not exist.") from exc

    return write_user_config(config_dir, username, hosts)


def cmd_add_user(args: argparse.Namespace) -> None:
    check_root()

    hosts = [parse_host_entry(raw) for raw in args.hosts]
    shell_path = Path(args.shell or DEFAULT_SHELL_PATH)
    ensure_shell_script(shell_path)
    create_user(
        username=args.username,
        shell_path=shell_path,
        create_home=not args.no_create_home,
        comment=args.comment,
        groups=args.groups or [],
        password_hash=args.password_hash,
    )
    config_path = write_user_config(
        Path(args.config_dir or DEFAULT_CONFIG_DIR), args.username, hosts
    )
    print(f"Created user '{args.username}' with restricted shell {shell_path}.")
    print(f"Allowed hosts written to {config_path}.")


def cmd_set_hosts(args: argparse.Namespace) -> None:
    check_root()

    hosts = [parse_host_entry(raw) for raw in args.hosts]
    config_path = set_hosts(
        username=args.username,
        config_dir=Path(args.config_dir or DEFAULT_CONFIG_DIR),
        hosts=hosts,
    )
    print(f"Updated allowed hosts for '{args.username}' in {config_path}.")


def cmd_show_hosts(args: argparse.Namespace) -> None:
    config_dir = Path(args.config_dir or DEFAULT_CONFIG_DIR)
    path = config_dir / f"{args.username}.json"
    try:
        content = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ManagerError(
            f"No configuration found for '{args.username}' in {config_dir}."
        ) from exc
    print(content.rstrip())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    add_user = subparsers.add_parser(
        "add-user",
        help="Create a new restricted user and configure allowed hosts.",
    )
    add_user.add_argument("username", help="System username to create.")
    add_user.add_argument(
        "--hosts",
        metavar="HOST",
        nargs="+",
        required=True,
        help=(
            "List of allowed hosts. Each entry may be 'name=host', 'user@host', or "
            "'user@host:port'. If a name is omitted the hostname is used."
        ),
    )
    add_user.add_argument(
        "--shell",
        metavar="PATH",
        help=f"Installation path for the restricted shell (default {DEFAULT_SHELL_PATH}).",
    )
    add_user.add_argument(
        "--config-dir",
        metavar="DIR",
        help=f"Directory for per-user host lists (default {DEFAULT_CONFIG_DIR}).",
    )
    add_user.add_argument(
        "--no-create-home",
        action="store_true",
        help="Do not create a home directory for the new user.",
    )
    add_user.add_argument(
        "--comment",
        help="GECOS comment / full name for the user.",
    )
    add_user.add_argument(
        "--groups",
        nargs="+",
        help="Additional groups to add the user to.",
    )
    add_user.add_argument(
        "--password-hash",
        help=(
            "Optional password hash passed to useradd's --password flag. "
            "Generate with 'openssl passwd -6'."
        ),
    )
    add_user.set_defaults(func=cmd_add_user)

    set_hosts_cmd = subparsers.add_parser(
        "set-hosts",
        help="Update the list of approved hosts for an existing user.",
    )
    set_hosts_cmd.add_argument("username", help="Restricted user to modify.")
    set_hosts_cmd.add_argument(
        "--hosts",
        metavar="HOST",
        nargs="+",
        required=True,
        help="List of hosts using the same syntax as 'add-user'.",
    )
    set_hosts_cmd.add_argument(
        "--config-dir",
        metavar="DIR",
        help=f"Directory for per-user host lists (default {DEFAULT_CONFIG_DIR}).",
    )
    set_hosts_cmd.set_defaults(func=cmd_set_hosts)

    show_hosts_cmd = subparsers.add_parser(
        "show-hosts",
        help="Display the JSON configuration for a restricted user.",
    )
    show_hosts_cmd.add_argument("username")
    show_hosts_cmd.add_argument(
        "--config-dir",
        metavar="DIR",
        help=f"Directory for per-user host lists (default {DEFAULT_CONFIG_DIR}).",
    )
    show_hosts_cmd.set_defaults(func=cmd_show_hosts)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        args.func(args)
    except ManagerError as exc:
        parser.exit(1, f"error: {exc}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
