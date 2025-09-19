# Locked SSH User Management

This repository contains a small toolkit for provisioning users whose shell is
restricted to launching SSH sessions against a curated list of hosts.  It is
useful when granting temporary or limited access to internal infrastructure
without exposing a full Linux shell.

Two entry points are provided:

* `locked_ssh_manager.py` &ndash; command line utility used by administrators to
  create users and configure their approved SSH destinations.
* `locked_ssh_shell.py` &ndash; Python program that acts as the login shell for the
  restricted users created by the manager.  The shell only accepts the `ssh`
  command and refuses all other input.

## Requirements

* Linux system with Python 3.8+.
* Root privileges to create users and write to `/etc`.
* `useradd` command available (provided by the `passwd`/`shadow` packages on
  most distributions).

## Creating a restricted user

The manager should be run as root.  The following example creates a user named
`jump` that may SSH to `bastion.example.com` as `jump`, or to
`admin@example.net` on TCP port 2222:

```bash
sudo ./locked_ssh_manager.py add-user jump \
    --hosts bastion.example.com admin=admin@example.net:2222
```

The command performs the following steps:

1. Installs `locked_ssh_shell.py` to `/usr/local/bin/locked_ssh_shell` (if not
   already present or out of date) and marks it executable.
2. Creates the `jump` user whose login shell is the restricted shell.
3. Generates `/etc/ssh-lockdown/jump.json`, a JSON document enumerating the
   hosts the user may contact.

You may override the shell installation path or configuration directory with
`--shell` and `--config-dir` respectively.  Additional options such as
`--comment`, `--groups`, `--no-create-home`, and `--password-hash` are forwarded
to the underlying `useradd` invocation.

## Updating allowed hosts

To change the host list for an existing restricted user, run:

```bash
sudo ./locked_ssh_manager.py set-hosts jump \
    --hosts bastion.example.com staging=staging@example.org
```

To inspect the stored configuration for troubleshooting:

```bash
./locked_ssh_manager.py show-hosts jump
```

## Behaviour of the restricted shell

When a restricted user logs in, `locked_ssh_shell.py` reads their configuration
file and presents a minimal prompt that only accepts three commands:

* `list` – display the approved host names and their targets.
* `ssh <name>` – connect to one of the approved hosts.
* `exit` – terminate the session.

All other input is rejected.  After an SSH session ends the user is returned to
the prompt so they can initiate another connection or log out.

Configuration files default to `/etc/ssh-lockdown/<username>.json`.  Set the
`LOCKED_SSH_CONFIG_DIR` environment variable if the files live elsewhere.
