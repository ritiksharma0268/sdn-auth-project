#!/usr/bin/env python3

import ipaddress
import subprocess

SWITCH = "s1"
PROTOCOL = "OpenFlow13"

HOSTS = {
    "alice": {
        "ip": "10.0.0.1",
        "mac": "00:00:00:00:00:01",
        "port": 1,
    },
    "bob": {
        "ip": "10.0.0.2",
        "mac": "00:00:00:00:00:02",
        "port": 2,
    },
}


def run_ovs(args):
    command = ["ovs-ofctl", "-O", PROTOCOL, args[0], SWITCH, *args[1:]]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=5,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())

    return result.stdout


def show_flows():
    return run_ovs(["dump-flows"])


def clear_flows():
    run_ovs(["del-flows"])


def initialize():
    """Clear old rules and block unmatched traffic."""
    clear_flows()
    run_ovs(["add-flow", "priority=0,actions=drop"])


def grant_access(username):
    """Allow the configured host's IPv4 and ARP traffic."""
    if username not in HOSTS:
        raise ValueError("Unknown user")

    host = HOSTS[username]
    ipaddress.ip_address(host["ip"])

    port = host["port"]
    other_port = 3 - port
    mac = host["mac"]
    ip = host["ip"]

    # Allow IPv4 traffic from this host.
    run_ovs([
        "add-flow",
        f"priority=100,dl_type=0x0800,in_port={port},dl_src={mac},nw_src={ip},actions=output:{other_port}",
    ])

    # Allow ARP from this host.
    run_ovs([
        "add-flow",
        f"priority=100,arp,in_port={port},dl_src={mac},actions=output:{other_port}",
    ])


def revoke_access(username):
    """Remove this host's IPv4 and ARP permissions."""
    if username not in HOSTS:
        raise ValueError("Unknown user")

    host = HOSTS[username]
    port = host["port"]
    mac = host["mac"]
    ip = host["ip"]

    run_ovs([
        "del-flows",
        "--strict",
        f"priority=100,dl_type=0x0800,in_port={port},dl_src={mac},nw_src={ip}",
    ])

    run_ovs([
        "del-flows",
        "--strict",
        f"priority=100,arp,in_port={port},dl_src={mac}",
    ])


if __name__ == "__main__":
    print("Flow manager syntax and loading check.")

    result = subprocess.run(
        ["ovs-ofctl", "--version"],
        capture_output=True,
        text=True,
        timeout=5,
    )

    if result.returncode != 0:
        raise SystemExit(result.stderr)

    print(result.stdout.splitlines()[0])
    print("Functions: initialize, grant_access, revoke_access, show_flows")
