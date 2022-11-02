#!/usr/bin/env python

#
# test_bgp_auth.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by Volta Networks
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
test_bgp_auth.py: Test BGP Md5 Authentication

                             +------+
                    +--------|      |--------+
                    | +------|  R1  |------+ |
                    | | -----|      |----+ | |
                    | | |    +------+    | | |
                    | | |                | | |
                   +------+            +------+
                   |      |------------|      |
                   |  R2  |------------|  R3  |
                   |      |------------|      |
                   +------+            +------+


setup is 3 routers with 3 links between each each link in a different vrf
Default, blue and red respectively
Tests check various fiddling with passwords and checking that the peer
establishment is as expected and passwords are not leaked across sockets
for bgp instances
"""
# pylint: disable=C0413

import json
import os
import platform
import sys
from time import sleep

import pytest
from lib import common_config, topotest
from lib.topolog import logger
from lib.common_config import (
    save_initial_config_on_routers,
    reset_with_new_configs,
)

from bgp_auth_common import (
    check_all_peers_established,
    check_vrf_peer_remove_passwords,
    check_vrf_peer_change_passwords,
    check_neigh_state
)
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd]

CWD = os.path.dirname(os.path.realpath(__file__))


def build_topo(tgen):
    tgen.add_router("R1")
    tgen.add_router("R2")
    tgen.add_router("R3")

    tgen.add_link(tgen.gears["R1"], tgen.gears["R2"])
    tgen.add_link(tgen.gears["R1"], tgen.gears["R3"])
    tgen.add_link(tgen.gears["R2"], tgen.gears["R3"])
    tgen.add_link(tgen.gears["R1"], tgen.gears["R2"])
    tgen.add_link(tgen.gears["R1"], tgen.gears["R3"])
    tgen.add_link(tgen.gears["R2"], tgen.gears["R3"])
    tgen.add_link(tgen.gears["R1"], tgen.gears["R2"])
    tgen.add_link(tgen.gears["R1"], tgen.gears["R3"])
    tgen.add_link(tgen.gears["R2"], tgen.gears["R3"])


def setup_module(mod):
    "Sets up the pytest environment"
    # This function initiates the topology build with Topogen...
    tgen = Topogen(build_topo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    r1 = tgen.gears["R1"]
    r2 = tgen.gears["R2"]
    r3 = tgen.gears["R3"]

    # blue vrf
    r1.cmd_raises("ip link add blue type vrf table 1001")
    r1.cmd_raises("ip link set up dev blue")
    r2.cmd_raises("ip link add blue type vrf table 1001")
    r2.cmd_raises("ip link set up dev blue")
    r3.cmd_raises("ip link add blue type vrf table 1001")
    r3.cmd_raises("ip link set up dev blue")

    r1.cmd_raises("ip link add lo1 type dummy")
    r1.cmd_raises("ip link set lo1 master blue")
    r1.cmd_raises("ip link set up dev lo1")
    r2.cmd_raises("ip link add lo1 type dummy")
    r2.cmd_raises("ip link set up dev lo1")
    r2.cmd_raises("ip link set lo1 master blue")
    r3.cmd_raises("ip link add lo1 type dummy")
    r3.cmd_raises("ip link set up dev lo1")
    r3.cmd_raises("ip link set lo1 master blue")

    r1.cmd_raises("ip link set R1-eth2 master blue")
    r1.cmd_raises("ip link set R1-eth3 master blue")
    r2.cmd_raises("ip link set R2-eth2 master blue")
    r2.cmd_raises("ip link set R2-eth3 master blue")
    r3.cmd_raises("ip link set R3-eth2 master blue")
    r3.cmd_raises("ip link set R3-eth3 master blue")

    r1.cmd_raises("ip link set up dev  R1-eth2")
    r1.cmd_raises("ip link set up dev  R1-eth3")
    r2.cmd_raises("ip link set up dev  R2-eth2")
    r2.cmd_raises("ip link set up dev  R2-eth3")
    r3.cmd_raises("ip link set up dev  R3-eth2")
    r3.cmd_raises("ip link set up dev  R3-eth3")

    # red vrf
    r1.cmd_raises("ip link add red type vrf table 1002")
    r1.cmd_raises("ip link set up dev red")
    r2.cmd_raises("ip link add red type vrf table 1002")
    r2.cmd_raises("ip link set up dev red")
    r3.cmd_raises("ip link add red type vrf table 1002")
    r3.cmd_raises("ip link set up dev red")

    r1.cmd_raises("ip link add lo2 type dummy")
    r1.cmd_raises("ip link set lo2 master red")
    r1.cmd_raises("ip link set up dev lo2")
    r2.cmd_raises("ip link add lo2 type dummy")
    r2.cmd_raises("ip link set up dev lo2")
    r2.cmd_raises("ip link set lo2 master red")
    r3.cmd_raises("ip link add lo2 type dummy")
    r3.cmd_raises("ip link set up dev lo2")
    r3.cmd_raises("ip link set lo2 master red")

    r1.cmd_raises("ip link set R1-eth4 master red")
    r1.cmd_raises("ip link set R1-eth5 master red")
    r2.cmd_raises("ip link set R2-eth4 master red")
    r2.cmd_raises("ip link set R2-eth5 master red")
    r3.cmd_raises("ip link set R3-eth4 master red")
    r3.cmd_raises("ip link set R3-eth5 master red")

    r1.cmd_raises("ip link set up dev  R1-eth4")
    r1.cmd_raises("ip link set up dev  R1-eth5")
    r2.cmd_raises("ip link set up dev  R2-eth4")
    r2.cmd_raises("ip link set up dev  R2-eth5")
    r3.cmd_raises("ip link set up dev  R3-eth4")
    r3.cmd_raises("ip link set up dev  R3-eth5")

    r1.cmd_raises("sysctl -w net.ipv4.tcp_l3mdev_accept=1")
    r2.cmd_raises("sysctl -w net.ipv4.tcp_l3mdev_accept=1")
    r3.cmd_raises("sysctl -w net.ipv4.tcp_l3mdev_accept=1")

    # This is a sample of configuration loading.
    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
        router.load_config(TopoRouter.RD_OSPF)
        router.load_config(TopoRouter.RD_BGP)

    # After copying the configurations, this function loads configured daemons.
    tgen.start_router()

    # Save the initial router config. reset_config_on_routers will return to this config.
    save_initial_config_on_routers(tgen)


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


@pytest.fixture(scope="session")
def tcp_authopt_sysctl_enabled():
    from pathlib import Path

    # This needs to be enabled system-wide, it is not namespaced
    path = Path("/proc/sys/net/ipv4/tcp_authopt")
    if not path.exists():
        yield
    else:
        if path.exists and path.read_text().strip() == "0":
            logger.info("Temporarily enabling tcp_authopt")
            path.write_text("1")
            yield
            path.write_text("0")
        else:
            yield


@pytest.fixture(scope="session")
def tcp_authopt_available(tcp_authopt_sysctl_enabled):
    from pathlib import Path
    import socket
    import errno

    path = Path("/proc/sys/net/ipv4/tcp_authopt")
    TCP_AUTHOPT = 38
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            optbuf = bytes(4)
            sock.setsockopt(socket.SOL_TCP, TCP_AUTHOPT, optbuf)
        except OSError as e:
            if e.errno == errno.ENOPROTOOPT:
                pytest.skip("TCP_AUTHOPT not supported by kernel")
            if e.errno == errno.EPERM:
                pytest.skip("TCP_AUTHOPT not permitted. Check CAP_NET_ADMIN and system-wide /proc/sys/net/ipv4/tcp_authopt")
            raise


def test_tcp_authopt_keychain(tgen, tcp_authopt_available):
    reset_with_new_configs(tgen, "bgpd.conf", "ospfd.conf")
    check_all_peers_established()
    r1 = tgen.gears["R1"]
    r2 = tgen.gears["R2"]
    out = r1.vtysh_cmd("""
        configure terminal
        key chain aaa
            key 1
                key-string aaa
                tcp-authopt enabled
                tcp-authopt algorithm hmac-sha-1-96
                tcp-authopt send-id 1
                tcp-authopt recv-id 2
            !
        !
        router bgp 65001
            no neighbor 2.2.2.2 password
            neighbor 2.2.2.2 tcp-authopt aaa
        !
""")
    logger.info("config msg:\n%s", out)
    out = r1.vtysh_cmd("show running-config")
    logger.info("new R1 config:\n%s", out)
    assert "key chain aaa" in out
    assert "key 1" in out
    assert "tcp-authopt enabled" in out
    assert "tcp-authopt send-id 1" in out
    assert "neighbor 2.2.2.2 tcp-authopt aaa" in out

    # configure R2:
    r2.vtysh_cmd("""
        configure terminal
        key chain aaa
            key 1
                key-string aaa
                tcp-authopt enabled
                tcp-authopt algorithm hmac-sha-1-96
                tcp-authopt send-id 2
                tcp-authopt recv-id 1
            !
        !
        router bgp 65002
            no neighbor 1.1.1.1 password
            neighbor 1.1.1.1 tcp-authopt aaa
        !
""")
    out = r2.vtysh_cmd("show running-config")
    logger.info("new R2 config:\n%s", out)
    assert "neighbor 1.1.1.1 tcp-authopt aaa" in out

    # wait connections established
    check_neigh_state(r1, "2.2.2.2", "Established")
    check_neigh_state(r2, "1.1.1.1", "Established")

    # Check keyids in json output
    assert router_bgp_tcp_authopt_cmp(r1, "2.2.2.2", dict(send_keyid=1, recv_keyid=2))
    assert router_bgp_tcp_authopt_cmp(r2, "1.1.1.1", dict(send_keyid=1, recv_keyid=2))

    # Check keyids in plain text output
    out = r1.vtysh_cmd("show bgp neighbor 2.2.2.2")
    logger.info("r1 peer r2:\n%s", out)
    assert " keyid 1 " in out
    assert " recv_keyid 2 " in out
    out = r2.vtysh_cmd("show bgp neighbor 1.1.1.1")
    logger.info("r2 peer r1:\n%s", out)
    assert " keyid 2 " in out
    assert " recv_keyid 1 " in out


def router_bgp_tcp_authopt_cmp(router, peer, tcp_authopt_data):
    cmd = "show bgp neighbor {} json".format(peer)
    data = dict(peer=dict(tcp_authopt=tcp_authopt_data))
    return topotest.router_json_cmp(router, cmd, data)



def test_default_peer_established(tgen):
    "default vrf 3 peers same password"

    reset_with_new_configs(tgen, "bgpd.conf", "ospfd.conf")
    check_all_peers_established()


def test_default_peer_remove_passwords(tgen):
    "selectively remove passwords checking state"

    reset_with_new_configs(tgen, "bgpd.conf", "ospfd.conf")
    check_vrf_peer_remove_passwords()


def test_default_peer_change_passwords(tgen):
    "selectively change passwords checking state"

    reset_with_new_configs(tgen, "bgpd.conf", "ospfd.conf")
    check_vrf_peer_change_passwords()


def test_default_prefix_peer_established(tgen):
    "default vrf 3 peers same password with prefix config"

    # only supported in kernel > 5.3
    if topotest.version_cmp(platform.release(), "5.3") < 0:
        return

    reset_with_new_configs(tgen, "bgpd_prefix.conf", "ospfd.conf")
    check_all_peers_established()


def test_prefix_peer_remove_passwords(tgen):
    "selectively remove passwords checking state with prefix config"

    # only supported in kernel > 5.3
    if topotest.version_cmp(platform.release(), "5.3") < 0:
        return

    reset_with_new_configs(tgen, "bgpd_prefix.conf", "ospfd.conf")
    check_vrf_peer_remove_passwords(prefix="yes")


def test_memory_leak(tgen):
    "Run the memory leak test and report results."
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
