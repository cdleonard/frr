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
from lib.common_config import (
    save_initial_config_on_routers,
    reset_with_new_configs,
)
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

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

    # This is a sample of configuration loading.
    router_list = tgen.routers()

    # For all registred routers, load the zebra configuration file
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


def vrf_str(vrf):
    if vrf == "":
        vrf_str = ""
    else:
        vrf_str = "vrf {}".format(vrf)

    return vrf_str


def peer_name(rtr, prefix, vrf):
    "generate VRF string for CLI"
    if vrf == "":
        vrf_str = ""
    else:
        vrf_str = "_" + vrf

    if prefix == "yes":
        if rtr == "R2":
            return "TWO_GROUP" + vrf_str
        else:
            return "THREE_GROUP" + vrf_str
    else:
        if rtr == "R2":
            return "2.2.2.2"
        else:
            return "3.3.3.3"


def print_diag(vrf):
    "print failure disagnostics"

    tgen = get_topogen()
    router_list = tgen.routers()
    for rname, router in router_list.items():
        print(rname + ":")
        print(router.vtysh_cmd("show run"))
        print(router.vtysh_cmd("show ip route {}".format(vrf_str(vrf))))
        print(router.vtysh_cmd("show bgp {} neighbor".format(vrf_str(vrf))))


@common_config.retry(retry_timeout=190)
def _check_neigh_state(router, peer, state, vrf=""):
    "check BGP neighbor state on a router"

    neigh_output = router.vtysh_cmd(
        "show bgp {} neighbors {} json".format(vrf_str(vrf), peer)
    )

    peer_state = "Unknown"
    neigh_output_json = json.loads(neigh_output)
    if peer in neigh_output_json:
        peer_state = neigh_output_json[peer]["bgpState"]
        if peer_state == state:
            return True
    return "{} peer with {} expected state {} got {} ".format(
        router.name, peer, state, peer_state
    )


def check_neigh_state(router, peer, state, vrf=""):
    "check BGP neighbor state on a router"

    assertmsg = _check_neigh_state(router, peer, state, vrf)
    assert assertmsg is True, assertmsg


def check_all_peers_established(vrf=""):
    "standard check for extablished peers per vrf"

    tgen = get_topogen()
    r1 = tgen.gears["R1"]
    r2 = tgen.gears["R2"]
    r3 = tgen.gears["R3"]
    # do r1 last as he might be the dynamic one
    check_neigh_state(r2, "1.1.1.1", "Established", vrf)
    check_neigh_state(r2, "3.3.3.3", "Established", vrf)
    check_neigh_state(r3, "1.1.1.1", "Established", vrf)
    check_neigh_state(r3, "2.2.2.2", "Established", vrf)
    check_neigh_state(r1, "2.2.2.2", "Established", vrf)
    check_neigh_state(r1, "3.3.3.3", "Established", vrf)


def check_vrf_peer_remove_passwords(vrf="", prefix="no"):
    "selectively remove passwords checking state"

    tgen = get_topogen()
    r1 = tgen.gears["R1"]
    r2 = tgen.gears["R2"]
    r3 = tgen.gears["R3"]

    check_all_peers_established(vrf)

    r1.vtysh_cmd(
        "conf t\nrouter bgp 65001 {}\nno neighbor {} password".format(
            vrf_str(vrf), peer_name("R2", prefix, vrf)
        )
    )

    check_neigh_state(r2, "1.1.1.1", "Connect", vrf)
    check_neigh_state(r2, "3.3.3.3", "Established", vrf)
    check_neigh_state(r3, "1.1.1.1", "Established", vrf)
    check_neigh_state(r3, "2.2.2.2", "Established", vrf)
    # don't check dynamic downed peers - they are removed
    if prefix == "no":
        check_neigh_state(r1, "2.2.2.2", "Connect", vrf)
    check_neigh_state(r1, "3.3.3.3", "Established", vrf)

    r2.vtysh_cmd(
        "conf t\nrouter bgp 65002 {}\nno neighbor 1.1.1.1 password".format(vrf_str(vrf))
    )
    check_all_peers_established(vrf)

    r1.vtysh_cmd(
        "conf t\nrouter bgp 65001 {}\nno neighbor {} password".format(
            vrf_str(vrf), peer_name("R3", prefix, vrf)
        )
    )
    check_neigh_state(r2, "1.1.1.1", "Established", vrf)
    check_neigh_state(r2, "3.3.3.3", "Established", vrf)
    check_neigh_state(r3, "1.1.1.1", "Connect", vrf)
    check_neigh_state(r3, "2.2.2.2", "Established", vrf)
    check_neigh_state(r1, "2.2.2.2", "Established", vrf)
    # don't check dynamic downed peers - they are removed
    if prefix == "no":
        check_neigh_state(r1, "3.3.3.3", "Connect", vrf)

    r3.vtysh_cmd(
        "conf t\nrouter bgp 65003 {}\nno neighbor 1.1.1.1 password".format(vrf_str(vrf))
    )
    check_all_peers_established(vrf)

    r2.vtysh_cmd(
        "conf t\nrouter bgp 65002 {}\nno neighbor 3.3.3.3 password".format(vrf_str(vrf))
    )
    check_neigh_state(r2, "1.1.1.1", "Established", vrf)
    check_neigh_state(r2, "3.3.3.3", "Connect", vrf)
    check_neigh_state(r3, "1.1.1.1", "Established", vrf)
    check_neigh_state(r3, "2.2.2.2", "Connect", vrf)
    check_neigh_state(r1, "2.2.2.2", "Established", vrf)
    check_neigh_state(r1, "3.3.3.3", "Established", vrf)

    r3.vtysh_cmd(
        "conf t\nrouter bgp 65003 {}\nno neighbor 2.2.2.2 password".format(vrf_str(vrf))
    )
    check_all_peers_established(vrf)


def check_vrf_peer_change_passwords(vrf="", prefix="no"):
    "selectively change passwords checking state"

    tgen = get_topogen()
    r1 = tgen.gears["R1"]
    r2 = tgen.gears["R2"]
    r3 = tgen.gears["R3"]
    check_all_peers_established(vrf)

    r1.vtysh_cmd(
        "conf t\nrouter bgp 65001 {}\nneighbor {} password change1".format(
            vrf_str(vrf), peer_name("R2", prefix, vrf)
        )
    )
    check_neigh_state(r2, "1.1.1.1", "Connect", vrf)
    check_neigh_state(r2, "3.3.3.3", "Established", vrf)
    check_neigh_state(r3, "1.1.1.1", "Established", vrf)
    check_neigh_state(r3, "2.2.2.2", "Established", vrf)
    # don't check dynamic downed peers - they are removed
    if prefix == "no":
        check_neigh_state(r1, "2.2.2.2", "Connect", vrf)
    check_neigh_state(r1, "3.3.3.3", "Established", vrf)

    r2.vtysh_cmd(
        "conf t\nrouter bgp 65002 {}\nneighbor 1.1.1.1 password change1".format(
            vrf_str(vrf)
        )
    )
    check_all_peers_established(vrf)

    r1.vtysh_cmd(
        "conf t\nrouter bgp 65001 {}\nneighbor {} password change2".format(
            vrf_str(vrf), peer_name("R3", prefix, vrf)
        )
    )
    check_neigh_state(r2, "1.1.1.1", "Established", vrf)
    check_neigh_state(r2, "3.3.3.3", "Established", vrf)
    check_neigh_state(r3, "1.1.1.1", "Connect", vrf)
    check_neigh_state(r3, "2.2.2.2", "Established", vrf)
    check_neigh_state(r1, "2.2.2.2", "Established", vrf)
    # don't check dynamic downed peers - they are removed
    if prefix == "no":
        check_neigh_state(r1, "3.3.3.3", "Connect", vrf)

    r3.vtysh_cmd(
        "conf t\nrouter bgp 65003 {}\nneighbor 1.1.1.1 password change2".format(
            vrf_str(vrf)
        )
    )
    check_all_peers_established(vrf)

    r2.vtysh_cmd(
        "conf t\nrouter bgp 65002 {}\nneighbor 3.3.3.3 password change3".format(
            vrf_str(vrf)
        )
    )
    check_neigh_state(r2, "1.1.1.1", "Established", vrf)
    check_neigh_state(r2, "3.3.3.3", "Connect", vrf)
    check_neigh_state(r3, "1.1.1.1", "Established", vrf)
    check_neigh_state(r3, "2.2.2.2", "Connect", vrf)
    check_neigh_state(r1, "2.2.2.2", "Established", vrf)
    check_neigh_state(r1, "3.3.3.3", "Established", vrf)

    r3.vtysh_cmd(
        "conf t\nrouter bgp 65003 {}\nneighbor 2.2.2.2 password change3".format(
            vrf_str(vrf)
        )
    )
    check_all_peers_established(vrf)


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
    logger.info("old R1 config:\n%s", out)
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


def test_prefix_peer_change_passwords(tgen):
    "selecively change passwords checkig state with prefix config"

    # only supported in kernel > 5.3
    if topotest.version_cmp(platform.release(), "5.3") < 0:
        return

    reset_with_new_configs(tgen, "bgpd_prefix.conf", "ospfd.conf")
    check_vrf_peer_change_passwords(prefix="yes")


def test_vrf_peer_established(tgen):
    "default vrf 3 peers same password with VRF config"

    # clean routers and load vrf config
    reset_with_new_configs(tgen, "bgpd_vrf.conf", "ospfd_vrf.conf")
    check_all_peers_established("blue")


def test_vrf_peer_remove_passwords(tgen):
    "selectively remove passwords checking state with VRF config"

    reset_with_new_configs(tgen, "bgpd_vrf.conf", "ospfd_vrf.conf")
    check_vrf_peer_remove_passwords(vrf="blue")


def test_vrf_peer_change_passwords(tgen):
    "selectively change passwords checking state with VRF config"

    reset_with_new_configs(tgen, "bgpd_vrf.conf", "ospfd_vrf.conf")
    check_vrf_peer_change_passwords(vrf="blue")


def test_vrf_prefix_peer_established(tgen):
    "default vrf 3 peers same password with VRF prefix config"

    # only supported in kernel > 5.3
    if topotest.version_cmp(platform.release(), "5.3") < 0:
        return

    reset_with_new_configs(tgen, "bgpd_vrf_prefix.conf", "ospfd_vrf.conf")
    check_all_peers_established("blue")


def test_vrf_prefix_peer_remove_passwords(tgen):
    "selectively remove passwords checking state with VRF prefix config"

    # only supported in kernel > 5.3
    if topotest.version_cmp(platform.release(), "5.3") < 0:
        return

    reset_with_new_configs(tgen, "bgpd_vrf_prefix.conf", "ospfd_vrf.conf")
    check_vrf_peer_remove_passwords(vrf="blue", prefix="yes")


def test_vrf_prefix_peer_change_passwords(tgen):
    "selectively change passwords checking state with VRF prefix config"

    # only supported in kernel > 5.3
    if topotest.version_cmp(platform.release(), "5.3") < 0:
        return

    reset_with_new_configs(tgen, "bgpd_vrf_prefix.conf", "ospfd_vrf.conf")
    check_vrf_peer_change_passwords(vrf="blue", prefix="yes")


def test_multiple_vrf_peer_established(tgen):
    "default vrf 3 peers same password with multiple VRFs"

    reset_with_new_configs(tgen, "bgpd_multi_vrf.conf", "ospfd_multi_vrf.conf")
    check_all_peers_established("blue")
    check_all_peers_established("red")


def test_multiple_vrf_peer_remove_passwords(tgen):
    "selectively remove passwords checking state with multiple VRFs"

    reset_with_new_configs(tgen, "bgpd_multi_vrf.conf", "ospfd_multi_vrf.conf")
    check_vrf_peer_remove_passwords("blue")
    check_all_peers_established("red")
    check_vrf_peer_remove_passwords("red")
    check_all_peers_established("blue")


def test_multiple_vrf_peer_change_passwords(tgen):
    "selectively change passwords checking state with multiple VRFs"

    reset_with_new_configs(tgen, "bgpd_multi_vrf.conf", "ospfd_multi_vrf.conf")
    check_vrf_peer_change_passwords("blue")
    check_all_peers_established("red")
    check_vrf_peer_change_passwords("red")
    check_all_peers_established("blue")


def test_multiple_vrf_prefix_peer_established(tgen):
    "default vrf 3 peers same password with multilpe VRFs and prefix config"

    # only supported in kernel > 5.3
    if topotest.version_cmp(platform.release(), "5.3") < 0:
        return

    reset_with_new_configs(tgen, "bgpd_multi_vrf_prefix.conf", "ospfd_multi_vrf.conf")
    check_all_peers_established("blue")
    check_all_peers_established("red")


def test_multiple_vrf_prefix_peer_remove_passwords(tgen):
    "selectively remove passwords checking state with multiple vrfs and prefix config"

    # only supported in kernel > 5.3
    if topotest.version_cmp(platform.release(), "5.3") < 0:
        return

    reset_with_new_configs(tgen, "bgpd_multi_vrf_prefix.conf", "ospfd_multi_vrf.conf")
    check_vrf_peer_remove_passwords(vrf="blue", prefix="yes")
    check_all_peers_established("red")
    check_vrf_peer_remove_passwords(vrf="red", prefix="yes")
    check_all_peers_established("blue")


def test_multiple_vrf_prefix_peer_change_passwords(tgen):
    "selectively change passwords checking state with multiple vrfs and prefix config"

    # only supported in kernel > 5.3
    if topotest.version_cmp(platform.release(), "5.3") < 0:
        return

    reset_with_new_configs(tgen, "bgpd_multi_vrf_prefix.conf", "ospfd_multi_vrf.conf")
    check_vrf_peer_change_passwords(vrf="blue", prefix="yes")
    check_all_peers_established("red")
    check_vrf_peer_change_passwords(vrf="red", prefix="yes")
    check_all_peers_established("blue")


def test_memory_leak(tgen):
    "Run the memory leak test and report results."
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
