#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import flow_manager


def run():
    net = Mininet(
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )

    info("*** Adding hosts\n")
    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")

    info("*** Adding an OpenFlow 1.3 switch\n")
    s1 = net.addSwitch(
        "s1",
        protocols="OpenFlow13",
        failMode="secure"
    )

    info("*** Creating links\n")
    net.addLink(h1, s1)
    net.addLink(h2, s1)

    info("*** Starting network\n")
    net.start()

    info("*** Initializing default-drop policy\n")
    flow_manager.initialize()

    info("*** Network ready. Entering Mininet CLI.\n")
    info("*** Type 'exit' to stop the network.\n")
    CLI(net)

    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()
