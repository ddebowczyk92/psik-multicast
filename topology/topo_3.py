#!/usr/bin/python
# author: Rafal Rzatkiewicz
# custom topology run in mininet

from mininet.cli import CLI
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.net import Mininet


def my_net():
    'Create network and add nodes to it.'

    net = Mininet(controller=RemoteController, link=TCLink,
                  switch=OVSKernelSwitch)

    info('*** Adding controller\n')
    c0 = net.addController('c0', controller=RemoteController, ip="192.168.56.1", port=6633, autoSetMacs=True,
                           xterms=True)

    info('*** Adding hosts\n')
    serv1 = net.addHost('serv1', ip='10.0.0.1', mac='00:00:00:00:00:06')
    serv2 = net.addHost('serv2', ip='10.0.0.2', mac='00:00:00:00:00:07')
    h3 = net.addHost('h3', ip='10.0.0.3', mac='00:00:00:00:00:08')
    h4 = net.addHost('h4', ip='10.0.0.4', mac='00:00:00:00:00:09')
    h5 = net.addHost('h5', ip='10.0.0.5', mac='00:00:00:00:00:10')
    h6 = net.addHost('h6', ip='10.0.0.6', mac='00:00:00:00:00:11')
    h7 = net.addHost('h7', ip='10.0.0.7', mac='00:00:00:00:00:12')

    info('*** Adding switch\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13', mac='00:00:00:00:00:01')
    s2 = net.addSwitch('s2', protocols='OpenFlow13', mac='00:00:00:00:00:02')
    s3 = net.addSwitch('s3', protocols='OpenFlow13', mac='00:00:00:00:00:03')
    s4 = net.addSwitch('s4', protocols='OpenFlow13', mac='00:00:00:00:00:04')
    s5 = net.addSwitch('s5', protocols='OpenFlow13', mac='00:00:00:00:00:05')

    info('*** Creating links\n')
    net.addLink(serv1, s1)
    net.addLink(serv2, s1)

    net.addLink(s1, s2)
    net.addLink(s1, s3)
    net.addLink(s1, s5)

    net.addLink(s2, s3)
    net.addLink(s2, h7)

    net.addLink(s3, s4)
    net.addLink(s3, h3)
    net.addLink(s3, h4)

    net.addLink(s4, h5)
    net.addLink(s4, h6)

    net.addLink(s5, s4)

    info('*** Starting network\n')
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    s4.start([c0])
    s5.start([c0])

    # cmd = ["socat", "UDP4-RECVFROM:1234,ip-add-membership=239.192.0.1:10.0.0.3"]
    # h3.popen(cmd)
    # lldp_command = 'python /media/sf_psik-multicast/packet/lldp_generator.py {0} {1}'
    # h3.cmdPrint(lldp_command.format('h3-eth0', '00:00:00:00:00:08'))

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    my_net()
