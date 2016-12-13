#!bin/bash/env python

from mininet.topo import Topo


class MulticastTopology(Topo):
    def __init__(self, *args, **params):
        super(MulticastTopology, self).__init__(*args, **params)

        serv1 = self.addHost('serv1', ip='10.0.0.1')
        serv2 = self.addHost('serv2', ip='10.0.0.1')

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')

        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')
        h7 = self.addHost('h7')

        self.addLink(serv1, s1)
        self.addLink(serv2, s1)

        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s1, s5)

        self.addLink(s2, s3)
        self.addLink(s2, h7)

        self.addLink(s3, s4)
        self.addLink(s3, h3)
        self.addLink(s3, h4)

        self.addLink(s4, h5)
        self.addLink(s4, h6)

        self.addLink(s5, s4)


topos = {'multicasttopo': (lambda: MulticastTopology())}
