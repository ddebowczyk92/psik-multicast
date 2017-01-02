#!/bin/bash python

from ryu.base import app_manager
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib import igmplib
from ryu.ofproto import ofproto_v1_3

from ryu.topology import event
from ryu.topology.api import get_switch, get_host


class MulticastController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    switches = {}
    hosts = {}
    nodes = {}
    links = []

    def __init__(self, *args, **kwargs):
        super(MulticastController, self).__init__(*args, **kwargs)

    @set_ev_cls(event.EventSwitchEnter)
    def get_switches_data(self, ev):
        self.switches.update({ev.switch.dp.id: get_switch(self, ev.switch.dp.id)})
        self.nodes.update({ev.switch.dp.id: get_switch(self, ev.switch.dp.id)})
        self.logger.info('switch added : {0}'.format(ev.switch.dp.id))

    @set_ev_cls(event.EventHostAdd)
    def get_hosts_data(self, ev):
        self.hosts.update({ev.host.port.dpid: get_host(self, ev.host.port.dpid)})
        self.nodes.update({ev.host.port.dpid: get_host(self, ev.host.port.dpid)})
        self.logger.info('host added : {0}'.format(ev.host.port.dpid))

    @set_ev_cls(event.EventLinkAdd)
    def get_links_data(self, ev):
        self.links.append({'src': ev.link.src.dpid, 'dst': ev.link.dst.dpid})
        self.logger.info('link added: src: {0}, dst: {1}'.format(ev.link.src.dpid, ev.link.dst.dpid))

    @set_ev_cls(igmplib.EventMulticastGroupStateChanged, MAIN_DISPATCHER)
    def _status_changed(self, ev):
        msg = {
            igmplib.MG_GROUP_ADDED: 'Multicast Group Added',
            igmplib.MG_MEMBER_CHANGED: 'Multicast Group Member Changed',
            igmplib.MG_GROUP_REMOVED: 'Multicast Group Removed',
        }
        self.logger.info("%s: [%s] querier:[%s] hosts:%s",
                         msg.get(ev.reason), ev.address, ev.src,
                         ev.dsts)



