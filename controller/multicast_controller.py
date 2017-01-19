#!/bin/bash python

import logging
import networkx as nx

from ryu.app.ofctl import api
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.lib.packet import (igmp, lldp, ipv4, packet, udp)
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_switch, get_host

JOIN_GROUP_CODE = 4
LEAVE_GROUP_CODE = 3


class MulticastController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _switches = {}
    _hosts = {}
    _links = []
    _groups = {}
    _dpid_to_port = {}
    _group_objects = {}
    _group_ids = {}
    _group_ids_gen = {}

    def __init__(self, *args, **kwargs):
        super(MulticastController, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        lldp_pkt = pkt.get_protocol(lldp.lldp)
        if lldp_pkt:
            return

        ipv4_pkt = pkt.get_protocols(ipv4.ipv4)[0]
        ipv4_src = ipv4_pkt.src
        ipv4_dst = ipv4_pkt.dst
        req_igmp = pkt.get_protocol(igmp.igmp)
        if req_igmp:
            self.logger.info(req_igmp)
            igmpv3_report = req_igmp.records[0]
            group_address = igmpv3_report.address
            if igmpv3_report.type_ is JOIN_GROUP_CODE:
                if group_address not in self._groups:
                    self._groups.setdefault(group_address, [])
                    self._group_objects.update({group_address:
                                                    MulticastGroup(group_address, self._links, self._dpid_to_port)})

                if ipv4_src not in self._groups[group_address]:
                    self._groups[group_address].append(ipv4_pkt.src)
                    group = self._group_objects[group_address]
                    group.join_host(ipv4_src, datapath.id, in_port)
                    if group.has_source():
                        self.add_group_flows(parser, ofproto, group.get_group_entries())

            elif igmpv3_report.type_ is LEAVE_GROUP_CODE:
                if group_address in self._groups and ipv4_src in self._groups[group_address]:
                    self._groups[group_address].remove(ipv4_src)
                    group = self._group_objects[group_address]
                    group.leave_group(ipv4_src, datapath.id)

        else:
            udp_pkt = pkt.get_protocol(udp.udp)
            if not udp_pkt:
                return
            self.logger.info('reveived udp packet: {0}'.format(udp_pkt))
            if ipv4_src not in self._hosts.keys():
                self._hosts.setdefault(ipv4_src, None)
                self._links.append((ipv4_src, datapath.id))
                self._links.append((datapath.id, ipv4_src))
                self._dpid_to_port[datapath.id][ipv4_src] = in_port
                self._dpid_to_port.setdefault(ipv4_src, {})
                self._dpid_to_port[ipv4_src][datapath.id] = in_port
                if ipv4_dst in self._group_objects.keys():
                    group = self._group_objects[ipv4_dst]
                    group.set_source_address(ipv4_src, datapath.id, in_port)
                    self.add_group_flows(parser, ofproto, group.get_group_entries(), msg)

                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                              in_port=in_port, data=data, actions=[])
                    datapath.send_msg(out)

        pass

    @set_ev_cls(event.EventSwitchEnter)
    def get_switches_data(self, ev):
        dp_id = ev.switch.dp.id
        self._switches.update({dp_id: get_switch(self, dp_id)})
        self._group_ids_gen[dp_id] = 1
        self._group_ids.setdefault(dp_id, {})
        self.logger.info('switch added : {0}'.format(dp_id))

    @set_ev_cls(event.EventHostAdd)
    def get_hosts_data(self, ev):
        hosts = get_host(self, ev.host.port.dpid)

        for host in hosts:
            ipv4 = host.ipv4[0]
            if ipv4 not in self._hosts:
                dpid = ev.host.port.dpid
                port_no = ev.host.port.port_no
                self._hosts.update({ipv4: host})
                self._links.append((ipv4, dpid))
                self._links.append((dpid, ipv4))
                self._dpid_to_port[dpid][ipv4] = port_no
                self._dpid_to_port.setdefault(ipv4, {})
                self._dpid_to_port[ipv4][dpid] = port_no
                self.logger.info('host added: ' + ipv4)

    @set_ev_cls(event.EventLinkAdd)
    def get_links_data(self, ev):
        dpid_src = ev.link.src.dpid
        dpid_dst = ev.link.dst.dpid
        port_no = ev.link.src.port_no
        self._dpid_to_port.setdefault(ev.link.src.dpid, {})
        self._dpid_to_port[dpid_src][dpid_dst] = port_no
        self._links.append((ev.link.src.dpid, ev.link.dst.dpid))
        self.logger.info('link added: src: {0}, dst: {1}'.format(ev.link.src.dpid, ev.link.dst.dpid))

    def add_group_flows(self, parser, ofproto, group_entries, msg):
        for dpid in group_entries:
            ports = group_entries[dpid]
            for port in ports:
                entry = ports[port]
                if entry:
                    self.logger.info('entry: {0}'.format(entry))
                    entry_match = entry['match']
                    datapath = api.get_datapath(self, dpid)
                    group_mod_type = ofproto.OFPGC_ADD
                    group_id = None
                    if entry_match['ipv4_dst'] in self._group_ids[dpid]:
                        group_id = self._group_ids[dpid][entry_match['ipv4_dst']]
                        group_mod_type = ofproto.OFPGC_MODIFY
                    else:
                        group_id = self.get_next_group_id(dpid, entry_match['ipv4_dst'])

                    match = parser.OFPMatch(in_port=entry_match['in_port'], eth_type=entry_match['eth_type'],
                                            ipv4_dst=entry_match['ipv4_dst'])
                    actions = [parser.OFPActionOutput(output_port) for output_port in entry['actions_output_ports']]
                    buckets = [parser.OFPBucket(actions=[action]) for action in actions]
                    req_group = parser.OFPGroupMod(datapath=datapath, command=ofproto.OFPGC_ADD,
                                                   type_=group_mod_type, group_id=group_id, buckets=buckets)
                    inst = [
                        parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                     [parser.OFPActionGroup(group_id=group_id)])]
                    req_flow = parser.OFPFlowMod(datapath=datapath, priority=1, match=match, instructions=inst)
                    datapath.send_msg(req_group)
                    datapath.send_msg(req_flow)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def get_next_group_id(self, dp_id, group_address):
        group_id = self._group_ids_gen[dp_id]
        self._group_ids_gen[dp_id] = group_id + 1
        self._group_ids[dp_id][group_address] = group_id
        return group_id


class MulticastGroup:
    _source_address = None
    _graph = nx.Graph()
    _shortest_paths = {}
    _host_adresses = []
    _group_entries = {}

    def __init__(self, multicast_group_address, network, dpid_to_port):
        self.name = self.__class__.__name__
        self.logger = logging.getLogger(self.name)
        self.multicast_group_address = multicast_group_address
        self._dpid_to_port = dpid_to_port
        self._graph.add_edges_from(network)
        for node in self._graph.nodes():
            self._group_entries.setdefault(node, {})
        self.logger.info('new multicast group object created: {0}'.format(multicast_group_address))

    def set_source_address(self, source_address, switch_dpid, port):
        if not self._source_address:
            self._source_address = source_address
            self.logger.info('multicast group: {0}, source address set: {1}'.format(self.multicast_group_address,
                                                                                    self._source_address))
            self.update_network_data(source_address, switch_dpid, port)
        else:
            raise Exception
        for host_address in self._host_adresses:
            self.update_shortest_paths(host_address)
            self.generate_flow_entry(host_address)

    def join_host(self, dst_address, switch_dpid, port):
        if dst_address not in self._host_adresses:
            self._host_adresses.append(dst_address)
            self.update_network_data(dst_address, switch_dpid, port)
            if self._source_address:
                self.update_shortest_paths(dst_address)
                self.generate_flow_entry(dst_address)
            self.logger.info('host {0} joined group {1}'.format(dst_address, self.multicast_group_address))

    def leave_group(self, dst_address, switch_dpid):
        if dst_address in self._host_adresses:
            self.delete_flow_entry(dst_address)
            self._host_adresses.remove(dst_address)
            self.delete_host_from_network(dst_address, switch_dpid)
            self.logger.info('host {0} left group {1}'.format(dst_address, self.multicast_group_address))

    def generate_flow_entry(self, dst_address):
        path = self._shortest_paths[dst_address]
        for node in path[1:-1]:
            index = path.index(node)
            prev_node = path[index - 1]
            next_node = path[index + 1]
            input_port = self._dpid_to_port[node][prev_node]
            output_port = self._dpid_to_port[node][next_node]
            if input_port not in self._group_entries[node]:
                self._group_entries[node][input_port] = {
                    'match': {
                        'in_port': input_port,
                        'eth_type': 0x800,
                        'ipv4_dst': self.multicast_group_address
                    },
                    'actions_output_ports': set([output_port])
                }
            else:
                self._group_entries[node][input_port]['actions_output_ports'].add(output_port)

    def delete_flow_entry(self, dst_address):
        path = self._shortest_paths[dst_address]
        for node in path[1:-1]:
            index = path.index(node)
            prev_node = path[index - 1]
            next_node = path[index + 1]
            input_port = self._dpid_to_port[node][prev_node]
            output_port = self._dpid_to_port[node][next_node]
            if output_port in self._group_entries[node][input_port]['actions_output_ports']:
                self._group_entries[node][input_port]['actions_output_ports'].remove(output_port)

    def update_shortest_paths(self, dst_address):
        self._shortest_paths.update({dst_address: nx.shortest_path(self._graph, self._source_address, dst_address)})

    def update_network_data(self, host_address, switch_dpid, port):
        self._graph.add_edge(switch_dpid, host_address)
        self._graph.add_edge(host_address, switch_dpid)
        self._dpid_to_port[switch_dpid][host_address] = port
        self._dpid_to_port.setdefault(host_address, {})
        self._dpid_to_port[host_address][switch_dpid] = port

    def delete_host_from_network(self, host_address, switch_dpid):
        self._graph.remove_node(host_address)
        self._dpid_to_port[switch_dpid][host_address] = None
        self._dpid_to_port[host_address][switch_dpid] = None

    def get_host_addresses(self):
        return self._host_adresses

    def get_group_entries(self):
        return self._group_entries

    def has_source(self):
        return self._source_address is not None
