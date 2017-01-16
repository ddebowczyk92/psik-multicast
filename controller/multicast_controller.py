#!/bin/bash python
import logging
import networkx as nx

from ryu.app.ofctl import api
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.lib.packet import (ethernet, igmp, lldp, ipv4, packet, udp)
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_switch, get_host

JOIN_GROUP_CODE = 4
LEAVE_GROUP_CODE = 3


class MulticastController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    switches = {}
    hosts = {}
    nodes = {}
    skeleton_links = []
    links = []
    groups = {}
    dpid_to_port = {}
    group_objects = {}

    def __init__(self, *args, **kwargs):
        super(MulticastController, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

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
                if group_address not in self.groups.keys():
                    self.logger.info('new multicast group created: {0}'.format(group_address))
                    self.groups.setdefault(group_address, [])
                    self.group_objects.update({group_address:
                                                   MulticastGroup(group_address, self.links, self.dpid_to_port)})

                if ipv4_src not in self.groups[group_address]:
                    self.groups[group_address].append(ipv4_pkt.src)
                    self.logger.info('groups: {0}'.format(self.groups))
                    self.logger.info('groups: {0}'.format(self.group_objects))
                    group = self.group_objects[group_address]
                    group.join_host(ipv4_src, datapath.id, in_port)
                    if group.has_source():
                        self.add_group_flows(parser, ofproto, group.get_group_entries())

        else:
            udp_pkt = pkt.get_protocol(udp.udp)
            if not udp_pkt:
                return
            self.logger.info('reveived udp packet: {0}'.format(udp_pkt))
            if ipv4_src not in self.hosts.keys():
                self.hosts.setdefault(ipv4_src, None)
                self.links.append((ipv4_src, datapath.id))
                self.links.append((datapath.id, ipv4_src))
                self.dpid_to_port[datapath.id][ipv4_src] = in_port
                self.dpid_to_port.setdefault(ipv4_src, {})
                self.dpid_to_port[ipv4_src][datapath.id] = in_port
                if ipv4_dst in self.group_objects.keys():
                    group = self.group_objects[ipv4_dst]
                    group.set_source_address(ipv4_src, datapath.id, in_port)
                    self.add_group_flows(parser, ofproto, group.get_group_entries())
                    # graph = nx.Graph()
                    # graph.add_edges_from(self.links)
                    #
                    # shortest_path = nx.shortest_path(graph, ipv4_pkt.src, self.groups[ipv4_pkt.dst][0])
                    # self.logger.info('shortest_path: {0}'.format(shortest_path))
                    # for node in shortest_path[1:-1]:
                    #     index = shortest_path.index(node)
                    #     prev_node = shortest_path[index - 1]
                    #     next_node = shortest_path[index + 1]
                    #     switch_dp = api.get_datapath(self, node)
                    #     input_port = self.dpid_to_port[node][prev_node]
                    #     output_port = self.dpid_to_port[node][next_node]
                    #     self.logger.info(self.dpid_to_port)
                    #     self.logger.info("node: {0}, input: {1}, output: {2}".format(node, input_port, output_port))
                    #     match = parser.OFPMatch(in_port=input_port, eth_type=0x800,
                    #                             ipv4_dst=ipv4_pkt.dst)
                    #     actions = [parser.OFPActionOutput(output_port)]
                    #     inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                    #                                          actions)]
                    #     mod = parser.OFPFlowMod(datapath=switch_dp, priority=1,
                    #                             match=match, instructions=inst)
                    #     switch_dp.send_msg(mod)

        pass

    def add_group_flows(self, parser, ofproto, group_entries):
        for dpid in group_entries:

            ports = group_entries[dpid]
            for port in ports:
                entry = ports[port]
                if entry:
                    self.logger.info('entry: {0}'.format(entry))
                    entry_match = entry['match']
                    datapath = api.get_datapath(self, dpid)
                    match = parser.OFPMatch(in_port=entry_match['in_port'], eth_type=entry_match['eth_type'],
                                            ipv4_dst=entry_match['ipv4_dst'])
                    actions = [parser.OFPActionOutput(output_port) for output_port in entry['actions_output_ports']]
                    buckets = [parser.OFPBucket(actions=actions)]
                    req_group = parser.OFPGroupMod(datapath=datapath, command=ofproto.OFPGC_ADD,
                                                   type_=ofproto.OFPGT_ALL, group_id=entry['group_id'], buckets=buckets)
                    inst = [
                        parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                     [parser.OFPActionGroup(group_id=entry['group_id'])])]
                    req_flow = parser.OFPFlowMod(datapath=datapath, priority=1, match=match, instructions=inst)
                    datapath.send_msg(req_group)
                    datapath.send_msg(req_flow)

    @set_ev_cls(event.EventSwitchEnter)
    def get_switches_data(self, ev):
        self.switches.update({ev.switch.dp.id: get_switch(self, ev.switch.dp.id)})
        self.nodes.update({ev.switch.dp.id: get_switch(self, ev.switch.dp.id)})
        self.logger.info('switch added : {0}'.format(ev.switch.dp.id))

    @set_ev_cls(event.EventHostAdd)
    def get_hosts_data(self, ev):
        hosts = get_host(self, ev.host.port.dpid)

        for host in hosts:
            ipv4 = host.ipv4[0]
            if ipv4 not in self.hosts:
                dpid = ev.host.port.dpid
                port_no = ev.host.port.port_no
                self.hosts.update({ipv4: host})
                self.links.append((ipv4, dpid))
                self.links.append((dpid, ipv4))
                self.dpid_to_port[dpid][ipv4] = port_no
                self.dpid_to_port.setdefault(ipv4, {})
                self.dpid_to_port[ipv4][dpid] = port_no
                self.logger.info('host added: ' + ipv4)

    @set_ev_cls(event.EventLinkAdd)
    def get_links_data(self, ev):
        dpid_src = ev.link.src.dpid
        dpid_dst = ev.link.dst.dpid
        port_no = ev.link.src.port_no
        self.dpid_to_port.setdefault(ev.link.src.dpid, {})
        self.dpid_to_port[dpid_src][dpid_dst] = port_no
        self.skeleton_links.append((ev.link.src.dpid, ev.link.dst.dpid))
        self.links.append((ev.link.src.dpid, ev.link.dst.dpid))
        self.logger.info('link added: src: {0}, dst: {1}'.format(ev.link.src.dpid, ev.link.dst.dpid))


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
        self.network = network
        self.dpid_to_port = dpid_to_port
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

    def generate_flow_entry(self, dst_address):
        path = self._shortest_paths[dst_address]
        for node in path[1:-1]:
            index = path.index(node)
            prev_node = path[index - 1]
            next_node = path[index + 1]
            input_port = self.dpid_to_port[node][prev_node]
            output_port = self.dpid_to_port[node][next_node]
            self.logger.info(self.dpid_to_port)
            if input_port not in self._group_entries[node]:
                self._group_entries[node][input_port] = {
                    'group_id': index,
                    'match': {
                        'in_port': input_port,
                        'eth_type': 0x800,
                        'ipv4_dst': self.multicast_group_address
                    },
                    'actions_output_ports': set([output_port])
                }
            else:
                self._group_entries[node][input_port]['actions_output_ports'].add(output_port)
        self.logger.info('group_entries: {0}'.format(self._group_entries))

    def update_shortest_paths(self, dst_address):
        self._shortest_paths.update({dst_address: nx.shortest_path(self._graph, self._source_address, dst_address)})
        self.logger.info('shortest paths: {0}'.format(self._shortest_paths))

    def update_network_data(self, host_address, switch_dpid, port):
        self._graph.add_edge(switch_dpid, host_address)
        self._graph.add_edge(host_address, switch_dpid)
        self.dpid_to_port[switch_dpid][host_address] = port
        self.dpid_to_port.setdefault(host_address, {})
        self.dpid_to_port[host_address][switch_dpid] = port

    def get_host_addresses(self):
        return self._host_adresses

    def get_group_entries(self):
        return self._group_entries

    def has_source(self):
        return self._source_address is not None


class FlowEntry:
    def __init__(self, dpid, priority=1):
        self._dpid = dpid
        self._priority = priority
        self._matches = {}
        self._actions = []

    def addMatch(self, field, value):
        self._matches[field] = value

    def addAction(self, action, **params):
        action = {'type': action}
        for key in params:
            action[key] = params[key]
        self._actions.append(action)


class GroupEntry:
    def __init__(self, dpid, grpid, grptype):
        self._dpid = dpid
        self._grpid = grpid
        self._type = grptype
        self._buckets = []

    def add_bucket(self, weight=0):
        self._buckets.append({'weight': weight, 'actions': []})

    def add_action(self, bucket, action, **params):
        if bucket > len(self._buckets):
            raise Exception
        action = {'type', action}
        for key in params:
            action[key] = params[key]
        self._buckets[bucket]['actions'].append(action)
