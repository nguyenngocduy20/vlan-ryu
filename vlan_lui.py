import sys
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link, get_host



class VLAN_Forward(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    hosts =[{}, {}, {}]


    def __init__(self, *args, **kwargs):
        super(VLAN_Forward, self).__init__(*args, **kwargs)
        print ("VLAN Forwarding")
        self.mac_to_port = {}
        self.topology_api_app = self

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


    #Xu ly goi tin theo VLAN
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        # MAC cua destination
        dst = eth.dst
        # MAC cua source
        src = eth.src

        # print (dst)
        # print (src)
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        # Hoc dia chi mac address tu port nguon
        self.mac_to_port[dpid][src] = in_port

        # Code cung cho cac port VLAN
        # { DPID, Port of DPID }
        # Mac dinh la cung VLAN 1
        flag = 1
        vlan_1 = ({1,1}, {1,3}, {2,2})
        vlan_2 = ({1,2}, {2,1}, {3,1})

        i = 1
        dpid_dst = 1
        for i in (1,2,3):
            #Duyet 3 con switch
            if dst in self.mac_to_port[i]:
                dpid_dst = i
                out_port = self.mac_to_port[i][dst]

        dpid_src = dpid
        #dpid_dst = ?
        # DPID Source
        tmp1 = {dpid_src, src}
        # DPID Dest
        tmp2 = {dpid_dst, dst}

        if tmp1 in vlan_2:
            flag = 2

        forward = False
        if flag == 1:
            if tmp2 in vlan_1:
                forward = True
        else:
            if tmp2 in vlan_2:
                forward = True

        if forward == False:
            return

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)

        ip = pkt.get_protocols(ipv4.ipv4)
        if len(ip) > 0:
            for p in pkt:
                # print p.protocol_name
                if p.protocol_name == "icmp":
                    sys.stdout.write('\nOpenFlow Protocol:\n')
                    print "Protocol: " + p.protocol_name
                    print 'Begin loop'
                    for p in ip:
                        print 'Source:  \t' + src + '\tIP: ' + p.src + '\tIn_port: ' + str(in_port) + "\tDPID: ", dpid
                        print 'Dest:    \t' + dst + '\tIP: ' + p.dst
                    print 'End of loop'
        datapath.send_msg(out)

    # Global Variable
    switches = 0
    links = 0
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        print "Beep!"
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        # host_list = get_host(self.topology_api_app, None)
        # hosts = [host.dp.id for host in host_list]
        # print i
        print switches
        print links
        # print 'Beep!!\n'
        # i += 1
