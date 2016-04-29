from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class VLAN_Reactive(app_manager.RyuApp):
    #------- Open Flow phien ban 1.3--------
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    hosts =[{}, {}, {}]


    def __init__(self, *args, **kwargs):
        super(VLAN_Reactive, self).__init__(*args, **kwargs)
        print ("VLAN Forwarding")
        self.mac_to_port = {}
        self.topology_api_app = self


    #------Ham add flow trong vlan_test.py-----
    def _add_flow(self, dp, match, actions):
        inst = [dp.ofproto_parser.OFPInstructionActions(
            dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = dp.ofproto_parser.OFPFlowMod(
            dp, cookie=0, cookie_mask=0, table_id=0,
            command=dp.ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0xff, buffer_id=0xffffffff,
            out_port=dp.ofproto.OFPP_ANY, out_group=dp.ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


    #---------------------------Xu ly goi tin theo VLAN--------------------------
    #-------------------------------REACTIVE Mode--------------------------------
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

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        # learn a mac address to avoid FLOOD next time.
        # Hoc dia chi mac address tu port nguon
        self.mac_to_port[dpid][src] = in_port


        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port


        #----------------- Duyet VLAN roi moi add flow --------------
        #------------------------------------------------------------
        # Code cung cho cac port VLAN
        # { DPID, Port of DPID }
        # Mac dinh la cung` VLAN 1
        flag = 1
        vlan_1 = ({1,1}, {1,3}, {2,2})
        vlan_2 = ({1,2}, {2,1}, {3,1})

        i = 1
        dpid_dst = 1
        for i in (1, 2, 3):
            # Duyet 3 con switch
            if dst in self.mac_to_port[i]:
                dpid_dst = i
                out_port = self.mac_to_port[i][dst]

        dpid_src = dpid
        # dpid_dst = ?
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
            print "VLAN is not matched"
            return
        #--------------------------------------------------
        print "VLAN is matched"


        # if packet in my_flow_table
        #           forward
        # else
        #           add in flow table
        #           forward
        out_port = self.mac_to_port[dpid][dst]
        actions = [parser.OFPActionOutput(out_port)]

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.match['in_port'],
                                          actions=actions)
            datapath.send_msg(out)
            return
        #else:
            #out_port = ofproto.OFPP_FLOOD


        actions = [parser.OFPActionOutput(out_port)]
        # install a flow to avoid packet_in next time
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



        #--------Send message-------------
        datapath.send_msg(out)

