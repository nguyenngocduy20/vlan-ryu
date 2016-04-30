from ryu.base import app_manager
from ryu.ofproto import ether, ofproto_v1_3, inet
from ryu.controller import dpset, ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.lib.mac import haddr_to_str
import logging
import struct

logger = logging.getLogger(__name__)

# static VLAN Ethertypes for testing
VLAN_TAG_802_1Q = 0x8100  
BRIDGE_TAG_802_1AD = 0x88A8
        
class VLan_Proactive(app_manager.RyuApp):
    _CONTEXTS = {'dpset': dpset.DPSet}
    # Set version 1.3 Open Flow
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    # switch = { port_no:vlan ...}
    # vlan 3 = trunk
    switch1 = {1    :   1, 2   :   2, 3    :   1
        , 4   :   3}
    switch2 = {1    :   2, 2   :   1
        , 3    :   3, 4     :   3}
    switch3 = {1    :   2
        , 2   :   3}

    def __init__(self, *_args, **_kvargs):
       super(VLan_Proactive, self).__init__(*_args, **_kvargs)

    '''
    Add  a new flow entry to the the switch flow table
    '''
    def _add_flow(self, datapath, match, actions, priority, buffer_id=None):
        # apply "actions" actions
        inst = [datapath.ofproto_parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # mod = datapath.ofproto_parser.OFPFlowMod(
        #     datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
        #     command=datapath.ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
        #     priority=0xff, buffer_id=0xffffffff,
        #     out_port=datapath.ofproto.OFPP_ANY, out_group=datapath.ofproto.OFPG_ANY,
        #     flags=0, match=match, instructions=inst)
        if buffer_id:
            mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, command=datapath.ofproto.OFPFC_ADD,buffer_id=buffer_id,
                                    priority=priority,  out_port=datapath.ofproto.OFPP_ANY, out_group=datapath.ofproto.OFPG_ANY, match=match,
                                    instructions=inst)
        else:
            mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, command=datapath.ofproto.OFPFC_ADD,buffer_id=0xffffffff,priority=priority,
                                                     out_port=datapath.ofproto.OFPP_ANY,
                                                     out_group=datapath.ofproto.OFPG_ANY,match=match, instructions=inst)
        datapath.send_msg(mod)

    def build_match(self, datapath, port):
        match = datapath.ofproto_parser.OFPMatch()
        match.set_in_port(port)
        match.set_dl_type(ether.ETH_TYPE_IP)
        return match

    '''
    VLAN
    Add 801.2Q tag
    Ethertype: 0x8100
    '''
    def tag_vlan(self, port, vlan_id, datapath):
        match = self.build_match(datapath, port)
        match.set_vlan_vid(vlan_id)

        field = datapath.ofproto_parser.OFPMatchField.make(
            datapath.ofproto.OXM_OF_VLAN_VID, vlan_id)

        actions = [datapath.ofproto_parser.OFPActionPushVlan(VLAN_TAG_802_1Q),
                   datapath.ofproto_parser.OFPActionSetField(field)]
        self._add_flow(datapath, match, actions, 1)

    
    '''
    TRUNK
    Add 801.1AD tag
    Ethertype: 0x88a8
    '''
    def tag_trunk(self, port, trunk_id, datapath):
        match = self.build_match(datapath, port)
                
        actions = [datapath.ofproto_parser.OFPActionPushVlan(BRIDGE_TAG_802_1AD)]
        self._add_flow(datapath, match, actions, 1)

    ##########################################################
    def install_vlans_flow(self, datapath):
        # Static value switch ports
        trunk_id = 4
        print "Switch ID: ", datapath.id
        if datapath.id is 1:
            list = self.switch1.items()
        elif datapath.id is 2:
            list = self.switch2.items()
        else:
            list = self.switch3.items()

        for port_no, vlan_id in (list):
            if vlan_id is not 3:
                self.tag_vlan(port_no, vlan_id, datapath )
            # else:
            #     self.tag_trunk(port_no, trunk_id, datapath)
        logger.info("")
    
    '''
    Install DataPath event dispatcher to invoke this method,
    anytime there's event dispatched to the DataPath from controller.
    '''
    #@set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    #@set_ev_cls(dpset.EventDP, CONFIG_DISPATCHER)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def handler_datapath(self, event):
        datapath = event.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        # Worst Flow : ask controller.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, match, actions, 0)

        req = parser.OFPDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

        # VLAN
        logger.info("++++++ Installing VLAN ++++++")
        self.install_vlans_flow(datapath)

        # @set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER)
        # def desc_stats_reply_handler(self, ev):
        #
        #     body = ev.msg.body
        #     # VLAN

