# Ray Grant u1168200 CS4480
#
# The skeleton of this code is form this tutorial: http://sdnhub.org/tutorials/ryu/
# with a licensing of http://www.apache.org/licenses/LICENSE-2.0
#


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ethernet, arp, packet, ipv4, ipv6, icmp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu import cfg



class Monitor2(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    package_count = 0
    backend_reached_count = 0

    def __init__(self, *args, **kwargs):
        super(Monitor2, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.package_count = 0
        self.backend_reached_count = 0

        CONF = cfg.CONF
        CONF.register_opts([
            cfg.IntOpt('front_end_testers', default=4, help=('Number of Front End Testers')),
            cfg.IntOpt('back_end_servers', default=2, help=('Number of Back End Testers')),
            cfg.StrOpt('virtual_ip', default='10.0.0.10', help=('Virtual IP address'))
        ])

        self.front_end_testers = CONF.front_end_testers
        self.back_end_servers = CONF.back_end_servers
        self.virtual_ip = CONF.virtual_ip
        self.next_out = self.front_end_testers


    def get_mac_from_num(self, optimal_number):


        if optimal_number < 10:
            mac_address = '00:00:00:00:00:0' + str(optimal_number)
        else:
            mac_address = '00:00:00:00:00:' + str(optimal_number)

        return mac_address

    def get_optimal_server_number(self):
        server_count = self.back_end_servers
        client_count = self.front_end_testers

        optimal_number = client_count + 1 + (self.backend_reached_count % server_count)

        return optimal_number





    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print("switch features handler")
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
        print("in add flow +++")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            print("flow info:")
            print("match:", match)
            print("actions: ", actions)
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        print("sending mod...")
        print(mod)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg  # Object representing a packet_in data structure.
        datapath = msg.datapath  # Switch Datapath ID
        ofproto = datapath.ofproto  # OpenFlow Protocol version the entities negotiated. In our case OF1.3
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_info = pkt.get_protocol(arp.arp)
        ipv4_info = pkt.get_protocol(ipv4.ipv4)
        ipv6_info = pkt.get_protocol(ipv6.ipv6)
        icmp_info = pkt.get_protocol(icmp.icmp)
        self.package_count += 1

        protocol_list = []
        for p in pkt.protocols:
            protocol_list.append(p.protocol_name)

        print("---------------------------------------------------")
        print("Packet ({}) Received on Port({}): {}".format(self.package_count, in_port, protocol_list))



        if arp_info:
            print(" ARP")
            print("     From IP: {}".format(arp_info.src_ip))
            print("     To   IP: {}".format(arp_info.dst_ip))
            print("     From Mac: {}".format(arp_info.src_mac))
            print("     To   Mac: {}".format(arp_info.dst_mac))

            print("ARP Request who-has {} tell {}".format(arp_info.dst_ip, arp_info.src_ip))
            print("ARP Reply {} is-at {}".format(arp_info.dst_ip, self.back_end_servers))

        if ipv4_info:
            print(" IPV4")
            print("     Check Sum: {}".format(ipv4_info.csum))
            print("     From   IP: {}".format(ipv4_info.src))
            print("     To     IP: {}".format(ipv4_info.dst))
            print("     Length   : {}".format(ipv4_info.total_length))
        else:
            print(" Not IPV4")

        if ipv6_info:
            print(" IPV6")
            print("  Version: {}".format(ipv6_info.version))
            print("  From   IP: {}".format(ipv6_info.src))
            print("  To     IP: {}".format(ipv6_info.dst))
            print("  Length   : {}".format(ipv6_info.payload_length))
        else:
            print(" Not IPV6")

        if icmp_info:
            print(" PING")

        if eth:

            print(" ETH")

            print("  From Mac: {}".format(eth.src))
            print("  To   Mac: {}".format(eth.dst))

        print(" Controller Switch (OF)")

        print("  Address, Port: {}".format(datapath.address))

        print("")


        # this next part is apart of future code...
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
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            print("dst in mac to port")
        else:
            out_port = ofproto.OFPP_FLOOD
            print("FLOODING THE PORTS!!!!!!!!!!!!!")


        if arp_info and arp_info.dst_ip == self.virtual_ip:
            #dst = arp_info.dst_ip
            print("!@#$%^& YA! we hot a virtual port request")
            out_port = self.get_optimal_server_number()
            dst = self.get_mac_from_num(out_port)
            self.backend_reached_count += 1

            # send arp request to host
            actions = [parser.OFPActionOutput(in_port)]
            arp_reply = packet.Packet()
            arp_reply.add_protocol(
                ethernet.ethernet(
                    ethertype=ether_types.ETH_TYPE_ARP,
                    src=dst,
                    dst=arp_info.src_mac
                )
            )
            print()
            print("arp_info.dst_mac", dst)
            print("arp_info.src_mac", arp_info.src_mac)
            print()
            arp_reply.add_protocol(
                arp.arp(
                    opcode=arp.ARP_REPLY,
                    src_ip=arp_info.dst_ip,
                    src_mac=dst,
                    dst_ip=arp_info.src_ip,
                    dst_mac=arp_info.src_mac
                )
            )
            arp_reply.serialize()

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions, data=arp_reply.data)

            datapath.send_msg(out)
        else:
            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                print("Push OF rules on s1:")
                print("match:")
                print("inport={}, dst-ip={}".format(in_port, dst))
                print("action:")
                print("set: dst-ip={}".format(dst))
                print("set: outport={}".format(out_port))
                print("")
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

            if arp_info:
                print("ARP Reply {} is-at {}".format(arp_info.dst_ip, dst))

            print("out = ", out)

            datapath.send_msg(out)





