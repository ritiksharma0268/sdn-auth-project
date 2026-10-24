#!/usr/bin/python3

import json
import socketserver
import threading

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from os_ken.ofproto import ofproto_v1_3


HOSTS = {
    "alice": {"ip": "10.0.0.1", "mac": "00:00:00:00:00:01", "port": 1},
    "bob":   {"ip": "10.0.0.2", "mac": "00:00:00:00:00:02", "port": 2},
}


class SDNController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.flow_lock = threading.Lock()
        self.control_server = None
        self.control_thread = None
        self.logger.info("SDN authentication controller initialized")

    def start(self):
        super(SDNController, self).start()
        controller = self

        class RequestHandler(socketserver.StreamRequestHandler):
            def handle(self):
                try:
                    line = self.rfile.readline(4096)
                    request = json.loads(line.decode("utf-8"))
                    action = request.get("action")
                    username = request.get("username")

                    if action not in ("grant", "revoke") or username not in HOSTS:
                        response = {"ok": False, "message": "Invalid request"}
                    else:
                        response = controller.change_access(action, username)

                    self.wfile.write(
                        (json.dumps(response) + "\n").encode("utf-8")
                    )
                except Exception as exc:
                    controller.logger.exception("Control request failed")
                    self.wfile.write(
                        (json.dumps({"ok": False, "message": str(exc)}) + "\n").encode("utf-8")
                    )

        class ThreadedServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self.control_server = ThreadedServer(("127.0.0.1", 5051), RequestHandler)
        self.control_thread = threading.Thread(
            target=self.control_server.serve_forever,
            daemon=True,
        )
        self.control_thread.start()
        self.logger.info("Authentication control API listening on 127.0.0.1:5051")

    def stop(self):
        if self.control_server:
            self.control_server.shutdown()
            self.control_server.server_close()
        super(SDNController, self).stop()

    def change_access(self, action, username):
        host = HOSTS[username]
        other_name = "bob" if username == "alice" else "alice"
        other = HOSTS[other_name]

        with self.flow_lock:
            datapath = next(iter(self.datapaths.values()), None)
            if datapath is None:
                return {"ok": False, "message": "No switch connected"}

            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto

            # These rules authorize the authenticated host's connection
            # to its peer, including the peer's return traffic.
            rules = [
                (
                    parser.OFPMatch(
                        in_port=host["port"],
                        eth_src=host["mac"],
                        eth_type=0x0800,
                        ipv4_src=host["ip"],
                        ipv4_dst=other["ip"],
                    ),
                    other["port"],
                ),
                (
                    parser.OFPMatch(
                        in_port=other["port"],
                        eth_src=other["mac"],
                        eth_type=0x0800,
                        ipv4_src=other["ip"],
                        ipv4_dst=host["ip"],
                    ),
                    host["port"],
                ),
                (
                    parser.OFPMatch(
                        in_port=host["port"],
                        eth_src=host["mac"],
                        eth_type=0x0806,
                    ),
                    other["port"],
                ),
                (
                    parser.OFPMatch(
                        in_port=other["port"],
                        eth_src=other["mac"],
                        eth_type=0x0806,
                    ),
                    host["port"],
                ),
            ]

            if action == "grant":
                for match, output_port in rules:
                    instructions = [
                        parser.OFPInstructionActions(
                            ofproto.OFPIT_APPLY_ACTIONS,
                            [parser.OFPActionOutput(output_port)],
                        )
                    ]
                    datapath.send_msg(parser.OFPFlowMod(
                        datapath=datapath,
                        priority=100,
                        match=match,
                        instructions=instructions,
                    ))
            else:
                for match, _output_port in rules:
                    datapath.send_msg(parser.OFPFlowMod(
                        datapath=datapath,
                        command=ofproto.OFPFC_DELETE_STRICT,
                        out_port=ofproto.OFPP_ANY,
                        out_group=ofproto.OFPG_ANY,
                        priority=100,
                        match=match,
                    ))

        self.logger.info("Access %s requested for %s", action, username)
        return {
            "ok": True,
            "message": f"Access {action} processed for {username}",
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=parser.OFPMatch(),
            instructions=[parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, []
            )],
        ))

        self.logger.info("Default-drop policy installed on switch %s", datapath.id)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER])
    def switch_state_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info("Switch %s connected to the SDN controller", datapath.id)


