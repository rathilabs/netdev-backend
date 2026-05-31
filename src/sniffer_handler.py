import asyncio
import json
import logging
from typing import Any, Dict, Optional
from .sniffer import TrafficSniffer

logger = logging.getLogger("NetworkTools.SnifferHandler")

class SnifferHandler:
    """
    Decoupled handler for all traffic capture commands.
    Manages the lifecycle of the sniffer and its integration with WebSocket broadcasting.
    """
    
    def __init__(self):
        self.sniffer = TrafficSniffer()

    async def handle_command(self, command: str, data: dict, active_connections: set, loop: asyncio.AbstractEventLoop) -> Optional[dict]:
        """Routes sniffer-specific commands."""
        
        if command == "START_SNIFFER":
            interface = data.get("interface")
            filter_bpf = data.get("filter")
            
            if self.sniffer.is_running:
                return {"status": "SUCCESS", "message": "Joined existing sniffer session"}

            def packet_broadcast(pkt_batch):
                message = json.dumps({
                    "type": "LIVE_PACKET_BATCH",
                    "data": pkt_batch
                })
                for conn in list(active_connections):
                    try:
                        asyncio.run_coroutine_threadsafe(conn.send(message), loop)
                    except Exception:
                        pass

            success, msg = self.sniffer.start(interface, filter_bpf, callback=packet_broadcast)
            return {"status": "SUCCESS" if success else "ERROR", "message": msg}

        elif command == "STOP_SNIFFER":
            success, msg = self.sniffer.stop()
            return {"status": "SUCCESS" if success else "ERROR", "message": msg}

        elif command == "SNIFFER_STATUS":
            return {"status": "SUCCESS", "data": self.sniffer.get_status()}

        elif command == "LIST_INTERFACES":
            from scapy.all import get_if_list
            try:
                interfaces = get_if_list()
                return {"status": "SUCCESS", "data": interfaces, "command": "LIST_INTERFACES"}
            except Exception as e:
                return {"status": "ERROR", "message": str(e)}

        return None
