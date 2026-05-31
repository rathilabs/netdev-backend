import logging
import threading
import time
import asyncio
import os
from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, ICMP, Ether
from typing import Optional, Callable, Dict, Any, List
import datetime

logger = logging.getLogger("NetworkTools.Sniffer")

class TrafficSniffer:
    """
    Manages asynchronous packet sniffing with 0.5s aggregation logic.
    Groups traffic by (Protocol, Src, Dst) and sends batches to prevent UI flooding.
    """
    
    def __init__(self):
        self.sniffer: Optional[AsyncSniffer] = None
        self.on_packet_callback: Optional[Callable[[List[Dict[str, Any]]], None]] = None
        self.is_running = False
        self._lock = threading.Lock()
        
        # Aggregation state
        self._aggregation_buffer = {} 
        self._aggregation_thread = None
        self._stop_aggregation = threading.Event()
        self._packet_count = 0
        
        # Self-filtering
        self.backend_port = 8001

    def _get_packet_key(self, pkt):
        proto, src, dst = "Unknown", "N/A", "N/A"
        try:
            if IP in pkt:
                src, dst = pkt[IP].src, pkt[IP].dst
                if TCP in pkt: proto = "TCP"
                elif UDP in pkt: proto = "UDP"
                elif ICMP in pkt: proto = "ICMP"
                else: proto = f"IP({pkt[IP].proto})"
            elif IPv6 in pkt:
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
                if TCP in pkt: proto = "TCP"
                elif UDP in pkt: proto = "UDP"
                else: proto = "IPv6"
            elif Ether in pkt:
                src, dst = pkt[Ether].src, pkt[Ether].dst
                proto = "L2/Eth"
        except: pass
        return (proto, src, dst)

    def _packet_handler(self, pkt):
        if TCP in pkt and (pkt[TCP].sport == self.backend_port or pkt[TCP].dport == self.backend_port):
            return

        key = self._get_packet_key(pkt)
        with self._lock:
            if key not in self._aggregation_buffer:
                self._aggregation_buffer[key] = {
                    "proto": key[0], "src": key[1], "dst": key[2],
                    "count": 0, "len": 0, "info": pkt.summary(),
                    "timestamp": datetime.datetime.now().isoformat(),
                    "interface": self.sniffer.iface if self.sniffer else "default"
                }
            entry = self._aggregation_buffer[key]
            entry["count"] += 1
            entry["len"] += len(pkt)
            if key[0] in ["TCP", "UDP", "ICMP"]: entry["info"] = pkt.summary()

    def _aggregation_loop(self):
        last_heartbeat = time.time()
        while not self._stop_aggregation.is_set():
            time.sleep(0.5) 
            to_flush = []
            with self._lock:
                if self._aggregation_buffer:
                    to_flush = list(self._aggregation_buffer.values())
                    self._aggregation_buffer.clear()
            
            if to_flush and self.on_packet_callback:
                for group in to_flush:
                    if group["count"] > 1: group["info"] = f"[{group['count']} packets] {group['info']}"
                self.on_packet_callback(to_flush)
                last_heartbeat = time.time()
            elif time.time() - last_heartbeat > 2.0 and self.on_packet_callback:
                self.on_packet_callback([{"type": "HEARTBEAT", "timestamp": datetime.datetime.now().isoformat(), "interface": self.sniffer.iface if self.sniffer else "default"}])
                last_heartbeat = time.time()

    def start(self, interface: Optional[str] = None, filter_bpf: Optional[str] = None, 
              callback: Optional[Callable[[List[Dict[str, Any]]], None]] = None):
        with self._lock:
            if self.is_running: return False, "Already running"
            
            # Privilege check for non-root users on Unix systems
            if os.name != 'nt' and os.geteuid() != 0:
                return False, "Capture requires ROOT privileges (Run with sudo)"

            self.on_packet_callback = callback
            self._stop_aggregation.clear()
            self._aggregation_buffer.clear()
            
            try:
                self.sniffer = AsyncSniffer(iface=interface, filter=filter_bpf, prn=self._packet_handler, store=0)
                self.sniffer.start()
                self._aggregation_thread = threading.Thread(target=self._aggregation_loop, daemon=True)
                self._aggregation_thread.start()
                self.is_running = True
                return True, "Started"
            except Exception as e:
                err = str(e)
                if "permission" in err.lower(): err = "Permission Denied: Run as root/admin"
                elif "no such device" in err.lower(): err = f"Interface '{interface}' not found"
                elif "syntax" in err.lower(): err = f"BPF Filter Syntax Error: {filter_bpf}"
                logger.error(f"Sniffer Start Failed: {err}")
                return False, err

    def stop(self):
        with self._lock:
            if not self.is_running: return False, "Not running"
            self._stop_aggregation.set()
            try:
                if self.sniffer and self.sniffer.running: self.sniffer.stop()
                return True, "Stopped"
            except Exception as e:
                err = str(e)
                if "Unsupported" in err: return True, "Stopped" # macOS quirk
                return False, err
            finally:
                self.is_running = False
                self.sniffer = None
                self.on_packet_callback = None

    def get_status(self):
        return {"is_running": self.is_running, "interface": self.sniffer.iface if (self.sniffer and self.is_running) else None}
