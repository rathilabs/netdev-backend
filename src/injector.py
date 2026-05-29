import socket
import struct
import array
import logging
import sys
from typing import Dict, Tuple, Optional, Any

# Configure module-level logger
logger = logging.getLogger("NetDev.Injector")

def calculate_checksum(data: bytes) -> int:
    """
    Standard Internet Checksum (RFC 1071).
    Used for IP, TCP, and UDP headers.
    
    Args:
        data: The byte sequence to checksum.
        
    Returns:
        A 16-bit integer representing the checksum.
    """
    if len(data) % 2 == 1:
        data += b'\x00'
    s = sum(array.array('H', data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return socket.htons(~s & 0xffff)

class PacketInjector:
    """
    Core engine for raw packet injection.
    Handles the manual construction of L3 (IP) and L4 (TCP/UDP) headers.
    """
    
    def __init__(self):
        """
        Initializes the raw socket. 
        Note: Requires root/administrator privileges on most operating systems.
        """
        self.socket = None
        try:
            # Create a raw socket with IP_HDRINCL to provide our own IP header
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            logger.debug("Raw socket ready.")
        except PermissionError:
            logger.error("Permission denied: root required.")
        except Exception as e:
            logger.error(f"Socket error: {e}")

    def create_ip_header(self, src_ip: str, dst_ip: str, protocol: int, length: int) -> bytes:
        """
        Constructs a standard 20-byte IPv4 header.
        
        Args:
            src_ip: Source IPv4 address string.
            dst_ip: Destination IPv4 address string.
            protocol: Protocol number (e.g., socket.IPPROTO_TCP).
            length: Total length of the transport layer header + payload.
        """
        version = 4
        ihl = 5 # 5 words = 20 bytes
        ver_ihl = (version << 4) + ihl
        tos = 0
        tot_len = 20 + length
        packet_id = 54321
        frag_off = 0
        ttl = 255
        check = 0 # Initial checksum
        saddr = socket.inet_aton(src_ip)
        daddr = socket.inet_aton(dst_ip)
        
        # macOS/BSD systems require tot_len and frag_off in host byte order
        if sys.platform == 'darwin':
            header = struct.pack('!BB', ver_ihl, tos) + \
                     struct.pack('H', tot_len) + \
                     struct.pack('!H', packet_id) + \
                     struct.pack('H', frag_off) + \
                     struct.pack('!BB', ttl, protocol) + \
                     struct.pack('!H', 0) + \
                     saddr + daddr
        else:
            header = struct.pack('!BBHHHBBH4s4s', 
                               ver_ihl, tos, tot_len, packet_id, frag_off, ttl, protocol, check, saddr, daddr)
            # Calculate and re-pack checksum for non-macOS systems
            check = calculate_checksum(header)
            header = struct.pack('!BBHHHBBH4s4s', 
                               ver_ihl, tos, tot_len, packet_id, frag_off, ttl, protocol, check, saddr, daddr)
        
        return header

    def create_udp_header(self, src_port: int, dst_port: int, payload_len: int) -> bytes:
        """Constructs an 8-byte UDP header."""
        length = 8 + payload_len
        check = 0 # Optional for UDP over IPv4
        return struct.pack('!HHHH', src_port, dst_port, length, check)

    def create_tcp_header(self, src_port: int, dst_port: int, flags: Dict[str, int], 
                          src_ip: str, dst_ip: str, payload: bytes) -> bytes:
        """Constructs a 20-byte TCP header with mandatory checksum calculation."""
        seq = 0
        ack_seq = 0
        doff = 5 # 5 words = 20 bytes
        window = socket.htons(5840)
        check = 0
        urg_ptr = 0
        
        # Map flags
        tcp_flags = (flags.get('fin', 0) + 
                    (flags.get('syn', 0) << 1) + 
                    (flags.get('rst', 0) << 2) + 
                    (flags.get('psh', 0) << 3) + 
                    (flags.get('ack', 0) << 4) + 
                    (flags.get('urg', 0) << 5))
        
        offset_res = (doff << 4) + 0
        header = struct.pack('!HHLLBBHHH', 
                           src_port, dst_port, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)
        
        # Pseudo-header for TCP checksum calculation
        psh = struct.pack('!4s4sBBH', 
                        socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 
                        0, socket.IPPROTO_TCP, len(header) + len(payload))
        check = calculate_checksum(psh + header + payload)
        
        return struct.pack('!HHLLBBHHH', 
                         src_port, dst_port, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)

    def send_packet(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        """
        The main entry point to inject a packet based on a configuration dictionary.
        
        Args:
            config: Dictionary containing 'protocol', 'srcIp', 'dstIp', 'srcPort', 
                   'dstPort', 'payload' (or 'payloadHex'), and optional 'flags'.
        """
        protocol_str = config.get('protocol', 'UDP').upper()
        src_ip = config.get('srcIp', '127.0.0.1')
        dst_ip = config.get('dstIp', '127.0.0.1')
        src_port = int(config.get('srcPort', 12345))
        dst_port = int(config.get('dstPort', 80))
        
        # Prepare Payload
        payload_hex = config.get('payloadHex')
        if payload_hex:
            payload = bytes.fromhex(payload_hex.replace(' ', ''))
        else:
            payload = config.get('payload', '').encode('utf-8')

        # Fallback for systems where raw sockets are not available/permitted
        if not self.socket:
            if protocol_str == 'UDP':
                try:
                    logger.info("Raw socket unavailable; using UDP fallback.")
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fallback_sock:
                        fallback_sock.sendto(payload, (dst_ip, dst_port))
                    return True, "Injected via kernel fallback (standard UDP)"
                except Exception as e:
                    return False, f"Fallback failed: {e}"
            return False, "Injection failed: Raw socket required (check root privileges)"

        try:
            if protocol_str == 'UDP':
                transport_proto = socket.IPPROTO_UDP
                transport_header = self.create_udp_header(src_port, dst_port, len(payload))
            elif protocol_str == 'TCP':
                transport_proto = socket.IPPROTO_TCP
                flags = config.get('flags', {'syn': 1})
                transport_header = self.create_tcp_header(src_port, dst_port, flags, src_ip, dst_ip, payload)
            else:
                return False, f"Unsupported protocol: {protocol_str}"

            ip_header = self.create_ip_header(src_ip, dst_ip, transport_proto, len(transport_header) + len(payload))
            full_packet = ip_header + transport_header + payload
            
            # Send the raw frame
            try:
                self.socket.sendto(full_packet, (dst_ip, 0))
            except OSError as e:
                # Specific handling for macOS raw socket limitations
                if e.errno == 22 and sys.platform == 'darwin':
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fallback_sock:
                        fallback_sock.sendto(payload, (dst_ip, dst_port))
                    return True, "Injected via macOS kernel fallback"
                raise e
                
            return True, "Packet injected successfully"
        except Exception as e:
            logger.exception(f"Injection Error: {e}")
            return False, str(e)
