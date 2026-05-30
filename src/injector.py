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

    def create_icmp_header(self, icmp_type: int = 8, code: int = 0) -> bytes:
        """Constructs a standard 8-byte ICMP header."""
        checksum = 0
        identifier = 12345
        sequence = 1
        header = struct.pack('!BBHHH', icmp_type, code, checksum, identifier, sequence)
        checksum = calculate_checksum(header)
        return struct.pack('!BBHHH', icmp_type, code, checksum, identifier, sequence)

    def create_igmp_header(self, igmp_type: int = 0x11, max_resp_time: int = 10, group_addr: str = '0.0.0.0') -> bytes:
        """Constructs an 8-byte IGMP header."""
        checksum = 0
        group_ip = socket.inet_aton(group_addr)
        header = struct.pack('!BBH4s', igmp_type, max_resp_time, checksum, group_ip)
        checksum = calculate_checksum(header)
        return struct.pack('!BBH4s', igmp_type, max_resp_time, checksum, group_ip)

    def create_arp_header(self, opcode: int = 1, sender_mac: str = '00:00:00:00:00:00', 
                          sender_ip: str = '0.0.0.0', target_mac: str = '00:00:00:00:00:00', 
                          target_ip: str = '0.0.0.0') -> bytes:
        """Constructs a standard 28-byte ARP header (Ethernet/IPv4)."""
        hrd = 1 # Ethernet
        pro = 0x0800 # IPv4
        hln = 6
        pln = 4
        
        sha = bytes.fromhex(sender_mac.replace(':', '').replace('-', ''))
        spa = socket.inet_aton(sender_ip)
        tha = bytes.fromhex(target_mac.replace(':', '').replace('-', ''))
        tpa = socket.inet_aton(target_ip)
        
        return struct.pack('!HHBBH6s4s6s4s', hrd, pro, hln, pln, opcode, sha, spa, tha, tpa)

    def update_arp_table(self, ip_addr: str, mac_addr: str) -> Tuple[bool, str]:
        """
        Attempts to manually update the system's ARP table.
        Note: Requires administrative privileges. 
        Platform-specific implementation using subprocess calls.
        """
        import subprocess
        try:
            if sys.platform == 'win32':
                # Windows: arp -s <ip> <mac>
                cmd = ['arp', '-s', ip_addr, mac_addr.replace(':', '-')]
            else:
                # Linux/macOS: arp -s <ip> <mac>
                cmd = ['arp', '-s', ip_addr, mac_addr]
                
            subprocess.run(cmd, check=True, capture_output=True)
            logger.info(f"ARP Table Updated: {ip_addr} -> {mac_addr}")
            return True, f"ARP table entry for {ip_addr} updated successfully."
        except subprocess.CalledProcessError as e:
            err_msg = e.stderr.decode().strip()
            logger.error(f"ARP Update Failed: {err_msg}")
            return False, f"Failed to update ARP table: {err_msg}"
        except Exception as e:
            return False, str(e)

    def ping_host(self, target_ip: str, count: int = 4) -> Dict[str, Any]:
        """
        Diagnostic placeholder for procedural ICMP Ping.
        In a full implementation, this would send ICMP Echo Requests and wait for Replies.
        """
        return {
            "target": target_ip,
            "status": "NOT_IMPLEMENTED",
            "message": "Procedural ping engine is staged for future integration."
        }

    def traceroute_host(self, target_ip: str, max_hops: int = 30) -> Dict[str, Any]:
        """
        Diagnostic placeholder for procedural Traceroute.
        In a full implementation, this would iterate through TTL values (1-max_hops) 
        and parse ICMP Time Exceeded messages.
        """
        return {
            "target": target_ip,
            "status": "NOT_IMPLEMENTED",
            "message": "Procedural traceroute engine is staged for future integration."
        }

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
        
        logger.info(f"Injection Attempt: {protocol_str} {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        
        # Prepare Payload
        payload_hex = config.get('payloadHex')
        if payload_hex:
            payload = bytes.fromhex(payload_hex.replace(' ', ''))
        else:
            payload = config.get('payload', '').encode('utf-8')

        # Fallback for systems where raw sockets are not available/permitted
        if not self.socket:
            if protocol_str in ['UDP', 'DNS', 'DHCP']:
                try:
                    logger.info(f"Raw socket unavailable; using UDP fallback for {dst_ip}:{dst_port}")
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fallback_sock:
                        fallback_sock.sendto(payload, (dst_ip, dst_port))
                    
                    success_msg = f"UDP packet ({len(payload)} bytes) transferred to {dst_ip}:{dst_port} via kernel fallback"
                    logger.info(f"Injection Success: {success_msg}")
                    return True, success_msg
                except Exception as e:
                    logger.error(f"Injection Failure (Fallback): {e}")
                    return False, f"Fallback failed: {e}"
            logger.error(f"Injection Failure: Raw socket required for {protocol_str}")
            return False, "Injection failed: Raw socket required (check root privileges)"

        try:
            transport_header = b''
            transport_proto = socket.IPPROTO_UDP # Default

            if protocol_str == 'UDP':
                transport_proto = socket.IPPROTO_UDP
                transport_header = self.create_udp_header(src_port, dst_port, len(payload))
            elif protocol_str == 'TCP':
                transport_proto = socket.IPPROTO_TCP
                flags = config.get('flags', {'syn': 1})
                transport_header = self.create_tcp_header(src_port, dst_port, flags, src_ip, dst_ip, payload)
            elif protocol_str == 'ICMP':
                transport_proto = socket.IPPROTO_ICMP
                transport_header = self.create_icmp_header()
            elif protocol_str == 'IGMP':
                transport_proto = 2 # IGMP
                transport_header = self.create_igmp_header()
            elif protocol_str == 'DNS':
                transport_proto = socket.IPPROTO_UDP
                # For DNS, we often use specific ports if not provided
                d_port = dst_port if dst_port != 80 else 53
                transport_header = self.create_udp_header(src_port, d_port, len(payload))
            elif protocol_str == 'DHCP':
                transport_proto = socket.IPPROTO_UDP
                s_port = src_port if src_port != 12345 else 68
                d_port = dst_port if dst_port != 80 else 67
                transport_header = self.create_udp_header(s_port, d_port, len(payload))
            elif protocol_str == 'ARP':
                # ARP is L2 and doesn't use the standard IP raw socket in the same way.
                # In most simple Python setups, injecting raw L2 is platform-specific.
                logger.warning("ARP injection attempted. ARP usually requires L2 access (PF_PACKET).")
                return False, "ARP injection not yet implemented for this platform's raw L3 socket."
            else:
                logger.error(f"Injection Failure: Unsupported protocol {protocol_str}")
                return False, f"Unsupported protocol: {protocol_str}"

            ip_header = self.create_ip_header(src_ip, dst_ip, transport_proto, len(transport_header) + len(payload))
            full_packet = ip_header + transport_header + payload
            
            # Send the raw frame
            try:
                self.socket.sendto(full_packet, (dst_ip, 0))
                
                # High-density success summary
                flags_str = f" FLAGS:{config.get('flags')}" if protocol_str == 'TCP' else ""
                success_msg = f"[TX] {protocol_str} ({len(full_packet)}B) ➔ {dst_ip}:{dst_port} | SRC:{src_ip}:{src_port} | TTL:{config.get('ttl', 64)}{flags_str}"
                
                logger.info(f"Injection Success: {success_msg}")
                return True, success_msg
            except OSError as e:
                # Specific handling for macOS raw socket limitations
                if e.errno == 22 and sys.platform == 'darwin':
                    logger.info(f"Injection: macOS raw socket limitation; using kernel fallback for {dst_ip}:{dst_port}")
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fallback_sock:
                        fallback_sock.sendto(payload, (dst_ip, dst_port))
                    
                    success_msg = f"[FALLBACK] UDP ({len(payload)}B) ➔ {dst_ip}:{dst_port}"
                    logger.info(f"Injection Success: {success_msg}")
                    return True, success_msg
                raise e
                
            return True, "Packet injected successfully"
        except Exception as e:
            logger.error(f"Injection Failure: {e}")
            logger.exception("Full traceback for injection error:")
            return False, str(e)
