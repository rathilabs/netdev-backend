import socket
import struct
import array
import logging
import sys

logger = logging.getLogger("PacketServer.Injector")

def checksum(data):
    """
    Standard Internet Checksum (RFC 1071)
    """
    if len(data) % 2 == 1:
        data += b'\x00'
    s = sum(array.array('H', data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return socket.htons(~s & 0xffff)

class PacketInjector:
    def __init__(self):
        # Raw socket requires root/admin privileges on most systems
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            # We want to provide our own IP header
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            logger.info("Raw socket initialized successfully")
        except PermissionError:
            logger.error("Permission Denied: Raw sockets require root/administrator privileges.")
            self.socket = None
        except Exception as e:
            logger.error(f"Error initializing raw socket: {e}")
            self.socket = None

    def create_ip_header(self, src_ip, dst_ip, protocol, length):
        """
        Creates a standard 20-byte IPv4 header.
        """
        import sys
        logger.debug(f"Creating IP header: {src_ip} -> {dst_ip}, Proto: {protocol}")
        version = 4
        ihl = 5
        ver_ihl = (version << 4) + ihl
        tos = 0
        tot_len = 20 + length
        id = 54321
        frag_off = 0
        ttl = 255
        check = 0
        saddr = socket.inet_aton(src_ip)
        daddr = socket.inet_aton(dst_ip)
        
        if sys.platform == 'darwin':
            # Standard BSD requirement: tot_len and frag_off in host byte order
            # Note: Modern macOS may still reject this due to SIP or interface restrictions
            header = struct.pack('!BB', ver_ihl, tos) + \
                     struct.pack('H', tot_len) + \
                     struct.pack('!H', id) + \
                     struct.pack('H', frag_off) + \
                     struct.pack('!BB', ttl, protocol) + \
                     struct.pack('!H', 0) + \
                     saddr + daddr
            return header
        else:
            header = struct.pack('!BBHHHBBH4s4s', 
                               ver_ihl, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)
        
        # Calculate and re-pack checksum
        if sys.platform != 'darwin':
            # On macOS, kernel often handles the IP checksum if set to 0, 
            # and our manual calculation might conflict with host-order fields.
            check = checksum(header)
            header = struct.pack('!BBHHHBBH4s4s', 
                               ver_ihl, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)
        
        return header

    def create_udp_header(self, src_port, dst_port, payload_len):
        """
        Creates an 8-byte UDP header.
        """
        logger.debug(f"Creating UDP header: {src_port} -> {dst_port}, Payload Len: {payload_len}")
        length = 8 + payload_len
        check = 0 # Optional for UDP
        return struct.pack('!HHHH', src_port, dst_port, length, check)

    def create_tcp_header(self, src_port, dst_port, flags, src_ip, dst_ip, payload):
        """
        Creates a 20-byte TCP header with checksum calculation.
        """
        logger.debug(f"Creating TCP header: {src_port} -> {dst_port}, Flags: {flags}")
        seq = 0
        ack_seq = 0
        doff = 5
        window = socket.htons(5840)
        check = 0
        urg_ptr = 0
        
        # Flags
        res = 0
        tcp_flags = (flags['fin'] + 
                    (flags['syn'] << 1) + 
                    (flags['rst'] << 2) + 
                    (flags['psh'] << 3) + 
                    (flags['ack'] << 4) + 
                    (flags['urg'] << 5))
        
        offset_res = (doff << 4) + res
        
        header = struct.pack('!HHLLBBHHH', 
                           src_port, dst_port, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)
        
        # Pseudo-header for checksum
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(header) + len(payload)
        
        psh = struct.pack('!4s4sBBH', socket.inet_aton(src_ip), socket.inet_aton(dst_ip), placeholder, protocol, tcp_length)
        psh = psh + header + payload
        
        check = checksum(psh)
        
        header = struct.pack('!HHLLBBHHH', 
                           src_port, dst_port, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)
        return header

    def send_packet(self, config):
        """
        Main entry point for sending a packet based on ICD config.
        """
        protocol_str = config.get('protocol', 'UDP').upper()
        src_ip = config.get('srcIp', '127.0.0.1')
        dst_ip = config.get('dstIp', '127.0.0.1')
        src_port = int(config.get('srcPort', 12345))
        dst_port = int(config.get('dstPort', 80))
        
        payload_hex = config.get('payloadHex')
        if payload_hex:
            payload = bytes.fromhex(payload_hex.replace(' ', ''))
        else:
            payload = config.get('payload', '').encode('utf-8')

        if not self.socket:
            logger.warning("Raw socket not initialized. Checking if fallback is possible...")
            if protocol_str == 'UDP':
                try:
                    logger.info(f"Using fallback UDP socket for {dst_ip}:{dst_port}")
                    fallback_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    fallback_sock.sendto(payload, (dst_ip, dst_port))
                    fallback_sock.close()
                    return True, "Packet injected (via kernel fallback - raw socket restricted)"
                except Exception as e:
                    return False, f"Fallback failed: {e}"
            return False, "Raw socket not initialized and protocol does not support fallback (check privileges)"

        try:
            logger.info(f"Injecting {protocol_str} packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            
            if protocol_str == 'UDP':
                protocol = socket.IPPROTO_UDP
                transport_header = self.create_udp_header(src_port, dst_port, len(payload))
            elif protocol_str == 'TCP':
                protocol = socket.IPPROTO_TCP
                flags = config.get('flags', {'syn':1, 'ack':0, 'fin':0, 'rst':0, 'psh':0, 'urg':0})
                transport_header = self.create_tcp_header(src_port, dst_port, flags, src_ip, dst_ip, payload)
            else:
                logger.error(f"Unsupported protocol requested: {protocol_str}")
                return False, f"Unsupported protocol: {protocol_str}"

            ip_header = self.create_ip_header(src_ip, dst_ip, protocol, len(transport_header) + len(payload))
            packet = ip_header + transport_header + payload
            
            logger.debug(f"Sending packet of total length {len(packet)} bytes")
            logger.debug(f"Packet Hex Dump: {packet.hex()}")
            
            try:
                self.socket.sendto(packet, (dst_ip, 0))
            except OSError as e:
                if e.errno == 22 and sys.platform == 'darwin':
                    logger.warning("Standard raw injection failed with Errno 22. Attempting fallback (kernel-managed IP header)...")
                    # Fallback: Create a standard UDP socket and let the kernel handle the IP header
                    fallback_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    fallback_sock.sendto(payload, (dst_ip, dst_port))
                    fallback_sock.close()
                    return True, "Packet injected (via kernel fallback due to macOS raw socket restrictions)"
                raise e
                
            return True, "Packet injected successfully"
        except Exception as e:
            logger.exception(f"Failed to inject packet: {e}")
            return False, str(e)
