import scapy.all as scapy
import datetime
import logging
from threading import Lock

logger = logging.getLogger(__name__)
network_lock = Lock()

def scan_network():
    try:
        with network_lock:
            ip_range = "192.168.1.0/24"  # Adjust to your network
            arp_request = scapy.ARP(pdst=ip_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            devices = [{"ip": pkt[1].psrc, "mac": pkt[1].hwsrc} for pkt in answered_list]
            return {"status": "Success", "devices": devices}
    except Exception as e:
        logger.error(f"Network scan error: {str(e)}")
        return {"error": f"Network scan failed: {str(e)}"}

def capture_packets(interface="eth0", count=5):
    try:
        with network_lock:
            packets = scapy.sniff(iface=interface, count=count, timeout=5)
            packet_summary = [
                {"src": pkt[scapy.IP].src, "dst": pkt[scapy.IP].dst, "protocol": pkt[scapy.IP].proto}
                for pkt in packets if scapy.IP in pkt
            ]
            log_file = f"logs/packets_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(log_file, 'w') as f:
                f.write(str(packet_summary))
            return {"status": "Success", "packets": packet_summary, "log_file": log_file}
    except Exception as e:
        logger.error(f"Packet capture error: {str(e)}")
        return {"error": f"Packet capture failed: {str(e)}"}

def sniff_http(interface="eth0", count=5):
    try:
        with network_lock:
            def process_packet(packet):
                if packet.haslayer(scapy.Raw):
                    load = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                    if "GET" in load or "POST" in load:
                        return {"src": packet[scapy.IP].src, "dst": packet[scapy.IP].dst, "data": load[:100]}
                return None
            packets = scapy.sniff(iface=interface, filter="tcp port 80", count=count, timeout=5, prn=process_packet)
            http_requests = [process_packet(pkt) for pkt in packets if process_packet(pkt)]
            log_file = f"logs/http_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(log_file, 'w') as f:
                f.write(str(http_requests))
            return {"status": "Success", "requests": http_requests, "log_file": log_file}
    except Exception as e:
        logger.error(f"HTTP sniff error: {str(e)}")
        return {"error": f"HTTP sniffing failed: {str(e)}"}

def analyze_traffic(interface="eth0", count=10):
    try:
        with network_lock:
            packets = scapy.sniff(iface=interface, count=count, timeout=10)
            protocols = {}
            for pkt in packets:
                if scapy.IP in pkt:
                    proto = pkt[scapy.IP].proto
                    protocols[proto] = protocols.get(proto, 0) + 1
            analysis = {
                "total_packets": len(packets),
                "protocol_breakdown": {k: v for k, v in protocols.items()},
                "top_sources": [pkt[scapy.IP].src for pkt in packets if scapy.IP in pkt][:5]
            }
            log_file = f"logs/traffic_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(log_file, 'w') as f:
                f.write(str(analysis))
            return {"status": "Success", "analysis": analysis, "log_file": log_file}
    except Exception as e:
        logger.error(f"Traffic analysis error: {str(e)}")
        return {"error": f"Traffic analysis failed: {str(e)}"}