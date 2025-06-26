import nmap
import logging

logger = logging.getLogger(__name__)

def scan_ports(target="localhost"):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments="-sT --top-ports 10")
        scan_results = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    scan_results.append({
                        "host": host,
                        "port": port,
                        "state": nm[host][proto][port]["state"]
                    })
        return {"status": "Success", "results": scan_results}
    except Exception as e:
        logger.error(f"Port scan error: {str(e)}")
        return {"error": f"Port scan failed: {str(e)}"}

def stealth_scan(target="localhost"):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments="-sS --top-ports 10")
        scan_results = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    scan_results.append({
                        "host": host,
                        "port": port,
                        "state": nm[host][proto][port]["state"]
                    })
        return {"status": "Success", "results": scan_results}
    except Exception as e:
        logger.error(f"Stealth scan error: {str(e)}")
        return {"error": f"Stealth scan failed: {str(e)}"}