import socket
import platform
import uuid
import logging

logger = logging.getLogger(__name__)

def get_device_info():
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8*6, 8)][::-1])
        os_info = f"{platform.system()} {platform.release()}"
        return {
            "hostname": hostname,
            "ip": ip,
            "mac": mac,
            "os": os_info
        }
    except Exception as e:
        logger.error(f"Device info error: {str(e)}")
        return {"error": f"Failed to get device info: {str(e)}"}