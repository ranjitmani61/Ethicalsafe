import platform
import logging

logger = logging.getLogger(__name__)

def get_device_info():
    """
    Retrieve system information for the current device.
    
    Returns:
        dict: Dictionary containing system details or error message.
    """
    try:
        info = {
            "hostname": platform.node(),
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor()
        }
        logger.info("Device info retrieved successfully")
        return info
    except Exception as e:
        logger.error(f"Device info error: {str(e)}")
        return {"error": f"Failed to retrieve device info: {str(e)}"}
