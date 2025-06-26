import psutil
import logging

logger = logging.getLogger(__name__)

def monitor_processes():
    """
    Monitor running processes on the system.
    
    Returns:
        dict: Dictionary containing list of processes or error message.
    """
    try:
        processes = [
            {"pid": proc.pid, "name": proc.name(), "username": proc.username()}
            for proc in psutil.process_iter(['pid', 'name', 'username'])
        ]
        logger.info("Processes retrieved successfully")
        return {"processes": processes[:10]}  # Limit to 10 for performance
    except Exception as e:
        logger.error(f"Process monitoring error: {str(e)}")
        return {"error": f"Failed to monitor processes: {str(e)}"}
