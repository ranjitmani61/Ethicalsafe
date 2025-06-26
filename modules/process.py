import psutil
import logging

logger = logging.getLogger(__name__)

def monitor_processes():
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            processes.append({
                "pid": proc.info['pid'],
                "name": proc.info['name'],
                "cpu": proc.info['cpu_percent'],
                "memory": proc.info['memory_percent']
            })
        return {"status": "Success", "processes": processes[:10]}
    except Exception as e:
        logger.error(f"Process monitor error: {str(e)}")
        return {"error": f"Process monitoring failed: {str(e)}"}