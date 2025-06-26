import streamlit as st
import logging
import os
from datetime import datetime
from modules.device_info import get_device_info
from modules.location import get_location
from modules.network import scan_network, capture_packets, sniff_http, analyze_traffic
from modules.process import monitor_processes
from modules.file_ops import check_file_hash, encrypt_decrypt_file
from modules.port_scan import scan_ports, stealth_scan
from modules.voice import recognize_voice
from modules.wifi import get_wifi_passwords
from modules.password import check_password_strength
from modules.keylogger import start_keylogger, stop_keylogger
from modules.web_scan import scan_sql_injection, scan_xss, brute_force_login

# Configure logging
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)
logging.basicConfig(
    filename=f"{log_dir}/app_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

def main():
    st.title("Ethical Hacking Dashboard")
    st.write("Use these tools only on your own devices/networks with permission.")
    
    # Sidebar for navigation
    st.sidebar.header("Select Tool")
    tool = st.sidebar.selectbox("Choose a tool", [
        "Device Info", "Track Location", "Network Scan", "Monitor Processes", 
        "Packet Capture", "File Hash Check", "Port Scan", 
        "Voice Recognition", "Wi-Fi Passwords", "Encrypt/Decrypt File", 
        "Password Strength", "Keylogger", "HTTP Sniffer", "SQL Injection Scan", 
        "XSS Scan", "Brute Force Test", "Traffic Analysis", "Stealth Scan"
    ])

    # Results container
    results = st.container()

    if tool == "Device Info":
        if st.button("Get Device Info"):
            with results:
                result = get_device_info()
                st.json(result)
                logger.info(f"Device Info: {result}")

    elif tool == "Track Location":
        if st.button("Track Location"):
            with results:
                result = get_location()
                st.json(result)
                logger.info(f"Location: {result}")

    elif tool == "Network Scan":
        if st.button("Scan Network"):
            with results:
                result = scan_network()
                st.json(result)
                logger.info(f"Network Scan: {result}")

    elif tool == "Monitor Processes":
        if st.button("Monitor Processes"):
            with results:
                result = monitor_processes()
                st.json(result)
                logger.info(f"Processes: {result}")

    elif tool == "Packet Capture":
        interface = st.text_input("Network Interface", value="eth0")
        count = st.number_input("Packet Count", min_value=1, max_value=100, value=5)
        if st.button("Capture Packets"):
            with results:
                result = capture_packets(interface, count)
                st.json(result)
                logger.info(f"Packet Capture: {result}")

    elif tool == "File Hash Check":
        file_path = st.text_input("File Path")
        if st.button("Check File Hash") and file_path:
            with results:
                result = check_file_hash(file_path)
                st.json(result)
                logger.info(f"File Hash: {result}")

    elif tool == "Port Scan":
        target = st.text_input("Target", value="localhost")
        if st.button("Scan Ports"):
            with results:
                result = scan_ports(target)
                st.json(result)
                logger.info(f"Port Scan: {result}")

    elif tool == "Voice Recognition":
        if st.button("Recognize Voice"):
            with results:
                result = recognize_voice()
                st.json(result)
                logger.info(f"Voice Recognition: {result}")

    elif tool == "Wi-Fi Passwords":
        if st.button("Get Wi-Fi Passwords"):
            with results:
                result = get_wifi_passwords()
                st.json(result)
                logger.info(f"Wi-Fi Passwords: {result}")

    elif tool == "Encrypt/Decrypt File":
        file_path = st.text_input("File Path")
        operation = st.selectbox("Operation", ["encrypt", "decrypt"])
        if st.button("Process File") and file_path:
            with results:
                result = encrypt_decrypt_file(file_path, operation)
                st.json(result)
                logger.info(f"File Operation: {result}")

    elif tool == "Password Strength":
        password = st.text_input("Password", type="password")
        if st.button("Check Password") and password:
            with results:
                result = check_password_strength(password)
                st.json(result)
                logger.info(f"Password Strength: {result}")

    elif tool == "Keylogger":
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Start Keylogger"):
                with results:
                    result = start_keylogger()
                    st.json(result)
                    logger.info(f"Keylogger Start: {result}")
        with col2:
            if st.button("Stop Keylogger"):
                with results:
                    result = stop_keylogger()
                    st.json(result)
                    logger.info(f"Keylogger Stop: {result}")

    elif tool == "HTTP Sniffer":
        interface = st.text_input("Network Interface", value="eth0")
        count = st.number_input("Request Count", min_value=1, max_value=100, value=5)
        if st.button("Sniff HTTP"):
            with results:
                result = sniff_http(interface, count)
                st.json(result)
                logger.info(f"HTTP Sniffer: {result}")

    elif tool == "SQL Injection Scan":
        url = st.text_input("URL", value="http://example.com")
        if st.button("Scan SQL"):
            with results:
                result = scan_sql_injection(url)
                st.json(result)
                logger.info(f"SQL Injection Scan: {result}")

    elif tool == "XSS Scan":
        url = st.text_input("URL", value="http://example.com")
        if st.button("Scan XSS"):
            with results:
                result = scan_xss(url)
                st.json(result)
                logger.info(f"XSS Scan: {result}")

    elif tool == "Brute Force Test":
        url = st.text_input("Login URL", value="http://example.com/login")
        username_field = st.text_input("Username Field", value="username")
        password_field = st.text_input("Password Field", value="password")
        if st.button("Test Brute Force"):
            with results:
                result = brute_force_login(url, username_field, password_field)
                st.json(result)
                logger.info(f"Brute Force Test: {result}")

    elif tool == "Traffic Analysis":
        interface = st.text_input("Network Interface", value="eth0")
        count = st.number_input("Packet Count", min_value=1, max_value=100, value=10)
        if st.button("Analyze Traffic"):
            with results:
                result = analyze_traffic(interface, count)
                st.json(result)
                logger.info(f"Traffic Analysis: {result}")

    elif tool == "Stealth Scan":
        target = st.text_input("Target", value="localhost")
        if st.button("Stealth Scan"):
            with results:
                result = stealth_scan(target)
                st.json(result)
                logger.info(f"Stealth Scan: {result}")

if __name__ == "__main__":
    main()