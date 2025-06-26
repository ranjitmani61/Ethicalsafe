import streamlit as st
import logging
import os
import pandas as pd
from datetime import datetime
from streamlit_autorefresh import st_autorefresh
from modules.device_info import get_device_info
from modules.location import get_location
from modules.process import monitor_processes
from modules.file_ops import check_file_hash, encrypt_decrypt_file
from modules.password import check_password_strength
from modules.web_scan import scan_sql_injection, scan_xss, brute_force_login
from modules.network import scan_network
from modules.port_scan import scan_ports

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

# Custom CSS for professional look
st.markdown("""
    <style>
    .main { background-color: #f5f5f5; }
    .stButton>button { background-color: #1f77b4; color: white; border-radius: 5px; }
    .stTextInput>div>input { border-radius: 5px; }
    .stSelectbox>div>select { border-radius: 5px; }
    .sidebar .sidebar-content { background-color: #2e2e2e; color: white; }
    </style>
""", unsafe_allow_html=True)

def main():
    """Main function to run the Ethical Hacking Dashboard."""
    st.set_page_config(page_title="Ethical Hacking Dashboard", layout="wide", initial_sidebar_state="expanded")
    st.title("🔒 Ethical Hacking Dashboard")
    st.markdown("""
        **Use these tools responsibly on your own devices/networks with explicit permission.**  
        Unauthorized use is strictly prohibited. Built for ethical hacking and security testing.
    """)

    # Sidebar for navigation
    st.sidebar.header("🛠️ Tools")
    tool = st.sidebar.selectbox(
        "Select a Tool",
        [
            "Device Info",
            "Track Location",
            "Monitor Processes",
            "File Hash Check",
            "Encrypt/Decrypt File",
            "Password Strength",
            "SQL Injection Scan",
            "XSS Scan",
            "Brute Force Test",
            "Network Scan",
            "Port Scan"
        ],
        help="Choose a tool for ethical hacking tasks."
    )

    # Auto-refresh for real-time tools
    if tool in ["Device Info", "Monitor Processes", "Network Scan"]:
        st_autorefresh(interval=3000)  # Refresh every 3 seconds

    # Results container
    with st.container():
        st.subheader(f"📊 {tool} Results")

        if tool == "Device Info":
            st.write("🔍 Real-time Device Information (updates every 3 seconds)")
            with st.spinner("Fetching device info..."):
                result = get_device_info()
                if "error" not in result:
                    df = pd.DataFrame([result], index=["Device"])
                    st.dataframe(df.style.set_caption("Device Information").set_table_styles([
                        {'selector': 'caption', 'props': [('font-size', '16px'), ('font-weight', 'bold')]}
                    ]))
                else:
                    st.error(result["error"])
                logger.info(f"Device Info: {result}")

        elif tool == "Track Location":
            if st.button("🌍 Track Location", key="track_location"):
                with st.spinner("Fetching location..."):
                    result = get_location()
                    if "error" not in result:
                        df = pd.DataFrame([result], index=["Location"])
                        st.dataframe(df.style.set_caption("Geolocation Data"))
                    else:
                        st.error(result["error"])
                    logger.info(f"Location: {result}")

        elif tool == "Monitor Processes":
            st.write("📈 Real-time Process Monitor (updates every 3 seconds)")
            with st.spinner("Fetching processes..."):
                result = monitor_processes()
                if "processes" in result:
                    df = pd.DataFrame(result["processes"])
                    st.dataframe(df.style.set_caption("Running Processes"))
                else:
                    st.error(result["error"])
                logger.info(f"Processes: {result}")

        elif tool == "File Hash Check":
            file_path = st.text_input("📁 File Path", help="Enter the path to the file")
            if st.button("Calculate Hash", key="file_hash"):
                if file_path:
                    with st.spinner("Calculating file hash..."):
                        result = check_file_hash(file_path)
                        if "error" not in result:
                            df = pd.DataFrame([result], index=["Hash"])
                            st.dataframe(df.style.set_caption("File Hash"))
                        else:
                            st.error(result["error"])
                        logger.info(f"File Hash: {result}")
                else:
                    st.warning("Please enter a file path.")

        elif tool == "Encrypt/Decrypt File":
            file_path = st.text_input("📁 File Path", help="Enter the path to the file")
            operation = st.selectbox("Operation", ["encrypt", "decrypt"], help="Choose encrypt or decrypt")
            if st.button("Process File", key="encrypt_decrypt"):
                if file_path:
                    with st.spinner(f"{operation.capitalize()}ing file..."):
                        result = encrypt_decrypt_file(file_path, operation)
                        if "error" not in result:
                            df = pd.DataFrame([result], index=["Operation"])
                            st.dataframe(df.style.set_caption(f"File {operation.capitalize()} Result"))
                            st.success(f"File {operation}ed successfully! Key: {result['key']}")
                        else:
                            st.error(result["error"])
                        logger.info(f"File Operation: {result}")
                else:
                    st.warning("Please enter a file path.")

        elif tool == "Password Strength":
            password = st.text_input("🔑 Password", type="password", help="Enter a password to check")
            if st.button("Check Password", key="password_strength"):
                if password:
                    with st.spinner("Checking password strength..."):
                        result = check_password_strength(password)
                        if "error" not in result:
                            df = pd.DataFrame([result], index=["Password"])
                            st.dataframe(df.style.set_caption("Password Strength"))
                            st.success(f"Password Strength: {result['strength']}")
                        else:
                            st.error(result["error"])
                        logger.info(f"Password Strength: {result}")
                else:
                    st.warning("Please enter a password.")

        elif tool == "SQL Injection Scan":
            url = st.text_input("🌐 URL", value="http://example.com", help="Enter the target URL")
            if st.button("Scan SQL", key="sql_scan"):
                if url:
                    with st.spinner("Scanning for SQL Injection..."):
                        result = scan_sql_injection(url)
                        if "error" not in result:
                            df = pd.DataFrame(result["results"])
                            st.dataframe(df.style.set_caption("SQL Injection Scan Results"))
                        else:
                            st.error(result["error"])
                        logger.info(f"SQL Injection Scan: {result}")
                else:
                    st.warning("Please enter a URL.")

        elif tool == "XSS Scan":
            url = st.text_input("🌐 URL", value="http://example.com", help="Enter the target URL")
            if st.button("Scan XSS", key="xss_scan"):
                if url:
                    with st.spinner("Scanning for XSS..."):
                        result = scan_xss(url)
                        if "error" not in result:
                            df = pd.DataFrame(result["results"])
                            st.dataframe(df.style.set_caption("XSS Scan Results"))
                        else:
                            st.error(result["error"])
                        logger.info(f"XSS Scan: {result}")
                else:
                    st.warning("Please enter a URL.")

        elif tool == "Brute Force Test":
            url = st.text_input("🌐 Login URL", value="http://example.com/login", help="Enter the login URL")
            username_field = st.text_input("Username Field", value="username")
            password_field = st.text_input("Password Field", value="password")
            if st.button("Test Brute Force", key="brute_force"):
                if url:
                    with st.spinner("Testing brute force..."):
                        result = brute_force_login(url, username_field, password_field)
                        if "error" not in result:
                            df = pd.DataFrame(result["results"])
                            st.dataframe(df.style.set_caption("Brute Force Test Results"))
                        else:
                            st.error(result["error"])
                        logger.info(f"Brute Force Test: {result}")
                else:
                    st.warning("Please enter a URL.")

        elif tool == "Network Scan":
            subnet = st.text_input("🌐 Subnet", value="192.168.1.0/24", help="Enter subnet (e.g., 192.168.1.0/24)")
            if st.button("Scan Network", key="network_scan"):
                with st.spinner("Scanning network..."):
                    result = scan_network(subnet)
                    if "error" not in result:
                        df = pd.DataFrame(result["devices"])
                        st.dataframe(df.style.set_caption("Network Devices"))
                    else:
                        st.error(result["error"])
                    logger.info(f"Network Scan: {result}")

        elif tool == "Port Scan":
            target = st.text_input("🎯 Target", value="localhost", help="Enter the target IP or hostname")
            if st.button("Scan Ports", key="port_scan"):
                if target:
                    with st.spinner("Scanning ports..."):
                        result = scan_ports(target)
                        if "error" not in result:
                            df = pd.DataFrame(result["ports"])
                            st.dataframe(df.style.set_caption("Open Ports"))
                        else:
                            st.error(result["error"])
                        logger.info(f"Port Scan: {result}")
                else:
                    st.warning("Please enter a target.")

if __name__ == "__main__":
    main()
