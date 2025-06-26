import streamlit as st
import logging
import os
from datetime import datetime
from modules.device_info import get_device_info
from modules.location import get_location
from modules.process import monitor_processes
from modules.file_ops import check_file_hash, encrypt_decrypt_file
from modules.password import check_password_strength
from modules.web_scan import scan_sql_injection, scan_xss, brute_force_login
from streamlit_autorefresh import st_autorefresh

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
    """Main function to run the Ethical Hacking Dashboard."""
    st.set_page_config(page_title="Ethical Hacking Dashboard", layout="wide")
    st.title("🔒 Ethical Hacking Dashboard")
    st.markdown("""
        **Use these tools responsibly on your own devices/networks with explicit permission.**
        Unauthorized use is strictly prohibited.
    """)

    # Sidebar for navigation
    st.sidebar.header("🛠️ Select Tool")
    tool = st.sidebar.selectbox(
        "Choose a tool",
        [
            "Device Info",
            "Track Location",
            "Monitor Processes",
            "File Hash Check",
            "Encrypt/Decrypt File",
            "Password Strength",
            "SQL Injection Scan",
            "XSS Scan",
            "Brute Force Test"
        ],
        help="Select a tool to perform ethical hacking tasks."
    )

    # Auto-refresh for real-time tools
    if tool in ["Device Info", "Monitor Processes"]:
        st_autorefresh(interval=5000)  # Refresh every 5 seconds

    # Results container
    with st.container():
        st.subheader(f"Results: {tool}")

        if tool == "Device Info":
            st.write("🔍 Real-time Device Information (updates every 5 seconds)")
            with st.spinner("Fetching device info..."):
                result = get_device_info()
                if "error" not in result:
                    st.table(result)  # Display as table
                else:
                    st.error(result["error"])
                logger.info(f"Device Info: {result}")

        elif tool == "Track Location":
            if st.button("🌍 Track Location"):
                with st.spinner("Fetching location..."):
                    result = get_location()
                    if "error" not in result:
                        st.table(result)
                    else:
                        st.error(result["error"])
                    logger.info(f"Location: {result}")

        elif tool == "Monitor Processes":
            st.write("📊 Real-time Process Monitor (updates every 5 seconds)")
            with st.spinner("Fetching processes..."):
                result = monitor_processes()
                if "processes" in result:
                    st.table(result["processes"])
                else:
                    st.error(result["error"])
                logger.info(f"Processes: {result}")

        elif tool == "File Hash Check":
            file_path = st.text_input("📁 File Path", help="Enter the path to the file")
            if st.button("Calculate Hash"):
                if file_path:
                    with st.spinner("Calculating file hash..."):
                        result = check_file_hash(file_path)
                        if "error" not in result:
                            st.table(result)
                        else:
                            st.error(result["error"])
                        logger.info(f"File Hash: {result}")
                else:
                    st.warning("Please enter a file path.")

        elif tool == "Encrypt/Decrypt File":
            file_path = st.text_input("📁 File Path", help="Enter the path to the file")
            operation = st.selectbox("Operation", ["encrypt", "decrypt"], help="Choose encrypt or decrypt")
            if st.button("Process File"):
                if file_path:
                    with st.spinner(f"{operation.capitalize()}ing file..."):
                        result = encrypt_decrypt_file(file_path, operation)
                        if "error" not in result:
                            st.table(result)
                        else:
                            st.error(result["error"])
                        logger.info(f"File Operation: {result}")
                else:
                    st.warning("Please enter a file path.")

        elif tool == "Password Strength":
            password = st.text_input("🔑 Password", type="password", help="Enter a password to check")
            if st.button("Check Password"):
                if password:
                    with st.spinner("Checking password strength..."):
                        result = check_password_strength(password)
                        if "error" not in result:
                            st.table(result)
                        else:
                            st.error(result["error"])
                        logger.info(f"Password Strength: {result}")
                else:
                    st.warning("Please enter a password.")

        elif tool == "SQL Injection Scan":
            url = st.text_input("🌐 URL", value="http://example.com", help="Enter the target URL")
            if st.button("Scan SQL"):
                if url:
                    with st.spinner("Scanning for SQL Injection..."):
                        result = scan_sql_injection(url)
                        if "error" not in result:
                            st.table(result["results"])
                        else:
                            st.error(result["error"])
                        logger.info(f"SQL Injection Scan: {result}")
                else:
                    st.warning("Please enter a URL.")

        elif tool == "XSS Scan":
            url = st.text_input("🌐 URL", value="http://example.com", help="Enter the target URL")
            if st.button("Scan XSS"):
                if url:
                    with st.spinner("Scanning for XSS..."):
                        result = scan_xss(url)
                        if "error" not in result:
                            st.table(result["results"])
                        else:
                            st.error(result["error"])
                        logger.info(f"XSS Scan: {result}")
                else:
                    st.warning("Please enter a URL.")

        elif tool == "Brute Force Test":
            url = st.text_input("🌐 Login URL", value="http://example.com/login", help="Enter the login URL")
            username_field = st.text_input("Username Field", value="username")
            password_field = st.text_input("Password Field", value="password")
            if st.button("Test Brute Force"):
                if url:
                    with st.spinner("Testing brute force..."):
                        result = brute_force_login(url, username_field, password_field)
                        if "error" not in result:
                            st.table(result["results"])
                        else:
                            st.error(result["error"])
                        logger.info(f"Brute Force Test: {result}")
                else:
                    st.warning("Please enter a URL.")

if __name__ == "__main__":
    main()
