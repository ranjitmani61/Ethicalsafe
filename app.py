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
   from modules.wifi import get_wifi_passwords
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
       st.title("Ethical Hacking Dashboard")
       st.write("Use these tools only on your own devices/networks with permission.")
       
       # Sidebar for navigation
       st.sidebar.header("Select Tool")
       tool = st.sidebar.selectbox("Choose a tool", [
           "Device Info", "Track Location", "Monitor Processes", 
           "File Hash Check", "Wi-Fi Passwords", "Encrypt/Decrypt File", 
           "Password Strength", "SQL Injection Scan", "XSS Scan", "Brute Force Test"
       ])

       # Auto-refresh for real-time feel
       if tool in ["Device Info", "Monitor Processes"]:
           st_autorefresh(interval=5000)  # Refresh every 5 seconds

       # Results container
       results = st.container()

       if tool == "Device Info":
           with results:
               st.write("Real-time Device Info (updates every 5 seconds)")
               result = get_device_info()
               st.json(result)
               logger.info(f"Device Info: {result}")

       elif tool == "Track Location":
           if st.button("Track Location"):
               with results:
                   result = get_location()
                   st.json(result)
                   logger.info(f"Location: {result}")

       elif tool == "Monitor Processes":
           with results:
               st.write("Real-time Process Monitor (updates every 5 seconds)")
               result = monitor_processes()
               st.json(result)
               logger.info(f"Processes: {result}")

       elif tool == "File Hash Check":
           file_path = st.text_input("File Path")
           if st.button("Check File Hash") and file_path:
               with results:
                   result = check_file_hash(file_path)
                   st.json(result)
                   logger.info(f"File Hash: {result}")

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

   if __name__ == "__main__":
       main()
