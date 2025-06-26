import requests
import logging
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

def scan_sql_injection(url):
    """
    Scan a URL for SQL injection vulnerabilities using common payloads.
    
    Args:
        url (str): Target URL to scan.
    
    Returns:
        dict: Dictionary containing scan results or error message.
    """
    try:
        payloads = ["' OR 1=1 --", "'; DROP TABLE users; --"]
        results = []
        for payload in payloads:
            test_url = f"{url}?id={payload}"
            response = requests.get(test_url, timeout=5)
            is_vulnerable = "error" in response.text.lower() or response.status_code == 500
            results.append({"payload": payload, "vulnerable": is_vulnerable})
            logger.info(f"SQL Injection scan for {test_url}: {'Vulnerable' if is_vulnerable else 'Not Vulnerable'}")
        return {"results": results}
    except Exception as e:
        logger.error(f"SQL Injection scan error: {str(e)}")
        return {"error": f"Failed to scan SQL injection: {str(e)}"}

def scan_xss(url):
    """
    Scan a URL for XSS vulnerabilities using common payloads.
    
    Args:
        url (str): Target URL to scan.
    
    Returns:
        dict: Dictionary containing scan results or error message.
    """
    try:
        payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
        results = []
        for payload in payloads:
            response = requests.get(url, params={"q": payload}, timeout=5)
            is_vulnerable = payload in response.text
            results.append({"payload": payload, "vulnerable": is_vulnerable})
            logger.info(f"XSS scan for {url} with payload {payload}: {'Vulnerable' if is_vulnerable else 'Not Vulnerable'}")
        return {"results": results}
    except Exception as e:
        logger.error(f"XSS scan error: {str(e)}")
        return {"error": f"Failed to scan XSS: {str(e)}"}

def brute_force_login(url, username_field, password_field):
    """
    Test a login URL for brute force vulnerabilities with common passwords.
    
    Args:
        url (str): Login URL to test.
        username_field (str): Name of the username field.
        password_field (str): Name of the password field.
    
    Returns:
        dict: Dictionary containing brute force results or error message.
    """
    try:
        passwords = ["password", "admin123", "test"]
        results = []
        for password in passwords:
            response = requests.post(url, data={username_field: "admin", password_field: password}, timeout=5)
            is_success = "login successful" in response.text.lower()
            results.append({"password": password, "success": is_success})
            logger.info(f"Brute force attempt for {url} with password {password}: {'Success' if is_success else 'Failed'}")
        return {"results": results}
    except Exception as e:
        logger.error(f"Brute force error: {str(e)}")
        return {"error": f"Failed to test brute force: {str(e)}"}
