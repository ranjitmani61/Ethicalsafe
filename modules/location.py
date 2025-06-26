import requests
import logging

logger = logging.getLogger(__name__)
IPINFO_URL = "https://ipinfo.io"

def get_location():
    try:
        res = requests.get(IPINFO_URL, timeout=5)
        res.raise_for_status()
        data = res.json()
        return {
            "ip": data.get("ip", "N/A"),
            "city": data.get("city", "N/A"),
            "region": data.get("region", "N/A"),
            "country": data.get("country", "N/A"),
            "org": data.get("org", "N/A")
        }
    except requests.RequestException as e:
        logger.error(f"Location error: {str(e)}")
        return {"error": f"Failed to fetch location: {str(e)}"}