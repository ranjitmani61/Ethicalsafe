import requests
import logging

logger = logging.getLogger(__name__)

def get_location():
    """
    Retrieve geolocation information using an external API.
    
    Returns:
        dict: Dictionary containing location details or error message.
    """
    try:
        response = requests.get("http://ip-api.com/json/", timeout=5)
        response.raise_for_status()
        data = response.json()
        location = {
            "ip": data.get("query", "N/A"),
            "city": data.get("city", "N/A"),
            "region": data.get("regionName", "N/A"),
            "country": data.get("country", "N/A"),
            "latitude": data.get("lat", "N/A"),
            "longitude": data.get("lon", "N/A")
        }
        logger.info("Location retrieved successfully")
        return location
    except Exception as e:
        logger.error(f"Location error: {str(e)}")
        return {"error": f"Failed to retrieve location: {str(e)}"}
