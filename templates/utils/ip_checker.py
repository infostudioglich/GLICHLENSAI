import socket
from urllib.parse import urlparse
import requests


def get_ip_info(url):

    try:
        parsed = urlparse(url)

        domain = parsed.netloc

        # DNS lookup
        ip_address = socket.gethostbyname(domain)

        try:
            response = requests.get(
                url,
                timeout=5,
                allow_redirects=True
            )

            status = response.status_code

        except Exception:
            status = "DOWN"

        return {
            "ip": ip_address,
            "status": status
        }

    except Exception:
        return {
            "ip": "Unknown",
            "status": "Error"
        }