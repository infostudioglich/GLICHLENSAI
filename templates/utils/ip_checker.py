import socket
from urllib.parse import urlparse
import requests


def get_ip_info(url):

    try:

        parsed = urlparse(url)

        domain = parsed.netloc

        ip_address = socket.gethostbyname(domain)

        try:

            response = requests.get(url, timeout=5)

            status = response.status_code

        except:

            status = "DOWN"

        return {
            "ip": ip_address,
            "status": status
        }

    except:

        return {
            "ip": "Unknown",
            "status": "Error"
        }