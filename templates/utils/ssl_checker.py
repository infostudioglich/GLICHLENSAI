import requests

def check_ssl(url):
    try:
        response = requests.get(url, timeout=5)

        if response.url.startswith("https://"):
            return True

        return False

    except:
        return False