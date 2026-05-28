import requests

def check_redirects(url):

    try:
        response = requests.get(
            url,
            allow_redirects=True,
            timeout=5
        )

        redirects = len(response.history)

        return redirects

    except Exception:
        return 0