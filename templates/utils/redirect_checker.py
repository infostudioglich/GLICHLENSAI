import requests

def check_redirects(url):

    try:
        response = requests.get(url, allow_redirects=True)

        redirects = len(response.history)

        return redirects

    except:
        return 0