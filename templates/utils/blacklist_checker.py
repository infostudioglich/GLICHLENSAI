blacklist = [
    "malicious.com",
    "phishing-site.com",
    "fakebank.com"
]

def check_blacklist(url):

    for bad in blacklist:

        if bad in url:
            return True

    return False