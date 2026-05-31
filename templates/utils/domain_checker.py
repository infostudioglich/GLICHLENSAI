import whois
from datetime import datetime

def check_domain_age(domain):

    try:
        info = whois.whois(domain)

        creation_date = info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age = (datetime.now() - creation_date).days

        return age

    except Exception:
     return None