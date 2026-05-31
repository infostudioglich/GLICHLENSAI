import whois
from datetime import datetime

def get_whois_info(domain):
    try:
        w = whois.whois(domain)

        creation_date = w.creation_date
        expiration_date = w.expiration_date

        # Handle multiple dates
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        age_days = None

        if creation_date:

            # Remove timezone if present
            if hasattr(creation_date, "tzinfo") and creation_date.tzinfo:
                creation_date = creation_date.replace(tzinfo=None)

            age_days = (datetime.now() - creation_date).days

            # Date only
            creation_date = creation_date.strftime("%Y-%m-%d")

        if expiration_date:

            if hasattr(expiration_date, "tzinfo") and expiration_date.tzinfo:
                expiration_date = expiration_date.replace(tzinfo=None)

            expiration_date = expiration_date.strftime("%Y-%m-%d")

        return {
            "success": True,
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "registrar": w.registrar,
            "age_days": age_days
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }