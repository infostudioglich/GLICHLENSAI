import requests
import time

API_KEY = "640e606a8f55a832006b724454557c615ee3071bbe5cb4d44c1a229333934fee"


def check_virustotal(url):

    headers = {
        "x-apikey": API_KEY
    }

    try:

        # Submit URL
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )

        data = response.json()

        analysis_id = data["data"]["id"]

        # Wait for analysis
        time.sleep(3)

        # Fetch result
        result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        result_response = requests.get(
            result_url,
            headers=headers
        )

        result_data = result_response.json()

        malicious = result_data["data"]["attributes"]["stats"]["malicious"]

        return malicious

    except Exception as e:

        print("VirusTotal Error:", e)

        return 0