from flask import Flask, render_template, request
import validators
import re
import joblib
from urllib.parse import urlparse

# Import utility files
from templates.utils.blacklist_checker import check_blacklist
from templates.utils.domain_checker import check_domain_age
from templates.utils.redirect_checker import check_redirects
from templates.utils.ssl_checker import check_ssl
from templates.utils.virustotal_checker import check_virustotal
from templates.utils.ip_checker import get_ip_info
app = Flask(__name__)

# Load trained ML model
model = joblib.load('phishing_model.pkl')

# Suspicious keywords
SUSPICIOUS_WORDS = [
    'login',
    'verify',
    'bank',
    'secure',
    'account',
    'update',
    'signin',
    'free',
    'bonus',
    'trigger',
    'trycloudflare'
]


# Extract URL features
def extract_features(url):

    url_length = len(url)

    has_https = 1 if url.startswith("https") else 0

    has_ip = 1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', url) else 0

    suspicious_count = 0

    for word in SUSPICIOUS_WORDS:
        if word in url.lower():
            suspicious_count += 1

    return [
        url_length,
        has_https,
        has_ip,
        suspicious_count
    ]


# Calculate risk score
def calculate_risk(
    features,
    blacklist_found,
    domain_age,
    redirects,
    ssl_valid,
    vt_malicious
):

    url_length, has_https, has_ip, suspicious_count = features

    score = 0

    # URL length
    if url_length > 75:
        score += 20

    # HTTPS check
    if has_https == 0:
        score += 25

    # IP address check
    if has_ip == 1:
        score += 30

    # Suspicious keywords
    score += suspicious_count * 10

    # Blacklist
    if blacklist_found:
        score += 40

    # Domain age
    if domain_age < 30:
        score += 20

    # Redirects
    if redirects > 3:
        score += 15

    # SSL validation
    if not ssl_valid:
        score += 20

    # VirusTotal result
    score += vt_malicious * 5

    return min(score, 100)


@app.route('/', methods=['GET', 'POST'])
def index():

    result = None
    risk_score = 0
    reasons = []

    if request.method == 'POST':

        url = request.form['url']

        ip_info = get_ip_info(url)

        ip_address = ip_info["ip"]

        server_status = ip_info["status"]

        # Validate URL
        if not validators.url(url):

            result = 'Invalid URL'

            return render_template(
                'index.html',
                result=result,
                risk_score=risk_score,
                reasons=reasons
            )
        # Extract features
        features = extract_features(url)

        # ML Prediction
        prediction = model.predict([features])[0]

        # Domain extract
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Utility checks
        blacklist_found = check_blacklist(url)

        domain_age = check_domain_age(domain)

        redirects = check_redirects(url)

        ssl_valid = check_ssl(url)

        vt_malicious = check_virustotal(url)

        # Risk Score
        risk_score = calculate_risk(
            features,
            blacklist_found,
            domain_age,
            redirects,
            ssl_valid,
            vt_malicious
        )

        # Explanations
        if features[0] > 75:
            reasons.append("URL is too long")

        if features[1] == 0:
            reasons.append("Website does not use HTTPS")

        if features[2] == 1:
            reasons.append("IP address detected in URL")

        if features[3] > 0:
            reasons.append("Suspicious keywords detected")

            reasons.append(f"Server IP  : {ip_address}")

            reasons.append(f"Server Status  : {server_status}")

        if blacklist_found:
            reasons.append("URL found in blacklist database")

        if domain_age < 30:
            reasons.append("Domain is very new")

        if redirects > 3:
            reasons.append(f"Too many redirects detected ({redirects})")

        if not ssl_valid:
            reasons.append("SSL certificate validation failed")

        if vt_malicious > 0:
            reasons.append(f"VirusTotal detected {vt_malicious} malicious reports")
        else:
            reasons.append("VirusTotal found no malicious reports")
        # Final Status
        if risk_score <= 30:
            result = 'SAFE'

        elif risk_score <= 60:
            result = 'SUSPICIOUS'

        else:
            result = 'DANGEROUS'

    return render_template(
        'index.html',
        result=result,
        risk_score=risk_score,
        reasons=reasons
    )


if __name__ == '__main__':
    app.run(debug=True, port=8080)