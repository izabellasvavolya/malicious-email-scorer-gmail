import re
from urllib.parse import urlparse

from web_risk import check_url_reputation


MAX_URL_LOOKUPS = 3


URGENT_PHRASES = [
    "urgent",
    "immediately",
    "act now",
    "account will be suspended",
    "account suspended",
    "verify immediately",
    "limited time",
    "final warning",
]

CREDENTIAL_PHRASES = [
    "password",
    "login credentials",
    "verification code",
    "one-time password",
    "otp",
    "credit card",
    "bank account",
    "social security number",
]

FINANCIAL_SCAM_PHRASES = [
    "send money",
    "credit card details",
    "wire transfer",
    "bank transfer",
    "you won",
    "you have won",
    "million dollars",
    "inheritance",
    "prince",
]

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
}


def extract_urls(text: str):
    urls = re.findall(
        r'(?:https?://|www\.)[^\s<>"\']+',
        text
    )

    normalized_urls = []

    for url in urls:
        # Remove punctuation sometimes attached to the URL
        url = url.rstrip(".,);]")

        if url.startswith("www."):
            url = "https://" + url

        normalized_urls.append(url)

    return normalized_urls


def is_ip_address(hostname: str):
    if not hostname:
        return False

    return bool(
        re.fullmatch(
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            hostname
        )
    )


def analyze_email(sender: str, subject: str, body: str):
    score = 0
    reasons = []

    combined_text = f"{subject} {body}".lower()

    # 1. Urgency / pressure
    urgent_matches = [
        phrase for phrase in URGENT_PHRASES
        if phrase in combined_text
    ]

    if urgent_matches:
        score += 10
        reasons.append(
            "Uses urgent or pressuring language"
        )

    # 2. Sensitive information
    credential_matches = [
        phrase for phrase in CREDENTIAL_PHRASES
        if phrase in combined_text
    ]

    if credential_matches:
        score += 20
        reasons.append(
            "Requests or references sensitive information"
        )

    # 3. Financial scam language
    financial_matches = [
        phrase for phrase in FINANCIAL_SCAM_PHRASES
        if phrase in combined_text
    ]

    if financial_matches:
        score += 15
        reasons.append(
            "Contains language commonly associated with financial scams"
        )

    # 4. Local URL analysis
    urls = extract_urls(body)

    for url in urls:
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""

            if is_ip_address(hostname):
                score += 25
                reasons.append(
                    "Contains a link that uses an IP address instead of a domain"
                )

            if parsed.scheme == "http":
                score += 3
                reasons.append(
                    "Contains an unencrypted HTTP link (weak signal)"
                )

            if hostname.lower() in URL_SHORTENERS:
                score += 10
                reasons.append(
                    "Contains a shortened URL that hides the final destination"
                )

            if hostname.lower().startswith("xn--"):
                score += 20
                reasons.append(
                    "Contains an internationalized domain that may be used for lookalike attacks"
                )

        except ValueError:
            score += 5
            reasons.append(
                "Contains a malformed or unusual URL"
            )

    # 5. External URL reputation
    # Only check the first 3 unique URLs to prevent excessive API calls.
    unique_urls = list(dict.fromkeys(urls))[:MAX_URL_LOOKUPS]

    external_threats = set()

    for url in unique_urls:
        reputation = check_url_reputation(url)

        if reputation["status"] == "match":
            external_threats.update(
                reputation["threat_types"]
            )

        if external_threats:
            score += 90

            readable_threats = ", ".join(
                sorted(external_threats)
            )

            reasons.append(
                f"External threat intelligence flags a URL as: {readable_threats}"
            )   
    # 6. Sender checks
    sender_lower = sender.lower()

    if "xn--" in sender_lower:
        score += 20
        reasons.append(
            "Sender domain uses punycode and may imitate another domain"
        )

    # Cap score at 100
    score = min(score, 100)

    # Remove duplicate explanations
    reasons = list(dict.fromkeys(reasons))

    if score >= 70:
        verdict = "Critical Risk"
    elif score >= 40:
        verdict = "High Risk"
    elif score >= 20:
        verdict = "Suspicious"
    else:
        verdict = "Low Risk"

    if not reasons:
        reasons.append(
            "No strong suspicious indicators were detected by the current rules"
        )

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
    }