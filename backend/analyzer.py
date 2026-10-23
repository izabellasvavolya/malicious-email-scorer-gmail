import re
from urllib.parse import urlparse


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

    # 2. Requests for sensitive information
    credential_matches = [
        phrase for phrase in CREDENTIAL_PHRASES
        if phrase in combined_text
    ]

    if credential_matches:
        score += 20
        reasons.append(
            "Requests or references sensitive information"
        )

    # 3. URLs
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

    # 4. Sender checks
    sender_lower = sender.lower()

    if "xn--" in sender_lower:
        score += 20
        reasons.append(
            "Sender domain uses punycode and may imitate another domain"
        )

    # Don't exceed 100
    score = min(score, 100)

    # Remove duplicate reasons
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
        "reasons": reasons
    }