from ai_analyzer import analyze_email_with_ai

import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.utils import parseaddr

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


def get_email_domain(address: str):
    if not address:
        return ""

    _, email_address = parseaddr(address)

    if "@" not in email_address:
        return ""

    return email_address.rsplit("@", 1)[1].lower()


def analyze_email(
    sender: str,
    subject: str,
    body: str,
    reply_to: str = "",
    authentication_results: str = ""
):
    # Limit untrusted input size
    sender = sender[:500]
    subject = subject[:500]
    body = body[:10000]

    score = 0
    reasons = []

    combined_text = f"{subject} {body}".lower()

    # --------------------------------------------------
    # 1. Urgency / pressure
    # --------------------------------------------------

    urgent_matches = [
        phrase
        for phrase in URGENT_PHRASES
        if phrase in combined_text
    ]

    if urgent_matches:
        score += 10
        reasons.append(
            "Uses urgent or pressuring language"
        )

    # --------------------------------------------------
    # 2. Sensitive information
    # --------------------------------------------------

    credential_matches = [
        phrase
        for phrase in CREDENTIAL_PHRASES
        if phrase in combined_text
    ]

    if credential_matches:
        score += 20
        reasons.append(
            "Requests or references sensitive information"
        )

    # --------------------------------------------------
    # 3. Financial scam language
    # --------------------------------------------------

    financial_matches = [
        phrase
        for phrase in FINANCIAL_SCAM_PHRASES
        if phrase in combined_text
    ]

    if financial_matches:
        score += 15
        reasons.append(
            "Contains language commonly associated with financial scams"
        )

    # --------------------------------------------------
    # 4. Local URL analysis
    # --------------------------------------------------

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

    # --------------------------------------------------
    # 5. Sender checks
    # --------------------------------------------------

    sender_lower = sender.lower()

    # Punycode / lookalike sender domain
    if "xn--" in sender_lower:
        score += 20
        reasons.append(
            "Sender domain uses punycode and may imitate another domain"
        )

    # From / Reply-To mismatch
    sender_domain = get_email_domain(sender)
    reply_to_domain = get_email_domain(reply_to)

    if (
        sender_domain
        and reply_to_domain
        and sender_domain != reply_to_domain
    ):
        score += 10
        reasons.append(
            "Reply-To domain differs from the sender domain"
        )

    # SPF / DKIM / DMARC authentication checks
    auth_results = authentication_results.lower()

    if re.search(
        r"\bspf=(fail|softfail)\b",
        auth_results
    ):
        score += 10
        reasons.append(
            "SPF authentication failed"
        )

    if re.search(
        r"\bdkim=fail\b",
        auth_results
    ):
        score += 10
        reasons.append(
            "DKIM authentication failed"
        )

    if re.search(
        r"\bdmarc=fail\b",
        auth_results
    ):
        score += 25
        reasons.append(
            "DMARC authentication failed"
        )

    # --------------------------------------------------
    # 6. External analysis
    #
    # Google Web Risk and AI run in parallel.
    # --------------------------------------------------

    unique_urls = list(
        dict.fromkeys(urls)
    )[:MAX_URL_LOOKUPS]

    external_threats = set()
    ai_analysis = None

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {}

        # Start AI analysis
        ai_future = executor.submit(
            analyze_email_with_ai,
            sender=sender,
            subject=subject,
            body=body
        )

        futures[ai_future] = "ai"

        # Start Web Risk checks at the same time
        for url in unique_urls:
            web_risk_future = executor.submit(
                check_url_reputation,
                url
            )

            futures[web_risk_future] = "web_risk"

        # Collect results as they finish
        for future in as_completed(futures):
            source = futures[future]

            try:
                result = future.result()

                if source == "ai":
                    ai_analysis = result

                elif source == "web_risk":
                    if (
                        result
                        and result.get("status") == "match"
                    ):
                        external_threats.update(
                            result.get("threat_types", [])
                        )

            except Exception:
                # External services should not crash
                # the whole scanner.
                continue

    # --------------------------------------------------
    # 7. Apply Web Risk result
    # --------------------------------------------------

    if external_threats:
        score += 90

        readable_threats = ", ".join(
            sorted(external_threats)
        )

        reasons.append(
            f"External threat intelligence flags a URL as: "
            f"{readable_threats}"
        )

    # --------------------------------------------------
    # 8. Apply AI semantic analysis
    # --------------------------------------------------

    if ai_analysis and ai_analysis.suspicious:

        if ai_analysis.severity.value == "high":
            score += 40

        elif ai_analysis.severity.value == "medium":
            score += 15

        elif ai_analysis.severity.value == "low":
            score += 5

        reasons.append(
            f"AI analysis: {ai_analysis.explanation}"
        )

    # --------------------------------------------------
    # 9. Final score
    # --------------------------------------------------

    score = min(score, 100)

    # Remove duplicate explanations
    reasons = list(dict.fromkeys(reasons))

    # --------------------------------------------------
    # 10. Verdict
    # --------------------------------------------------

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