import os
from urllib.parse import urlsplit, urlunsplit

import requests
from dotenv import load_dotenv


load_dotenv()

WEB_RISK_ENDPOINT = "https://webrisk.googleapis.com/v1/uris:search"

THREAT_TYPES = [
    "SOCIAL_ENGINEERING",
    "MALWARE",
    "UNWANTED_SOFTWARE",
]


def sanitize_url_for_lookup(url: str):
    try:
        parsed = urlsplit(url)

        if not parsed.scheme or not parsed.hostname:
            return None

        # Remove embedded username/password if present
        netloc = parsed.netloc.rsplit("@", 1)[-1]

        # Remove query string and fragment before sending externally
        return urlunsplit(
            (
                parsed.scheme,
                netloc,
                parsed.path or "/",
                "",
                "",
            )
        )

    except ValueError:
        return None


def check_url_reputation(url: str):
    api_key = os.getenv("GOOGLE_WEB_RISK_API_KEY")

    if not api_key:
        return {
            "status": "unavailable",
            "threat_types": [],
        }

    safe_url = sanitize_url_for_lookup(url)

    if not safe_url:
        return {
            "status": "invalid_url",
            "threat_types": [],
        }

    params = [("uri", safe_url)]

    for threat_type in THREAT_TYPES:
        params.append(("threatTypes", threat_type))

    try:
        response = requests.get(
            WEB_RISK_ENDPOINT,
            params=params,
            headers={"X-Goog-Api-Key": api_key},
            timeout=3,
        )

        response.raise_for_status()

        data = response.json()

        threat_types = (
            data.get("threat", {})
            .get("threatTypes", [])
        )

        if threat_types:
            return {
                "status": "match",
                "threat_types": threat_types,
            }

        return {
            "status": "no_match",
            "threat_types": [],
        }

    except requests.RequestException:
        return {
            "status": "unavailable",
            "threat_types": [],
        }