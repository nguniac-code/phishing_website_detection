"""Deterministic, local-only URL normalization and feature extraction."""

import ipaddress
import re
from urllib.parse import urlsplit

import pandas as pd

from config import FEATURE_NAMES


_SUSPICIOUS_KEYWORDS = (
    "account",
    "bank",
    "confirm",
    "login",
    "password",
    "paypal",
    "secure",
    "signin",
    "update",
    "verify",
    "wallet",
)
_SPECIAL_CHARACTERS = set("@?=%&_~!$'()*+,;:")


def normalize_url(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Enter a URL as text.")
    url = value.strip()
    if not url or len(url) > 4096:
        raise ValueError("Enter a non-empty URL of at most 4,096 characters.")
    if any(ord(character) < 32 or character.isspace() for character in url):
        raise ValueError("URL must not contain whitespace or control characters.")
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", url):
        url = "https://" + url.lstrip("/")
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("The URL contains an invalid host or port.") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        raise ValueError("Enter a valid HTTP or HTTPS website URL.")
    if len(hostname) > 253 or "." not in hostname.strip("."):
        raise ValueError("Enter a URL with a valid domain name.")
    if any(character in hostname for character in "<>[]"):
        raise ValueError("The URL contains an invalid domain name.")
    return url


def extract_url_features(value: str) -> dict[str, int]:
    url = normalize_url(value)
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    labels = [label for label in hostname.split(".") if label]
    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    lowered = url.lower()
    return {
        "url_length": len(url),
        "domain_length": len(hostname),
        "num_dots": hostname.count("."),
        "num_hyphens": hostname.count("-"),
        "num_subdomains": max(0, len(labels) - 2),
        "has_https": int(parsed.scheme.lower() == "https"),
        "has_ip": has_ip,
        "suspicious_keyword_count": sum(
            lowered.count(keyword) for keyword in _SUSPICIOUS_KEYWORDS
        ),
        "special_char_count": sum(character in _SPECIAL_CHARACTERS for character in url),
        "path_length": len(parsed.path),
        "num_digits": sum(character.isdigit() for character in url),
    }


def extract_features(urls: list[str]) -> pd.DataFrame:
    """Return rows in the exact feature order used by trained model artifacts."""
    rows = [extract_url_features(url) for url in urls]
    return pd.DataFrame(rows, columns=FEATURE_NAMES)