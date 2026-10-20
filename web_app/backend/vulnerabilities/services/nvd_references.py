"""Safe, bounded references included in the NVD CPE product dictionary.

NVD supplies links, not an independent guarantee that the destinations are
authoritative. No HTTP requests are performed here.
"""
import ipaddress
import re
from urllib.parse import urlsplit

MAX_NVD_REFERENCES = 20
MAX_URL_LENGTH = 2048


def safe_reference_url(value):
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_URL_LENGTH:
        return None
    if value != value.strip() or any(ord(ch) <= 32 or ord(ch) == 127 for ch in value):
        return None
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if (parsed.scheme.lower() != "https" or not host
                or parsed.username is not None or parsed.password is not None
                or parsed.port not in (None, 443)
                or len(parsed.fragment) > 256):
            return None
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            pass
        host = host.lower().rstrip(".")
        labels = host.split(".")
        if (host == "localhost" or host.endswith((".localhost", ".local", ".internal",
                                                   ".test", ".invalid", ".example"))
                or len(labels) < 2 or len(host) > 253
                or all(label.isdigit() for label in labels)
                or any(len(label) > 63 or re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label, flags=re.ASCII
                ) is None for label in labels)):
            return None
    except (ValueError, TypeError):
        return None
    return value


def safe_references(raw):
    """Accept NVD {'ref','type'} and normalized {'url','type'} entries."""
    if not isinstance(raw, list):
        return []
    result, visited = [], set()
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        url = safe_reference_url(entry.get("url", entry.get("ref")))
        if not url or url in visited:
            continue
        source_type = entry.get("type")
        if isinstance(source_type, list):
            source_type = next((t for t in source_type if isinstance(t, str)), "")
        if not isinstance(source_type, str):
            source_type = ""
        source_type = source_type.strip()
        if not source_type:
            tags = entry.get("tags")
            if isinstance(tags, list):
                source_type = next((t.strip() for t in tags if isinstance(t, str) and t.strip()), "")
        if len(source_type) > 60 or any(ord(ch) < 32 or ord(ch) == 127 for ch in source_type):
            source_type = "Referencia"
        result.append({"url": url, "type": source_type or "Referencia", "source": "NVD"})
        visited.add(url)
        if len(result) >= MAX_NVD_REFERENCES:
            break
    return result


def combine_references(*lists):
    """Stable deduplication across NVD strategies for the same UUID."""
    all_references = []
    for entries in lists:
        if isinstance(entries, list):
            all_references.extend(entries)
    return safe_references(all_references)
