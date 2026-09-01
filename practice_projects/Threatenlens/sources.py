"""
sources.py

Contains ALL external threat-intelligence source functions for ThreatLens.

Every source function must:
  - accept (target, target_type)
  - return a dict shaped like:
        {"source": "<Name>", "status": "success", "data": {...}}
    or
        {"source": "<Name>", "status": "error", "error": "<message>"}

To add a new source:
  1. Write one function:  def get_newsource(target, target_type): ...
  2. Register it:         SOURCES["NewSource"] = get_newsource

No other file needs to change. app.py discovers sources purely through
the SOURCES dict below.

NOTE: app.py must never be imported here. This file has zero knowledge
of Streamlit, Gemini, or the UI.
"""

import os
import requests
import whois


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

def get_virustotal(target, target_type):
    """Query VirusTotal for the given target and return a normalized result."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return {
            "source": "VirusTotal",
            "status": "error",
            "error": "VIRUSTOTAL_API_KEY is not set.",
        }

    headers = {"x-apikey": api_key}

    try:
        if target_type == "IP Address":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"

        elif target_type == "Domain":
            url = f"https://www.virustotal.com/api/v3/domains/{target}"

        elif target_type == "URL":
            # VirusTotal identifies URLs by a URL-safe base64 id (no padding).
            import base64
            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

            # If VT hasn't seen this URL before, submit it for analysis first.
            lookup_resp = requests.get(url, headers=headers, timeout=15)
            if lookup_resp.status_code == 404:
                submit_resp = requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": target},
                    timeout=15,
                )
                if submit_resp.status_code not in (200, 201):
                    return {
                        "source": "VirusTotal",
                        "status": "error",
                        "error": f"Failed to submit URL for analysis "
                                 f"(HTTP {submit_resp.status_code}).",
                    }
                # Re-check the now-registered URL record.
                lookup_resp = requests.get(url, headers=headers, timeout=15)

            response = lookup_resp

        else:
            return {
                "source": "VirusTotal",
                "status": "error",
                "error": f"Unsupported target type: {target_type}",
            }

        if target_type != "URL":
            response = requests.get(url, headers=headers, timeout=15)

        if response.status_code != 200:
            return {
                "source": "VirusTotal",
                "status": "error",
                "error": f"VirusTotal API returned HTTP {response.status_code}.",
            }

        payload = response.json()
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        reputation = attributes.get("reputation")
        categories = attributes.get("categories")

        return {
            "source": "VirusTotal",
            "status": "success",
            "data": {
                "analysis_stats": stats,
                "reputation": reputation,
                "categories": categories,
            },
        }

    except requests.exceptions.RequestException as exc:
        return {
            "source": "VirusTotal",
            "status": "error",
            "error": f"Network error while contacting VirusTotal: {exc}",
        }
    except Exception as exc:  # noqa: BLE001 - never let a source crash the app
        return {
            "source": "VirusTotal",
            "status": "error",
            "error": f"Unexpected error: {exc}",
        }


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

def get_whois(target, target_type):
    """Look up WHOIS registration data for a domain (or a URL's host)."""
    try:
        # WHOIS is only meaningful for domains and URL hosts, not raw IPs.
        if target_type == "IP Address":
            return {
                "source": "WHOIS",
                "status": "error",
                "error": "WHOIS lookups are not performed for raw IP addresses.",
            }

        lookup_target = target
        if target_type == "URL":
            from urllib.parse import urlparse
            lookup_target = urlparse(target).netloc or target

        record = whois.whois(lookup_target)

        # python-whois returns an object where fields may be missing, a
        # single value, or a list. Normalize into simple JSON-friendly data.
        def normalize(value):
            if isinstance(value, list):
                return [str(v) for v in value]
            if value is None:
                return None
            return str(value)

        data = {
            "domain_name": normalize(record.domain_name),
            "registrar": normalize(record.registrar),
            "creation_date": normalize(record.creation_date),
            "expiration_date": normalize(record.expiration_date),
            "updated_date": normalize(record.updated_date),
            "name_servers": normalize(record.name_servers),
            "status": normalize(record.status),
            "org": normalize(getattr(record, "org", None)),
            "country": normalize(getattr(record, "country", None)),
        }

        # If WHOIS returned essentially nothing useful, treat as incomplete
        # rather than crashing or silently pretending we have full data.
        if not any(data.values()):
            return {
                "source": "WHOIS",
                "status": "error",
                "error": "No WHOIS data was returned for this target.",
            }

        return {
            "source": "WHOIS",
            "status": "success",
            "data": data,
        }

    except Exception as exc:  # noqa: BLE001 - WHOIS libs raise many error types
        return {
            "source": "WHOIS",
            "status": "error",
            "error": f"WHOIS lookup failed: {exc}",
        }


# ---------------------------------------------------------------------------
# Source Registry — the single extension point for new sources
# ---------------------------------------------------------------------------

SOURCES = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}