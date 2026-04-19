"""
threat_intel.py — Optional VirusTotal threat intelligence integration.

Set the environment variable VT_API_KEY to enable.
Free tier: 500 lookups/day  |  https://www.virustotal.com/gui/my-apikey
"""
import base64
import logging
import os

import requests

logger = logging.getLogger(__name__)

VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_BASE    = "https://www.virustotal.com/api/v3"


def check_virustotal(url: str):
    """
    Returns a dict with scan stats, or None if key not configured / request fails.
    {
        status:     'found' | 'submitted' | 'unavailable'
        malicious:  int
        suspicious: int
        harmless:   int
        undetected: int
        total:      int
        vt_link:    str   (link to VT report)
    }
    """
    if not VT_API_KEY:
        return {"status": "unavailable", "message": "No VT_API_KEY set"}

    headers = {"x-apikey": VT_API_KEY, "Accept": "application/json"}
    url_id  = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    try:
        resp = requests.get(f"{VT_BASE}/urls/{url_id}", headers=headers, timeout=10)

        if resp.status_code == 404:
            # Not cached — submit for analysis
            sub = requests.post(f"{VT_BASE}/urls", headers=headers,
                                data={"url": url}, timeout=10)
            if sub.status_code in (200, 201):
                return {"status": "submitted",
                        "message": "URL submitted to VirusTotal — check back shortly"}
            return {"status": "unavailable", "message": "Submission failed"}

        if resp.status_code == 401:
            return {"status": "unavailable", "message": "Invalid API key"}

        if resp.status_code != 200:
            return {"status": "unavailable",
                    "message": f"VT returned HTTP {resp.status_code}"}

        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        total = sum(stats.values())
        return {
            "status":     "found",
            "malicious":  stats.get("malicious",  0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless",   0),
            "undetected": stats.get("undetected", 0),
            "total":      total,
            "vt_link":    f"https://www.virustotal.com/gui/url/{url_id}",
        }

    except requests.exceptions.Timeout:
        logger.warning("VirusTotal timeout for %s", url)
        return {"status": "unavailable", "message": "VirusTotal request timed out"}
    except Exception as exc:
        logger.warning("VirusTotal error for %s: %s", url, exc)
        return {"status": "unavailable", "message": str(exc)}
