import os
import requests
import time
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_BASE = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": VT_API_KEY,
    "Accept": "application/json"
}


def is_configured():
    return bool(VT_API_KEY)


def check_url(url):
    """Submit a URL to VirusTotal and return scan results."""
    if not is_configured():
        return {"error": "No VirusTotal API key configured", "url": url}

    try:
        # Submit URL for analysis
        resp = requests.post(
            f"{VT_BASE}/urls",
            headers=HEADERS,
            data={"url": url},
            timeout=10
        )
        if resp.status_code != 200:
            return {"error": f"VT submission failed: {resp.status_code}", "url": url}

        analysis_id = resp.json()["data"]["id"]
        time.sleep(2)  # Wait for scan

        # Get results
        result_resp = requests.get(
            f"{VT_BASE}/analyses/{analysis_id}",
            headers=HEADERS,
            timeout=10
        )
        if result_resp.status_code != 200:
            return {"error": "Failed to retrieve VT results", "url": url}

        data = result_resp.json()["data"]["attributes"]
        stats = data.get("stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        total = malicious + suspicious + harmless + stats.get("undetected", 0)

        return {
            "url": url,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "total_engines": total,
            "verdict": "MALICIOUS" if malicious > 0 else ("SUSPICIOUS" if suspicious > 0 else "CLEAN"),
            "error": None
        }

    except requests.exceptions.Timeout:
        return {"error": "VirusTotal request timed out", "url": url}
    except Exception as e:
        return {"error": str(e), "url": url}


def check_urls_batch(urls, max_urls=5):
    """Check up to max_urls from a list against VirusTotal."""
    if not is_configured():
        return []

    results = []
    for url in urls[:max_urls]:
        result = check_url(url)
        results.append(result)
        time.sleep(1)  # Respect rate limit (4 requests/min on free tier)

    return results