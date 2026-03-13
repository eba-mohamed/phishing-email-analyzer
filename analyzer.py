import re
from urllib.parse import urlparse
from email_parser import extract_domain, extract_url_domains


# ── Phishing keyword lists ─────────────────────────────────────────────────────

URGENCY_KEYWORDS = [
    "urgent", "immediately", "action required", "account suspended",
    "verify now", "click here", "limited time", "expire", "warning",
    "unusual activity", "unauthorized", "confirm your", "update your",
    "suspended", "locked", "blocked", "validate", "security alert",
    "your account", "login attempt", "password reset", "verify your identity",
    "act now", "final notice", "last chance", "risk", "compromise"
]

SUSPICIOUS_PHRASES = [
    "dear customer", "dear user", "dear account holder",
    "congratulations you have won", "you have been selected",
    "claim your prize", "free gift", "100% free", "no cost",
    "guaranteed", "winner", "lottery", "inheritance", "million dollars",
    "wire transfer", "western union", "bitcoin", "cryptocurrency",
    "kindly", "do the needful"
]

SUSPICIOUS_ATTACHMENT_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".vbs", ".js", ".jar", ".ps1",
    ".scr", ".pif", ".com", ".zip", ".rar", ".7z", ".iso",
    ".docm", ".xlsm", ".xlam", ".xltm"
]

LEGITIMATE_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "google.com", "facebook.com", "twitter.com", "linkedin.com",
    "github.com", "dropbox.com"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "rebrand.ly", "short.io", "cutt.ly", "tiny.cc"
]


# ── Analysis functions ─────────────────────────────────────────────────────────

def check_sender_spoofing(parsed):
    """Check if the From domain differs from Reply-To or Return-Path domains."""
    flags = []
    from_domain = extract_domain(parsed["from"])
    reply_domain = extract_domain(parsed["reply_to"]) if parsed["reply_to"] else ""
    return_domain = extract_domain(parsed["return_path"]) if parsed["return_path"] else ""

    if reply_domain and from_domain and reply_domain != from_domain:
        flags.append({
            "type": "SENDER_SPOOFING",
            "severity": "HIGH",
            "detail": f"From domain '{from_domain}' differs from Reply-To domain '{reply_domain}'"
        })

    if return_domain and from_domain and return_domain != from_domain:
        flags.append({
            "type": "RETURN_PATH_MISMATCH",
            "severity": "MEDIUM",
            "detail": f"From domain '{from_domain}' differs from Return-Path domain '{return_domain}'"
        })

    return flags


def check_urgency_language(parsed):
    """Scan body text for urgency and manipulation keywords."""
    flags = []
    body = (parsed["body_text"] + " " + parsed["body_html"] + " " + parsed["subject"]).lower()

    found_urgency = [kw for kw in URGENCY_KEYWORDS if kw in body]
    found_suspicious = [kw for kw in SUSPICIOUS_PHRASES if kw in body]

    if len(found_urgency) >= 3:
        flags.append({
            "type": "HIGH_URGENCY_LANGUAGE",
            "severity": "HIGH",
            "detail": f"Multiple urgency keywords detected: {', '.join(found_urgency[:5])}"
        })
    elif found_urgency:
        flags.append({
            "type": "URGENCY_LANGUAGE",
            "severity": "MEDIUM",
            "detail": f"Urgency keywords found: {', '.join(found_urgency[:3])}"
        })

    if found_suspicious:
        flags.append({
            "type": "SUSPICIOUS_PHRASES",
            "severity": "MEDIUM",
            "detail": f"Suspicious phrases found: {', '.join(found_suspicious[:3])}"
        })

    return flags


def check_links(parsed):
    """Analyze links for suspicious patterns."""
    flags = []
    links = parsed["links"]

    if not links:
        return flags

    url_domains = extract_url_domains(links)

    # Check for URL shorteners
    shorteners_found = [d for d in url_domains if d in URL_SHORTENERS]
    if shorteners_found:
        flags.append({
            "type": "URL_SHORTENER",
            "severity": "MEDIUM",
            "detail": f"URL shorteners detected (hides real destination): {', '.join(shorteners_found)}"
        })

    # Check for IP address URLs (e.g. http://192.168.1.1/login)
    ip_urls = [u for u in links if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u)]
    if ip_urls:
        flags.append({
            "type": "IP_ADDRESS_URL",
            "severity": "HIGH",
            "detail": f"Links using raw IP addresses instead of domain names: {ip_urls[0]}"
        })

    # Check for mismatched anchor text vs actual URL (basic check)
    from_domain = extract_domain(parsed["from"])
    suspicious_links = []
    for url in links:
        try:
            parsed_url = urlparse(url)
            netloc = parsed_url.netloc.lower()
            # Flag if URL contains a known brand but sender is different
            for legit in LEGITIMATE_DOMAINS:
                brand = legit.split(".")[0]
                if brand in netloc and from_domain and brand not in from_domain:
                    suspicious_links.append(url)
                    break
        except Exception:
            pass

    if suspicious_links:
        flags.append({
            "type": "BRAND_IMPERSONATION_URL",
            "severity": "HIGH",
            "detail": f"Links appear to impersonate a known brand: {suspicious_links[0][:80]}"
        })

    # Many links in one email
    if len(links) > 10:
        flags.append({
            "type": "EXCESSIVE_LINKS",
            "severity": "LOW",
            "detail": f"Email contains {len(links)} links — unusually high count"
        })

    return flags


def check_attachments(parsed):
    """Check attachments for dangerous file types."""
    flags = []
    for att in parsed["attachments"]:
        fname = att["filename"].lower()
        for ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS:
            if fname.endswith(ext):
                flags.append({
                    "type": "DANGEROUS_ATTACHMENT",
                    "severity": "CRITICAL",
                    "detail": f"Dangerous attachment detected: '{att['filename']}' ({ext} files can execute malware)"
                })
                break

        # Double extension trick (e.g. invoice.pdf.exe)
        if fname.count(".") >= 2:
            flags.append({
                "type": "DOUBLE_EXTENSION",
                "severity": "HIGH",
                "detail": f"Possible double extension trick: '{att['filename']}'"
            })

    return flags


def check_header_anomalies(parsed):
    """Check email headers for authentication failures and anomalies."""
    flags = []
    headers = {k.lower(): v for k, v in parsed["headers"].items()}

    # Check for missing authentication headers
    if "dkim-signature" not in headers:
        flags.append({
            "type": "MISSING_DKIM",
            "severity": "LOW",
            "detail": "Email lacks DKIM signature — sender authenticity cannot be verified"
        })

    # Check for suspicious subject patterns
    subject = parsed["subject"].lower()
    if re.search(r'^(re:|fw:|fwd:)', subject) and not parsed["reply_to"]:
        flags.append({
            "type": "FAKE_REPLY_SUBJECT",
            "severity": "MEDIUM",
            "detail": "Subject starts with Re:/Fwd: but email is not a reply — common phishing trick"
        })

    # No subject
    if not parsed["subject"]:
        flags.append({
            "type": "MISSING_SUBJECT",
            "severity": "LOW",
            "detail": "Email has no subject line"
        })

    return flags


# ── Risk scoring ───────────────────────────────────────────────────────────────

SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH":     25,
    "MEDIUM":   10,
    "LOW":       5
}

def calculate_risk_score(all_flags):
    """Calculate a 0-100 risk score from all flags."""
    score = 0
    for flag in all_flags:
        score += SEVERITY_WEIGHTS.get(flag["severity"], 0)
    return min(score, 100)


def get_verdict(score):
    """Return a verdict based on the risk score."""
    if score >= 70:
        return "PHISHING", "red"
    elif score >= 40:
        return "SUSPICIOUS", "orange"
    elif score >= 15:
        return "LOW RISK", "yellow"
    else:
        return "LIKELY SAFE", "green"


# ── Main analyze function ──────────────────────────────────────────────────────

def analyze(parsed):
    """Run all heuristic checks and return full analysis result."""
    all_flags = []
    all_flags += check_sender_spoofing(parsed)
    all_flags += check_urgency_language(parsed)
    all_flags += check_links(parsed)
    all_flags += check_attachments(parsed)
    all_flags += check_header_anomalies(parsed)

    score = calculate_risk_score(all_flags)
    verdict, color = get_verdict(score)

    return {
        "flags":        all_flags,
        "risk_score":   score,
        "verdict":      verdict,
        "verdict_color": color,
        "total_flags":  len(all_flags),
        "critical":     sum(1 for f in all_flags if f["severity"] == "CRITICAL"),
        "high":         sum(1 for f in all_flags if f["severity"] == "HIGH"),
        "medium":       sum(1 for f in all_flags if f["severity"] == "MEDIUM"),
        "low":          sum(1 for f in all_flags if f["severity"] == "LOW"),
    }