import email
import re
from email import policy
from email.parser import BytesParser, Parser
from urllib.parse import urlparse


def parse_email(file_path=None, raw_text=None):
    """Parse an .eml file or raw email text and extract all relevant fields."""
    
    if file_path:
        with open(file_path, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
    elif raw_text:
        msg = Parser(policy=policy.default).parsestr(raw_text)
    else:
        raise ValueError("Provide either file_path or raw_text")

    result = {
        "subject":      msg.get("Subject", ""),
        "from":         msg.get("From", ""),
        "to":           msg.get("To", ""),
        "reply_to":     msg.get("Reply-To", ""),
        "date":         msg.get("Date", ""),
        "message_id":   msg.get("Message-ID", ""),
        "return_path":  msg.get("Return-Path", ""),
        "headers":      dict(msg.items()),
        "body_text":    "",
        "body_html":    "",
        "links":        [],
        "attachments":  [],
    }

    # Walk parts
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            disp = str(part.get_content_disposition() or "")
            if "attachment" in disp:
                result["attachments"].append({
                    "filename": part.get_filename() or "unknown",
                    "content_type": ct,
                    "size": len(part.get_payload(decode=True) or b"")
                })
            elif ct == "text/plain" and not result["body_text"]:
                result["body_text"] = part.get_payload(decode=True).decode("utf-8", errors="replace")
            elif ct == "text/html" and not result["body_html"]:
                result["body_html"] = part.get_payload(decode=True).decode("utf-8", errors="replace")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            result["body_text"] = payload.decode("utf-8", errors="replace")

    # Extract URLs from body
    text_to_scan = result["body_text"] + result["body_html"]
    urls = re.findall(r'https?://[^\s\'"<>]+', text_to_scan)
    result["links"] = list(set(urls))  # deduplicate

    return result


def extract_domain(email_address):
    """Extract domain from an email address string."""
    match = re.search(r'@([\w.-]+)', email_address)
    return match.group(1).lower() if match else ""


def extract_url_domains(links):
    """Extract unique domains from a list of URLs."""
    domains = []
    for url in links:
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                domains.append(parsed.netloc.lower())
        except Exception:
            pass
    return list(set(domains))