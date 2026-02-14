from multiprocessing.resource_tracker import register
from urllib.parse import urlparse,parse_qs
import tldextract
from streamlit import rerun

from .rules import SUSPICIOUS_KEYWORDS,SHORTENER_DOMAINS,REGEX_PATTERNS
def analyze_url(url:str)->dict:
    original = url.strip()

    if not original.startswith(("http//","https://")):
        url="http://"+original
    else:
        url=original
    parsed=urlparse(url)
    host=parsed.netloc.lower()
    path=parsed.path.lower()
    query=parsed.query.lower()

    ext=tldextract.extract(host)
    registered_domain=f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    subdomain=ext.subdomain

    score = 0
    reasons=[]

    if parsed.scheme !="https":
        score +=10
        reasons.append("Not using HTTPS")

    if REGEX_PATTERNS["ip_in_domain"].search(original):

        score += 30
        reasons.append("Uses IP address instead of domain")

    if REGEX_PATTERNS["at_symbol"].search(original):
        score += 25
        reasons.append("Contains '@'(possible credential/redirect trick)")

    if subdomain :
        sub_parts = [p for p in subdomain.split(".") if p]
        if len(sub_parts)>=3:
            score += 20
            reasons.append(f"Too many subdomains ({len(sub_parts)})")

    if len(original)>=100:
        score += 15
        reasons.append("URL is too long")

    if host.count("-")>=3:
        score += 10
        reasons.append("Many hyphenes in domain")
    combined =f"{host} {path}{query}"
    hits=[k for k in SUSPICIOUS_KEYWORDS if k in combined]
    if hits:
        score+=min(25,5 *len(hits))
        reasons.append("Suspicious keywords found: " + ", ".join(hits[:6]) + ("..." if len(hits) > 6 else ""))

    if REGEX_PATTERNS["hex_encoding"].search(original):
        score += 10
        reasons.append("Uses hex encoding instead of ASCII")

    qs = parse_qs(parsed.query)
    redirect_keys = {"redirect", "return", "returnurl", "next", "continue", "url"}
    if any(k.lower() in redirect_keys for k in qs.keys()):
            score += 15
            reasons.append("Contains redirect-style query parameters")
    score=max(0,min(100,score))
    if score>=60:
        level="HIGH"
    elif score>=30:
        level="MEDIUM"
    else:
        level="LOW"
    return {
        "input": original,
        "normalized": url,
        "domain": registered_domain,
        "score": score,
        "level": level,
        "reasons": reasons

    }