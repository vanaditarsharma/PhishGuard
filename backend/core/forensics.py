"""Deterministic, offline-first email forensics for PhishGuard 2.0."""
from __future__ import annotations
import hashlib, html, ipaddress, math, mimetypes, re
from collections import Counter
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse, unquote
from core.advanced_intel import url_features
from core.attachment_scanner import inspect_attachment
YARA_RULES = Path(__file__).resolve().parents[1] / "yara" / "phishguard_basic.yar"

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "tiny.cc"}
URGENT = {"urgent", "immediately", "suspend", "suspended", "expire", "expired", "verify", "verification", "action required", "within 24 hours", "limited time"}
CREDENTIAL = {"password", "sign in", "log in", "login", "account", "credential", "authentication", "unlock", "reset"}
PAYMENT = {"wire transfer", "bank account", "invoice", "payment", "gift card", "payroll", "bank details", "change of account"}
BRANDS = ["paypal", "microsoft", "office365", "google", "amazon", "apple", "dhl", "netflix", "linkedin", "github", "dropbox"]
DANGEROUS_EXT = {".exe", ".scr", ".js", ".vbs", ".hta", ".iso", ".img", ".bat", ".cmd", ".ps1", ".lnk", ".jar", ".docm", ".xlsm"}


def _entropy(s: str) -> float:
    if not s: return 0.0
    counts = Counter(s)
    return -sum((n/len(s))*math.log2(n/len(s)) for n in counts.values())


def _domain(url: str) -> str:
    try: return (urlparse(url if "://" in url else "http://"+url).hostname or "").lower().rstrip(".")
    except Exception: return ""


def _is_ip(host: str) -> bool:
    try: ipaddress.ip_address(host); return True
    except ValueError: return False


def _safe_filename(name: str) -> str:
    return Path(name.replace('\\', '/')).name[:180]


def parse_email(raw: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    sender = str(msg.get("From", "Unknown"))
    from_name, from_addr = parseaddr(sender)
    reply_name, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    return_path = parseaddr(str(msg.get("Return-Path", "")))[1]
    plain_parts, html_parts, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart(): continue
        ctype = part.get_content_type().lower()
        disp = str(part.get("Content-Disposition", "")).lower()
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if filename or "attachment" in disp:
            name = _safe_filename(filename or "unnamed-attachment")
            ext = Path(name).suffix.lower()
            guessed = mimetypes.guess_type(name)[0]
            magic = "unknown"
            if payload.startswith(b"MZ"): magic = "windows_pe"
            elif payload.startswith(b"%PDF-"): magic = "pdf"
            elif payload.startswith(b"PK\x03\x04"): magic = "zip_container"
            elif payload.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"): magic = "ole_compound_document"
            elif payload.startswith(b"\x7fELF"): magic = "elf_executable"
            elif payload.startswith(b"\x89PNG"): magic = "png"
            elif payload.startswith(b"GIF8"): magic = "gif"
            scan=inspect_attachment(payload,name,YARA_RULES)
            attachments.append({"filename": name, "content_type": ctype, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest(), "extension": ext, "dangerous_extension": ext in DANGEROUS_EXT, "mime_mismatch": bool(ext and guessed and guessed != ctype), "magic_type": magic, "magic_extension_mismatch": bool(magic in {"windows_pe","elf_executable","ole_compound_document"} and ext not in {".exe",".dll",".scr",".doc",".docx",".xls",".xlsx",".docm",".xlsm"}), "double_extension": bool(re.search(r"\.(pdf|docx?|xlsx?|jpg|png)\.(exe|scr|js|vbs|bat|cmd|ps1)$", name, re.I)), "scan":scan})
        elif ctype == "text/plain":
            try: plain_parts.append(part.get_content())
            except Exception: plain_parts.append(payload.decode("utf-8", "replace"))
        elif ctype == "text/html":
            try: html_parts.append(part.get_content())
            except Exception: html_parts.append(payload.decode("utf-8", "replace"))
    plain = "\n".join(plain_parts).strip()
    html_body = "\n".join(html_parts).strip()
    # Conservative HTML-to-text fallback; preserve raw HTML for structural checks.
    visible_html = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html_body)
    visible_html = re.sub(r"(?s)<[^>]+>", " ", visible_html)
    visible_html = html.unescape(re.sub(r"\s+", " ", visible_html)).strip()
    body = plain or visible_html
    headers = {k: str(v) for k, v in msg.items()}
    auth_raw = "\n".join(msg.get_all("Authentication-Results", []))
    received_spf = "\n".join(msg.get_all("Received-SPF", []))
    auth = {}
    for key in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{key}\s*=\s*([a-z]+)", auth_raw, re.I)
        auth[key] = m.group(1).lower() if m else "unknown"
    if auth["spf"] == "unknown":
        m = re.search(r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", received_spf, re.I)
        if m: auth["spf"] = m.group(1).lower()
    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
    dkim_domains = re.findall(r"\bd=([^;\s]+)", auth_raw, re.I)
    spf_domains = re.findall(r"smtp\.mailfrom=([^;\s]+)", auth_raw, re.I)
    from_headers = msg.get_all("From", [])
    reply_domain = reply_addr.split("@")[-1].lower() if "@" in reply_addr else ""
    return {
        "sender": sender, "sender_name": from_name, "sender_address": from_addr,
        "subject": str(msg.get("Subject", "(No Subject)")), "date": str(msg.get("Date", "Unknown")),
        "message_id": str(msg.get("Message-ID", "")), "reply_to": str(msg.get("Reply-To", "")),
        "return_path": return_path, "from_domain": from_domain, "reply_domain": reply_domain,
        "headers": headers, "received_headers": [str(v) for v in msg.get_all("Received", [])],
        "authentication": auth, "authentication_results_raw": auth_raw or "Not present",
        "dkim_signing_domains": dkim_domains, "spf_mailfrom_domains": spf_domains,
        "authentication_alignment": {"dkim_aligned": any(x.lower()==from_domain or x.lower().endswith("."+from_domain) for x in dkim_domains) if dkim_domains and from_domain else None, "spf_aligned": any(x.lower()==from_domain or x.lower().endswith("."+from_domain) for x in spf_domains) if spf_domains and from_domain else None},
        "header_anomalies": {"multiple_from_headers": len(from_headers)>1, "display_name_domain_mismatch": bool(from_name and from_domain and any(b in from_name.lower() for b in ("paypal","microsoft","google","amazon","apple","dhl")) and not any(b in from_domain.lower() for b in ("paypal","microsoft","google","amazon","apple","dhl")))},
        "body": body, "plain_body": plain, "html_body": html_body,
        "html_analysis": {"has_html": bool(html_body), "has_forms": bool(re.search(r"(?i)<form\b", html_body)), "has_password_field": bool(re.search(r"(?i)type\s*=\s*['\"]?password", html_body)), "has_hidden_elements": bool(re.search(r"(?i)display\s*:\s*none|visibility\s*:\s*hidden|type\s*=\s*['\"]?hidden", html_body)), "plain_html_text_mismatch": bool(plain and visible_html and abs(len(plain)-len(visible_html)) > max(100, len(plain)*0.65))},
        "attachments": attachments, "urls": analyze_urls(body + "\n" + html_body),
        "raw_sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)
    }


def analyze_urls(text: str) -> list[dict]:
    results, seen = [], set()
    for match in URL_RE.findall(text or ""):
        raw = match.rstrip(".,);]}>")
        if raw in seen: continue
        seen.add(raw)
        normalized = raw if raw.lower().startswith("http") else "http://" + raw
        p = urlparse(normalized)
        host = (p.hostname or "").lower().rstrip(".")
        flags = []
        if p.scheme != "https": flags.append("non_https")
        if host in SHORTENERS: flags.append("shortened_url")
        if _is_ip(host): flags.append("ip_literal")
        if host.count(".") >= 3: flags.append("excessive_subdomains")
        if "@" in p.netloc: flags.append("userinfo_in_url")
        if len(raw) > 100: flags.append("long_url")
        if _entropy(p.path + p.query) > 4.2 and len(p.path + p.query) > 18: flags.append("high_url_entropy")
        if host.startswith("xn--") or ".xn--" in host: flags.append("punycode_domain")
        if any(t in (host + p.path).lower() for t in ("login", "verify", "secure", "account", "update", "wallet", "password")): flags.append("credential_or_brand_bait")
        brand_matches = [b for b in BRANDS if b in (host + p.path).lower() and not host.endswith(b + ".com") and (b not in host.split(".")[-2])]
        if brand_matches: flags.append("possible_brand_impersonation")
        advanced = url_features(raw)
        results.append({"url": raw, "domain": host, "scheme": p.scheme, "path": p.path, "query_length": len(p.query), "length": len(raw), "entropy": round(_entropy(p.path+p.query), 3), "flags": sorted(set(flags + advanced.get("flags", []))), "brand_matches": brand_matches or advanced.get("brand_similarity", []), "features": advanced})
    return results


def analyze_evidence(parsed: dict) -> dict:
    body = (parsed.get("body") or "").lower()
    subject = (parsed.get("subject") or "").lower()
    full = subject + " " + body
    auth = parsed.get("authentication", {})
    urls = parsed.get("urls", [])
    attachments = parsed.get("attachments", [])
    signals = []
    dimensions = {"authentication": 0, "headers": 0, "urls": 0, "attachments": 0, "language": 0, "behaviour": 0}
    def add(dim, points, code, title, detail):
        dimensions[dim] = min(100, dimensions[dim] + points)
        signals.append({"dimension": dim, "points": points, "code": code, "title": title, "detail": detail})
    for key in ("spf", "dkim", "dmarc"):
        val = auth.get(key, "unknown")
        if val == "fail": add("authentication", 22 if key == "dmarc" else 12, f"{key}_fail", f"{key.upper()} reported fail", "Receiver-stamped Authentication-Results reports a failure; this is evidence, not a fresh cryptographic verification.")
        elif val in ("softfail", "permerror", "temperror"): add("authentication", 7, f"{key}_{val}", f"{key.upper()} reported {val}", "Authentication result is weak or indeterminate.")
    alignment=parsed.get("authentication_alignment",{})
    if alignment.get("dkim_aligned") is False: add("authentication",12,"dkim_alignment_fail","DKIM domain is not aligned","The observed DKIM signing domain does not align with the visible From domain.")
    if alignment.get("spf_aligned") is False: add("authentication",10,"spf_alignment_fail","SPF mail-from domain is not aligned","The observed SPF envelope domain does not align with the visible From domain.")
    if parsed.get("header_anomalies", {}).get("multiple_from_headers"): add("headers", 28, "multiple_from_headers", "Multiple From headers", "The message contains more than one From header; this is structurally anomalous.")
    if parsed.get("header_anomalies", {}).get("display_name_domain_mismatch"): add("headers", 16, "display_name_mismatch", "Brand-like display name mismatch", "The display name resembles a major brand but the sender domain does not.")
    if parsed.get("reply_domain") and parsed.get("from_domain") and parsed["reply_domain"] != parsed["from_domain"]:
        add("headers", 22, "reply_to_domain_mismatch", "Reply-To domain differs", f"From uses {parsed['from_domain']} while Reply-To uses {parsed['reply_domain']}.")
    if parsed.get("return_path") and parsed.get("sender_address") and parsed["return_path"].lower() != parsed["sender_address"].lower():
        add("headers", 10, "return_path_mismatch", "Return-Path differs from From", "The envelope return path does not match the visible sender address.")
    if len(parsed.get("received_headers", [])) == 0: add("headers", 5, "no_received_trace", "No Received trace", "No Received headers were present in the uploaded message.")
    for u in urls:
        for flag, pts, title in [("ip_literal",22,"URL uses an IP literal"),("shortened_url",12,"URL uses a shortening service"),("possible_brand_impersonation",24,"Possible brand impersonation"),("brand_lookalike",22,"Possible lookalike brand domain"),("punycode_domain",18,"Punycode domain"),("userinfo_in_url",18,"URL contains user-info"),("high_url_entropy",8,"High-entropy URL path"),("credential_or_brand_bait",7,"Credential-related URL wording"),("excessive_subdomains",7,"Excessive subdomains"),("non_https",4,"URL does not use HTTPS")]:
            if flag in u.get("flags", []): add("urls", pts, f"url_{flag}", title, u["url"])
    for a in attachments:
        if a.get("dangerous_extension"): add("attachments", 28, "dangerous_attachment_extension", "Potentially risky attachment type", a["filename"])
        if a.get("magic_extension_mismatch"): add("attachments", 30, "attachment_magic_mismatch", "File signature conflicts with extension", f"{a['filename']} has signature {a.get('magic_type')}.")
        if a.get("double_extension"): add("attachments", 24, "double_extension", "Double file extension", a["filename"])
        if a.get("scan",{}).get("yara",{}).get("matches"): add("attachments", 35, "yara_match", "YARA rule matched attachment bytes", ", ".join(a["scan"]["yara"]["matches"]))
        if a.get("scan",{}).get("clamav",{}).get("infected"): add("attachments", 60, "clamav_detection", "ClamAV reported a detection", a["filename"])
        if a.get("scan",{}).get("qr_codes"): add("attachments", 18, "qr_code_present", "QR code detected in attachment", "QR payload(s): "+", ".join(a["scan"]["qr_codes"][:3]))
        if a.get("mime_mismatch"): add("attachments", 24, "attachment_mime_mismatch", "Attachment extension and MIME type differ", a["filename"])
        if a.get("size", 0) > 15*1024*1024: add("attachments", 5, "large_attachment", "Large attachment", f"{a['filename']} is larger than 15 MiB.")
    urgent_hits = sorted(t for t in URGENT if t in full)
    credential_hits = sorted(t for t in CREDENTIAL if t in full)
    payment_hits = sorted(t for t in PAYMENT if t in full)
    if urgent_hits: add("language", min(24, 7+4*len(urgent_hits)), "urgency_language", "Urgency or pressure language", ", ".join(urgent_hits))
    if credential_hits: add("language", min(22, 5+3*len(credential_hits)), "credential_language", "Credential or account language", ", ".join(credential_hits))
    if payment_hits: add("behaviour", min(28, 8+5*len(payment_hits)), "payment_request_language", "Payment or bank-change language", ", ".join(payment_hits))
    bec_patterns={"secrecy_request":r"\b(keep this confidential|do not tell|don't tell|keep this between us)\b","channel_switch":r"\b(use whatsapp|message me privately|personal email|outside the company)\b","executive_impersonation":r"\b(ceo|cfo|chief executive|managing director|director)\b"}
    for code,pattern in bec_patterns.items():
        if re.search(pattern,full,re.I): add("behaviour",9,code,code.replace('_',' ').title(),"Business email compromise/social-engineering phrase detected.")
    if parsed.get("html_analysis", {}).get("has_password_field"): add("behaviour", 22, "html_password_form", "HTML contains a password field", "A password input was found in the email HTML.")
    if parsed.get("html_analysis", {}).get("has_forms"): add("behaviour", 12, "html_form", "HTML contains a form", "An embedded form was found; inspect its action offline before interacting.")
    if parsed.get("html_analysis", {}).get("has_hidden_elements"): add("behaviour", 8, "hidden_html_content", "HTML contains hidden elements", "Hidden content may be used to conceal text or links.")
    # Evidence dimensions are transparent heuristic indices, not probabilities.
    weights = {"authentication":.15,"headers":.15,"urls":.25,"attachments":.20,"language":.10,"behaviour":.15}
    total_weight = sum(weights[d] for d,v in dimensions.items() if v > 0)
    weighted = sum(weights[d]*v for d,v in dimensions.items())
    risk = round(min(100, weighted))
    if risk >= 80: verdict, severity = "phishing", "critical"
    elif risk >= 60: verdict, severity = "phishing", "high"
    elif risk >= 40: verdict, severity = "suspicious", "medium"
    elif risk >= 20: verdict, severity = "suspicious", "low"
    else: verdict, severity = "legitimate", "low"
    # Missing auth evidence cannot be interpreted as a pass. Low evidence scores are not proof of safety.
    manual = not any(v not in ("unknown", "none") for v in auth.values()) or (risk >= 20 and risk < 45)
    if verdict == "legitimate" and (not urls and not attachments): manual = True
    confidence = min(.94, .45 + (len(signals)*.055) + (min(risk,80)/400))
    if manual: confidence = min(confidence, .68)
    technique = "business_email_compromise" if payment_hits else "credential_harvesting" if credential_hits else "spoofing" if parsed.get("reply_domain") and parsed["reply_domain"] != parsed.get("from_domain") else "malicious_link" if urls else "malicious_attachment" if attachments else "social_engineering" if urgent_hits else "none_detected"
    reasons = [s["title"] + ": " + s["detail"] for s in signals]
    reasoning = "No high-risk heuristic indicators were found. This is not proof that the email is safe." if not reasons else "Evidence-based findings: " + " | ".join(reasons)
    return {"verdict": verdict, "severity": severity, "risk_score": risk, "confidence": round(confidence,3), "technique": technique, "signals": signals, "dimensions": dimensions, "manual_review_required": manual, "reasoning": reasoning, "score_type": "heuristic_risk_index_not_probability", "weights": weights}


def coaching_for(result: dict) -> str:
    if result["verdict"] == "phishing":
        return "Do not click links, open attachments, reply, or share credentials. Report the message to your security team. Verify unusual requests through a separately known contact channel."
    if result["verdict"] == "suspicious":
        return "Pause before taking action. Check the sender and destination using a trusted channel, and ask your security team to review the message. Do not use links or contact details supplied in the email."
    return "No strong phishing indicators were detected by the current checks. Still verify unexpected requests and report anything that feels unusual; automated analysis cannot guarantee an email is safe."
