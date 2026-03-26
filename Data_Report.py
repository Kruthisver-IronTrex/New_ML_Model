import pandas as pd
import re
import math
from urllib.parse import urlparse, unquote
from collections import defaultdict
from tqdm import tqdm
from difflib import SequenceMatcher

try:
    import tldextract
    def get_parts(hostname):
        e = tldextract.extract(hostname)
        return e.subdomain, e.domain, e.suffix
except ImportError:
    def get_parts(hostname):
        parts = hostname.rsplit(".", 2)
        return ("", parts[-2], parts[-1]) if len(parts) >= 2 else ("", hostname, "")

# ── Pre-compiled patterns ──────────────────────────────────────────────────────
FREE_HOSTS  = re.compile(r"(000webhostapp|weebly|wixsite|blogspot|wordpress|github\.io|netlify\.app|firebaseapp|glitch\.me|repl\.co|web\.app|pages\.dev|vercel\.app|surge\.sh|biz\.nf|esy\.es|hol\.es|atspace|freehosting|byethost|infinityfree)", re.I)
SHORTENERS  = re.compile(r"^(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|shorte\.st|adf\.ly|rebrand\.ly|cutt\.ly|shorturl\.at|rb\.gy|tiny\.cc|lnkd\.in|clck\.ru|mcaf\.ee|soo\.gd|bc\.vc|go2l\.ink|x\.co|qr\.ae|url4\.eu|u\.to|tr\.im|turl\.ca|tweez\.me|v\.gd|urls\.im)$", re.I)
BRANDS      = re.compile(r"(paypal|apple|google|microsoft|amazon|facebook|instagram|netflix|dropbox|linkedin|twitter|chase|wellsfargo|bankofamerica|ebay|yahoo|outlook|office365|onedrive|sharepoint|icloud|coinbase|binance|blockchain|dhl|fedex|ups|usps|irs|walmart|target|bestbuy|steam|roblox|discord|tiktok|whatsapp|telegram)", re.I)
MALICIOUS_EXT = re.compile(r"\.(exe|zip|rar|7z|tar\.gz|msi|bat|ps1|sh|apk|dmg|iso|jar|vbs|cmd|scr|pif|hta|wsf|lnk|dll|sys|reg|cab|deb|rpm|pkg|run|bin|com|cpl|inf|tmp)(\?.*)?$", re.I)
HOMOGLYPHS  = re.compile(r"[àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿа-яА-ЯёЁα-ωΑ-Ω]")
CRED_KEYS   = re.compile(r"(login|signin|sign-in|log-in|verify|secure|account|update|confirm|password|credential|auth|banking|wallet|portal|webscr|submit|validation|security|recover|unlock|suspend|billing|invoice|checkout|support|helpdesk|service|customer)", re.I)
REDIRECT_RX = re.compile(r"(redirect|url|next|goto|return|rurl|dest|destination|continue|forward|target|link|go|out|click|ref|jump|navigate)=https?", re.I)
TYPO_RX     = re.compile(r"(paypa[l1][^a-z]|g[o0][o0]gle|micr[o0]s[o0]ft|faceb[o0]{2}k|amaz[o0]n|app[l1]e[^t]|netfl[i1]x|[l1]inked[i1]n|tw[i1]tter|[o0]utl[o0]{2}k|dr[o0]pb[o0]x|paypall|g[o0]gle|micros[o0]ft|g[o0]{2}g[l1]e|[a4]pp[l1]e|y[a4]h[o0]{2}|[e3]bay|[i1]nstagram|wh[a4]ts[a4]pp)", re.I)
LOOKALIKE_RX= re.compile(r"(pay[-_]?pa[l1]|g[o0]{2,}gle|micros[o0]ft|arna[z2]on|amaz[o0][n0]|faceb[o0]{2,}k|app[l1][e3]|[l1]inked[l1]n|rnyspace|tw[i1]tt[e3]r|[i1]nstagramm?|y[a4]ho{2}|[e3]b[a4]y|d[i1]scord|st[e3][a4]m|r[o0]b[l1][o0]x)", re.I)
PUNYCODE_RX = re.compile(r"xn--")
ENCODING_RX = re.compile(r"%[0-9a-fA-F]{2}")
IP_RX       = re.compile(r"^https?://(\d{1,3}\.){3}\d{1,3}")
IP_PORT_RX  = re.compile(r"^https?://(\d{1,3}\.){3}\d{1,3}:\d+")
DATA_RX     = re.compile(r"^(data:|javascript:)", re.I)
SUSPICIOUS_TLDS = re.compile(r"\.(xyz|top|club|online|site|info|tk|ml|ga|cf|gq|pw|cc|ws|buzz|icu|cyou|fun|monster|rest|uno|works|click|link|win|loan|gdn|accountant|review|trade|science|date|faith|racing|bid|party|cricket|download|stream|gq|cf|ml|tk)$", re.I)
RANDOM_DOM  = re.compile(r"^[a-z0-9]{8,}$", re.I)
SUSPICIOUS_WORDS = re.compile(r"(free|prize|winner|lucky|reward|gift|bonus|deal|offer|promo|coupon|discount|limited|urgent|alert|warning|suspended|verify|unusual|activity|access|update|required|immediately|bank|secure|official|legit|authentic|trust|safe|protected)", re.I)

BRAND_LIST = ["paypal","google","microsoft","amazon","facebook","instagram","netflix",
              "dropbox","linkedin","twitter","apple","yahoo","ebay","coinbase","binance",
              "chase","wellsfargo","bankofamerica","discord","steam","roblox","tiktok",
              "whatsapp","telegram","outlook","icloud","onedrive","sharepoint"]

def entropy(s):
    if not s: return 0
    freq = defaultdict(int)
    for c in s: freq[c] += 1
    l = len(s)
    return -sum((v/l)*math.log2(v/l) for v in freq.values())

def brand_similarity(domain):
    domain_clean = re.sub(r"[\d\-_]", "", domain.lower())
    return any(SequenceMatcher(None, domain_clean, b).ratio() > 0.82
               for b in BRAND_LIST if abs(len(domain_clean) - len(b)) <= 3)

def digit_ratio(s):
    return sum(c.isdigit() for c in s) / len(s) if s else 0

def has_repeated_chars(s, n=4):
    return bool(re.search(r"(.)\1{" + str(n-1) + r",}", s))

def suspicious_keyword_count(url):
    return len(SUSPICIOUS_WORDS.findall(url))

def parse_url(url):
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    try:
        p = urlparse(url)
        hostname = (p.hostname or "").lower()
        sub, dom, suf = get_parts(hostname)
        return p, hostname, sub, dom, suf, url
    except Exception:
        return None, "", "", "", "", url

# ── Rules dictionary ───────────────────────────────────────────────────────────
rules = {
    "Malicious-File-Extension":  lambda u, p, h, sub, dom, suf: bool(MALICIOUS_EXT.search(p.path)),
    "Typosquatting":             lambda u, p, h, sub, dom, suf: bool(TYPO_RX.search(h)) or (brand_similarity(dom) and not any(h == b + "." + "com" for b in BRAND_LIST)),
    "Brand-Subdomain":           lambda u, p, h, sub, dom, suf: bool(BRANDS.search(sub)) and not BRANDS.search(dom),
    "Free-Hosting-Abuse":        lambda u, p, h, sub, dom, suf: bool(FREE_HOSTS.search(h)),
    "URL-Shortener-Abuse":       lambda u, p, h, sub, dom, suf: bool(SHORTENERS.match(h)),
    "Open-Redirect":             lambda u, p, h, sub, dom, suf: bool(REDIRECT_RX.search(u)),
    "Punycode":                  lambda u, p, h, sub, dom, suf: bool(PUNYCODE_RX.search(h)),
    "Homoglyph":                 lambda u, p, h, sub, dom, suf: bool(HOMOGLYPHS.search(unquote(h))),
    "Non-Standard-Port":         lambda u, p, h, sub, dom, suf: p.port is not None and p.port not in (80, 443),
    "URL-Encoding":              lambda u, p, h, sub, dom, suf: len(ENCODING_RX.findall(u)) >= 3,
    "IP-Based-Port":             lambda u, p, h, sub, dom, suf: bool(IP_PORT_RX.match(u)),
    "IP-Based":                  lambda u, p, h, sub, dom, suf: bool(IP_RX.match(u)) and not bool(IP_PORT_RX.match(u)),
    "Subdomain-Stacking":        lambda u, p, h, sub, dom, suf: h.count(".") >= 4 or sub.count(".") >= 2,
    "Deep-Path-Brand":           lambda u, p, h, sub, dom, suf: bool(BRANDS.search(p.path)) and p.path.count("/") >= 3,
    "Credential-Harvesting":     lambda u, p, h, sub, dom, suf: suspicious_keyword_count(u) >= 2 or bool(CRED_KEYS.search(p.path + "?" + (p.query or ""))),
    "HTTP-Downgrade":            lambda u, p, h, sub, dom, suf: u.startswith("http://") and bool(BRANDS.search(h)),
    "Data-URI-Javascript":       lambda u, p, h, sub, dom, suf: bool(DATA_RX.match(u)),
    "Subdomain-Confusion":       lambda u, p, h, sub, dom, suf: bool(BRANDS.search(sub)) and bool(suf) and not BRANDS.search(dom),
    "Path-Confusion":            lambda u, p, h, sub, dom, suf: bool(re.search(r"https?://", unquote(p.path), re.I)) or bool(re.search(r"https?%3A", p.path, re.I)),
    "Lookalike-Domain":          lambda u, p, h, sub, dom, suf: bool(LOOKALIKE_RX.search(dom + "." + suf)),
    "Random-Suspicious-Domain":  lambda u, p, h, sub, dom, suf: (bool(RANDOM_DOM.match(dom)) and bool(SUSPICIOUS_TLDS.search("." + suf)) and len(dom) >= 7) or (entropy(dom) > 3.7 and bool(SUSPICIOUS_TLDS.search("." + suf))),
}

# ── Secondary heuristics for unclassified URLs ────────────────────────────────
def secondary_classify(u, p, h, sub, dom, suf):
    tags = []
    ent = entropy(dom)
    url_len = len(u)
    path_depth = p.path.count("/")
    drat = digit_ratio(dom)

    if ent > 3.5 or (ent > 3.0 and len(dom) > 12):              tags.append("Random-Suspicious-Domain")
    if url_len > 100:                                             tags.append("Credential-Harvesting")
    if url_len > 200:                                             tags.append("Deep-Path-Brand")
    if path_depth >= 5:                                           tags.append("Deep-Path-Brand")
    if drat > 0.4 and len(dom) > 5:                              tags.append("Random-Suspicious-Domain")
    if has_repeated_chars(dom, 3):                                tags.append("Typosquatting")
    if suspicious_keyword_count(u) >= 1:                          tags.append("Credential-Harvesting")
    if bool(SUSPICIOUS_TLDS.search("." + suf)):                  tags.append("Random-Suspicious-Domain")
    if brand_similarity(dom):                                      tags.append("Lookalike-Domain")
    if bool(BRANDS.search(u)) and u.startswith("http://"):       tags.append("HTTP-Downgrade")
    if bool(BRANDS.search(sub)):                                  tags.append("Subdomain-Confusion")
    if h.count(".") >= 3 and bool(BRANDS.search(h)):             tags.append("Brand-Subdomain")
    if len(dom) > 20 and re.search(r"[a-z]{15,}", dom):         tags.append("Random-Suspicious-Domain")
    if bool(re.search(r"@", u)):                                  tags.append("Credential-Harvesting")
    if bool(re.search(r"(\.php|\.asp|\.jsp)\?", u, re.I)):       tags.append("Credential-Harvesting")
    return list(dict.fromkeys(tags))

# ── Main loop ─────────────────────────────────────────────────────────────────
df = pd.read_csv(r"Data\train.csv")
phishing = df[df["Label"] == 1]["URL"].dropna().tolist()

counts = defaultdict(int)
classified_count = 0
unclassified = []

for url in tqdm(phishing, desc="Classifying URLs", unit="url"):
    try:
        p, h, sub, dom, suf, url = parse_url(url)
        if p is None:
            unclassified.append(url); continue

        matched = [name for name, fn in rules.items() if fn(url, p, h, sub, dom, suf)]

        if not matched:
            matched = secondary_classify(url, p, h, sub, dom, suf)

        if len(matched) > 1 and "Mixed-Attack" not in matched:
            matched.append("Mixed-Attack")

        if matched:
            classified_count += 1
            for m in matched: counts[m] += 1
        else:
            unclassified.append(url)
    except Exception:
        unclassified.append(url)

# ── Save unclassified ─────────────────────────────────────────────────────────
if unclassified:
    def extract_info(url):
        try:
            p, h, sub, dom, suf, url = parse_url(url)
            return {"url": url, "domain": h, "length": len(url),
                    "entropy": round(entropy(dom), 3),
                    "has_digits": bool(re.search(r"\d", url)),
                    "special_chars": len(re.findall(r"[^a-zA-Z0-9/:._-]", url)),
                    "path_depth": (p.path.count("/") if p else 0),
                    "suspicious_keywords": suspicious_keyword_count(url)}
        except Exception:
            return {"url": url, "domain": None, "length": len(url), "entropy": 0,
                    "has_digits": False, "special_chars": 0, "path_depth": 0, "suspicious_keywords": 0}

    pd.DataFrame([extract_info(u) for u in tqdm(unclassified, desc="Extracting unclassified", unit="url")]) \
      .to_csv("unclassified_urls.csv", index=False)

# ── Summary ───────────────────────────────────────────────────────────────────
summary = pd.DataFrame(sorted(counts.items(), key=lambda x: -x[1]), columns=["Type", "Count"])
print("\n" + summary.to_string(index=False))
print(f"\nClassified URLs  : {classified_count}")
print(f"Unclassified URLs: {len(unclassified)}")