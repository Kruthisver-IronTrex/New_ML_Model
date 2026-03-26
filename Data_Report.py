import re, math, pandas as pd
from urllib.parse import urlparse, unquote
from collections import defaultdict
from difflib import SequenceMatcher
from tqdm import tqdm

try:
    import tldextract as _tld
    def _split(h): e = _tld.extract(h); return e.subdomain, e.domain, e.suffix
except ImportError:
    def _split(h):
        p = h.rsplit(".", 2)
        return ("", p[-2], p[-1]) if len(p) >= 2 else ("", h, "")

# ══════════════════════════════════════════════════════
# 1. REGEX CONSTANTS
# ══════════════════════════════════════════════════════

_FREE    = re.compile(r"(000webhostapp|weebly|wixsite|blogspot|wordpress\.com|github\.io|netlify\.app|firebaseapp\.com|glitch\.me|repl\.co|web\.app|pages\.dev|vercel\.app|surge\.sh|byethost|infinityfree|tripod\.com|angelfire|jimdo|webnode|yolasite|ucoz|site123|strikingly|awardspace)", re.I)
_SHORT   = re.compile(r"^(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|shorte\.st|adf\.ly|rebrand\.ly|cutt\.ly|shorturl\.at|rb\.gy|tiny\.cc|lnkd\.in|clck\.ru|soo\.gd|bc\.vc|qrco\.de|bit\.do|t2m\.io|short\.io|bl\.ink|rotf\.lol|v\.gd|u\.to|tr\.im|tweez\.me)$", re.I)
_DDNS    = re.compile(r"(duckdns\.org|no-ip\.|ddns\.net|afraid\.org|bounceme\.net|hopto\.org|myftp\.|myvnc\.|sytes\.net|zapto\.org|dynu\.com|dyn\.com|noip\.com|dyndns\.|changeip\.|3utilities\.com|publicvm\.com|ddnsking\.com)", re.I)
_BRANDS  = re.compile(r"(paypal|apple|google|microsoft|amazon|facebook|instagram|netflix|dropbox|linkedin|twitter|chase|wellsfargo|bankofamerica|ebay|yahoo|outlook|office365|onedrive|sharepoint|icloud|coinbase|binance|dhl|fedex|ups|usps|steam|roblox|discord|tiktok|whatsapp|telegram|citibank|hsbc|barclays|natwest|santander|lloyds|americanexpress|capitalone|robinhood|cashapp|venmo|stripe|shopify|spotify|adobe|zoom|intuit|turbotax)", re.I)
_TYPOS   = re.compile(r"(paypa[l1][^a-z]|g[o0][o0]gle|micr[o0]s[o0]ft|faceb[o0]{2}k|amaz[o0]n|app[l1]e(?!t)|netfl[i1]x|[l1]inked[i1]n|tw[i1]tter|dr[o0]pb[o0]x|paypall|g[o0]{2}g[l1]e|y[a4]h[o0]{2}|[e3]bay|[i1]nstagramm?|wh[a4]ts[a4]pp|d[i1]sc[o0]rd|g00g1e|micros0ft|facebo0k|t[i1]kt[o0]k)", re.I)
_LOOK    = re.compile(r"(pay[-_]?pa[l1]|g[o0]{2,}gle|micros[o0]ft|arna[z2]on|amaz[o0][n0]|faceb[o0]{2,}k|app[l1][e3]|[l1]inked[l1]n|tw[i1]tt[e3]r|y[a4]ho{2}|[e3]b[a4]y|d[i1]scord|st[e3][a4]m|r[o0]b[l1][o0]x|[i1]cl[o0]ud|sh[o0]p[i1]fy|sp[o0]t[i1]fy|wh[a4]tsapp|t[i1]kt[o0]k|[o0]utl[o0]{2}k)", re.I)
_MALEXT  = re.compile(r"\.(exe|zip|rar|7z|msi|bat|ps1|sh|apk|dmg|iso|jar|vbs|cmd|scr|pif|hta|wsf|lnk|dll|cab|deb|rpm|xll|xlam|docm|xlsm|pptm)(\?.*)?$", re.I)
_HOMO    = re.compile(r"[\u00C0-\u024F\u0370-\u03FF\u0400-\u04FF]")
_CRED    = re.compile(r"(login|signin|sign[-_]in|log[-_]in|verify|secure|account|update|confirm|password|credential|auth(?:enticate)?|banking|wallet|portal|webscr|validation|security|recover|unlock|suspend|billing|invoice|checkout|username|passwd|reset|reactivate|2fa|otp|token|identity|ssn|cvv|expir)", re.I)
_REDIR   = re.compile(r"(?:^|&)(?:redirect|redir|url|next|goto|return(?:url|to)?|rurl|dest(?:ination)?|continue|forward|target|callback|fallback|successurl|cancelurl)=", re.I)
_SUSP_W  = re.compile(r"(free|prize|winner|lucky|reward|gift|bonus|deal|offer|promo|coupon|discount|limited|urgent|alert|warning|suspended|verify|unusual|activity|required|expire[ds]?|blocked|frozen|restricted|compromised|unauthorized|action.required|confirm.now)", re.I)
_STLDS   = re.compile(r"\.(xyz|top|club|online|site|tk|ml|ga|cf|gq|pw|cc|ws|buzz|icu|cyou|fun|monster|rest|uno|works|click|link|win|loan|gdn|accountant|review|trade|science|date|faith|racing|bid|party|cricket|download|stream|vip|live|shop|store|tech|digital|space|zone|rocks|guru|ninja|ru|cn|su|to|la)$", re.I)
_PCODE   = re.compile(r"xn--")
_ENC     = re.compile(r"%[0-9a-fA-F]{2}")
_DATAURI = re.compile(r"^(data:|javascript:)", re.I)
_AT      = re.compile(r"https?://[^@\s]{1,256}@")
_IPHOST  = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_IPHPORT = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")   # port checked via f["port"]
_CMS     = re.compile(r"/(wp-(?:login|admin|content|includes|config|json|cron)|phpmyadmin|xmlrpc\.php|administrator|cpanel|joomla|drupal|magento|prestashop|opencart|typo3)(?:/|\.php|$)", re.I)
_WMAIL   = re.compile(r"(webmail\.|roundcube|squirrelmail|horde|zimbra|owa\.|autodiscover\.)", re.I)
_ADULT   = re.compile(r"(porn|(?<![a-z])sex(?![a-z])|nude|naked|xxx|erotic|hentai|milf|cumshot|fetish|bdsm|stripclub|escort|hookup|onlyfan|camgirl|nsfw|xvideo|xhamster|redtube|youporn|pornhub|brazzers)", re.I)
_IPFS    = re.compile(r"(ipfs\.io/ipfs|\.ipfs\.|ipfs\.dweb|cloudflare-ipfs)", re.I)
_HEXSUB  = re.compile(r"^[a-f0-9]{20,}$", re.I)
_NUMLONG = re.compile(r"^\d{6,}$")
_PATHURL = re.compile(r"https?://", re.I)
_RNDDOM  = re.compile(r"^[a-z0-9]{8,}$", re.I)
_TRKSUB  = re.compile(r"^(track|click|redirect|trk|go|out|link|ad|ads|promo|pixel|imp|beacon|stat|hit)\.", re.I)
_LEGITTR = re.compile(r"(google-analytics\.com|googletagmanager\.com|segment\.com|amplitude\.com|mixpanel\.com|hotjar\.com|cloudflare\.com|fastly\.com|akamai|cloudfront\.net)", re.I)

BRAND_LIST = ["paypal","google","microsoft","amazon","facebook","instagram","netflix","dropbox",
              "linkedin","twitter","apple","yahoo","ebay","coinbase","binance","chase","wellsfargo",
              "bankofamerica","discord","steam","roblox","tiktok","whatsapp","telegram","outlook",
              "icloud","onedrive","sharepoint","citibank","hsbc","barclays","natwest","santander",
              "lloyds","americanexpress","capitalone","robinhood","cashapp","venmo","stripe",
              "shopify","spotify","adobe","zoom","intuit","turbotax"]
_BRAND_SET = set(BRAND_LIST)

# ══════════════════════════════════════════════════════
# 2. HELPER FUNCTIONS
# ══════════════════════════════════════════════════════

def _entropy(s):
    if not s: return 0.0
    f = defaultdict(int)
    for c in s: f[c] += 1
    n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in f.values())

def _fuzzy_brand(dom):
    """SequenceMatcher brand similarity — skips exact brand names (legitimate)."""
    clean = re.sub(r"[\d\-_\.]", "", dom.lower())
    if not clean or clean in _BRAND_SET: return False
    return any(SequenceMatcher(None, clean, b).ratio() > 0.82
               for b in BRAND_LIST if abs(len(clean) - len(b)) <= 3)

def _external_redirect(url, host):
    """True if redirect param target has a different registered domain."""
    m = re.search(r"=https?://([^/&\s]+)", url, re.I)
    if not m: return False
    tgt = m.group(1).lower().split(":")[0]
    reg = lambda h: ".".join(h.rsplit(".", 2)[-2:]) if "." in h else h
    return reg(tgt) != reg(host)

# ══════════════════════════════════════════════════════
# 3. URL PARSER — single parse, all features cached
# ══════════════════════════════════════════════════════

def _parse(raw):
    url = raw.strip()
    if not re.match(r"^https?://", url, re.I): url = "http://" + url
    try:
        p              = urlparse(url)
        host           = (p.hostname or "").lower()
        sub, dom, suf  = _split(host)
        path, query    = p.path or "", p.query or ""
        ent            = _entropy(dom)
        return {
            "url": url, "p": p, "host": host, "sub": sub, "dom": dom, "suf": suf,
            "path": path, "query": query, "pq": path + "?" + query,
            "port": p.port,
            "ent": ent, "dlen": len(dom), "ulen": len(url),
            "drat": sum(c.isdigit() for c in dom) / len(dom) if dom else 0,
            "enc": len(_ENC.findall(url)),
            "depth": path.count("/"),
            "skw": len(_SUSP_W.findall(url)),
        }
    except Exception:
        return None

# ══════════════════════════════════════════════════════
# 4. RULE FUNCTIONS  (each = one real phishing behaviour)
# ══════════════════════════════════════════════════════

# ── Identity ──────────────────────────────────────────
# Strong leet/misspelling regex against known brands
def r_typo_rx(f):    return bool(_TYPOS.search(f["host"]))
# Fuzzy match gated by corroborating signal (avoids amazonblog.com FP)
def r_typo_fz(f):
    return _fuzzy_brand(f["dom"]) and (
        bool(_STLDS.search("." + f["suf"])) or f["ent"] > 3.0
        or f["skw"] >= 1 or bool(_CRED.search(f["pq"])))
# Visual character substitutions targeting specific brand names
def r_look(f):       return bool(_LOOK.search(f["dom"] + "." + f["suf"]))
# Unicode lookalike characters (Cyrillic/Greek) in hostname
def r_homo(f):       return bool(_HOMO.search(unquote(f["host"])))
# Internationalised domain names (xn--) used for homograph attacks
def r_pcode(f):      return bool(_PCODE.search(f["host"]))
# Brand in subdomain but NOT in registered domain (paypal.evil.com)
def r_bsub(f):       return bool(_BRANDS.search(f["sub"])) and not bool(_BRANDS.search(f["dom"]))
# @ trick: http://trusted.com@evil.com — browser ignores pre-@ part
def r_at(f):         return bool(_AT.match(f["url"]))

# ── Infrastructure ────────────────────────────────────
# Phishing pages on free hosts to leverage platform SSL/reputation
def r_free(f):       return bool(_FREE.search(f["host"]))
# Shortener hides real destination from scanners
def r_short(f):      return bool(_SHORT.match(f["host"]))
# Dynamic DNS enables rapid IP rotation and takedown evasion
def r_ddns(f):       return bool(_DDNS.search(f["host"]))
# Raw IP hostname (no port) — no legit service uses bare IP links
def r_ip(f):         return bool(_IPHOST.match(f["host"])) and f["port"] is None
# Raw IP + explicit port — rogue server on non-standard port
def r_ipp(f):        return bool(_IPHOST.match(f["host"])) and f["port"] is not None
# Non-standard port on named host — never used by real login pages
def r_port(f):       return (f["port"] not in (None,80,443) and not bool(_IPHOST.match(f["host"])))
# Loopback in public URL — phishing kit artefact / SSRF vector
def r_local(f):      return f["host"] in ("localhost","127.0.0.1","0.0.0.0","::1")
# IPFS hosting makes takedown near-impossible
def r_ipfs(f):       return bool(_IPFS.search(f["url"]))
# Injected phishing page inside compromised CMS installation
def r_cms(f):        return bool(_CMS.search(f["url"]))
# Long hex subdomain = per-victim tracking token generated by phishing kit
def r_hexsub(f):     return bool(_HEXSUB.match(f["sub"]))
# Pure long-numeric subdomain = machine-generated identifier
def r_numsub(f):     return bool(_NUMLONG.match(f["sub"]))

# ── Obfuscation ───────────────────────────────────────
# ≥3 encoded chars = hiding keywords/brand names from scanners
def r_enc(f):        return f["enc"] >= 3
# Embedded http:// inside path — confuses parsers and users
def r_pathc(f):      return bool(_PATHURL.search(unquote(f["path"]))) or bool(re.search(r"https?%3A", f["path"], re.I))
# Redirect to EXTERNAL domain only (same-domain return URLs excluded)
def r_redir(f):      return bool(_REDIR.search(f["query"] + "&" + f["url"])) and _external_redirect(f["url"], f["host"])
# Tracking subdomain PLUS at least one suspicious signal (avoids analytics FP)
def r_track(f):
    return (not bool(_LEGITTR.search(f["host"])) and bool(_TRKSUB.match(f["sub"] + "."))
            and (bool(_STLDS.search("." + f["suf"])) or f["skw"] >= 1 or bool(_FREE.search(f["host"]))))
# data:/javascript: pseudo-protocols execute code on click
def r_data(f):       return bool(_DATAURI.match(f["url"]))
# Direct malware delivery via dangerous file extension in path
def r_malext(f):     return bool(_MALEXT.search(f["path"]))

# ── Social engineering ────────────────────────────────
# Login/credential keywords in path+query OR ≥2 urgency words in URL
def r_cred(f):       return bool(_CRED.search(f["pq"])) or f["skw"] >= 2
# Brand buried ≥3 levels deep in path (http://evil.com/secure/accounts/paypal)
def r_dpbrand(f):    return bool(_BRANDS.search(f["path"])) and f["depth"] >= 3
# Webmail interface clone — exclude real brand domains to avoid FP
def r_wmail(f):      return bool(_WMAIL.search(f["host"])) and not bool(_BRANDS.search(f["dom"]))
# Adult content used as bait for credential harvest or malware delivery
def r_adult(f):      return bool(_ADULT.search(f["url"]))
# ≥4 subdomain levels pushes real domain far right where users don't look
def r_stacksub(f):   return f["host"].count(".") >= 4 or f["sub"].count(".") >= 2

# ── Heuristic ─────────────────────────────────────────
# DGA/random domain: must meet ALL THREE criteria to reduce false positives
def r_rand(f):       return f["ent"] > 3.5 and bool(_STLDS.search("." + f["suf"])) and f["dlen"] > 8

# ══════════════════════════════════════════════════════
# 5. RULE REGISTRY + CATEGORY TAXONOMY
# ══════════════════════════════════════════════════════

RULES = {
    # identity
    "Typosquatting-Regex"      : (r_typo_rx, "identity"),
    "Typosquatting-Fuzzy"      : (r_typo_fz, "identity"),
    "Lookalike-Domain"         : (r_look,    "identity"),
    "Homoglyph"                : (r_homo,    "identity"),
    "Punycode"                 : (r_pcode,   "identity"),
    "Brand-Subdomain"          : (r_bsub,    "identity"),
    "At-Sign-Deception"        : (r_at,      "identity"),
    # infrastructure
    "Free-Hosting-Abuse"       : (r_free,    "infra"),
    "URL-Shortener-Abuse"      : (r_short,   "infra"),
    "Dynamic-DNS"              : (r_ddns,    "infra"),
    "IP-Based"                 : (r_ip,      "infra"),
    "IP-Based-Port"            : (r_ipp,     "infra"),
    "Non-Standard-Port"        : (r_port,    "infra"),
    "Localhost-Based"          : (r_local,   "infra"),
    "IPFS-Abuse"               : (r_ipfs,    "infra"),
    "CMS-Exploit"              : (r_cms,     "infra"),
    "Hex-Encoded-Subdomain"    : (r_hexsub,  "infra"),
    "Long-Numeric-Subdomain"   : (r_numsub,  "infra"),
    # obfuscation
    "URL-Encoding"             : (r_enc,     "obfusc"),
    "Path-Confusion"           : (r_pathc,   "obfusc"),
    "Open-Redirect"            : (r_redir,   "obfusc"),
    "Tracking-Redirect"        : (r_track,   "obfusc"),
    "Data-URI-Javascript"      : (r_data,    "obfusc"),
    "Malicious-File-Extension" : (r_malext,  "obfusc"),
    # social
    "Credential-Harvesting"    : (r_cred,    "social"),
    "Deep-Path-Brand"          : (r_dpbrand, "social"),
    "Webmail-Phishing"         : (r_wmail,   "social"),
    "Adult-Content"            : (r_adult,   "social"),
    "Subdomain-Stacking"       : (r_stacksub,"social"),
    # heuristic
    "Random-Suspicious-Domain" : (r_rand,    "heuris"),
}

def _mixed(tags):
    """Mixed-Attack only when tags span ≥2 distinct attack categories."""
    return len({RULES[t][1] for t in tags if t in RULES}) >= 2

# ══════════════════════════════════════════════════════
# 6. SECONDARY CLASSIFIER  (≤2 tags, weaker thresholds)
# ══════════════════════════════════════════════════════

def _secondary(f):
    out = []
    # Relaxed entropy (no TLD required) for DGA on .com
    if f["ent"] > 3.8 and f["dlen"] > 8:                                    out.append("Random-Suspicious-Domain")
    # Single cred keyword (primary requires path+query hit or ≥2 words)
    if not out and (bool(_CRED.search(f["pq"])) or f["skw"] == 1):          out.append("Credential-Harvesting")
    # Suspicious TLD alone (weaker than full random combo)
    if len(out) < 2 and bool(_STLDS.search("." + f["suf"])) and "Random-Suspicious-Domain" not in out:
                                                                              out.append("Random-Suspicious-Domain")
    # Brand anywhere in URL but not in registered domain → weak subdomain signal
    if len(out) < 2 and bool(_BRANDS.search(f["url"])) and not bool(_BRANDS.search(f["dom"])):
                                                                              out.append("Brand-Subdomain")
    # High digit ratio suggests generated/numeric domain
    if len(out) < 2 and f["drat"] > 0.5 and f["dlen"] > 6 and "Random-Suspicious-Domain" not in out:
                                                                              out.append("Random-Suspicious-Domain")
    return out[:2]

# ══════════════════════════════════════════════════════
# 7. MAIN LOOP
# ══════════════════════════════════════════════════════

df       = pd.read_csv(r"Data\train.csv")
phishing = df[df["Label"] == 1]["URL"].dropna().tolist()

counts, classified, unclassified = defaultdict(int), 0, []

for raw in tqdm(phishing, desc="Classifying", unit="url"):
    f = _parse(raw)
    if f is None:
        counts["Unclassified"] += 1; unclassified.append(raw); continue

    tags = [name for name, (fn, _) in RULES.items() if fn(f)]
    if not tags: tags = _secondary(f)
    if _mixed(tags): tags.append("Mixed-Attack")
    if not tags: tags = ["Unclassified"]; unclassified.append(f["url"])
    else: classified += 1

    for t in tags: counts[t] += 1

# ══════════════════════════════════════════════════════
# 8. OUTPUT
# ══════════════════════════════════════════════════════

if unclassified:
    def _info(raw):
        f = _parse(raw)
        if f: return {"url":f["url"],"domain":f["host"],"tld":f["suf"],"length":f["ulen"],
                      "entropy":round(f["ent"],3),"digit_ratio":round(f["drat"],3),
                      "path_depth":f["depth"],"enc_count":f["enc"],"susp_keywords":f["skw"],
                      "has_ip":bool(_IPHOST.match(f["host"])),"subdomain_dots":f["host"].count(".")}
        return {"url":raw,"domain":None,"tld":None,"length":len(raw),"entropy":0,"digit_ratio":0,
                "path_depth":0,"enc_count":0,"susp_keywords":0,"has_ip":False,"subdomain_dots":0}
    pd.DataFrame([_info(u) for u in tqdm(unclassified, desc="Saving unclassified", unit="url")]).to_csv("unclassified_urls.csv", index=False)

summary = pd.DataFrame(sorted(counts.items(), key=lambda x:-x[1]), columns=["Type","Count"])
print("\n" + summary.to_string(index=False))
print(f"\nClassified URLs  : {classified}")
print(f"Unclassified URLs: {counts.get('Unclassified',0)}")
print(f"Total            : {len(phishing)}")
