import pandas as pd
import re
import json
import math
from urllib.parse import urlparse
from collections import Counter

try:
    import tldextract
    USE_TLDEXTRACT = True
except ImportError:
    USE_TLDEXTRACT = False

# ---------------------------------------------------------------------------
# Precompiled regex patterns
# ---------------------------------------------------------------------------
RE_IPV4              = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$')
RE_IPV6              = re.compile(r'^\[?[0-9a-fA-F:]+\]?(:\d+)?$')
RE_HTTP_IN_PATH      = re.compile(r'https?://', re.I)
RE_DIGITS            = re.compile(r'\d')
RE_SPECIAL           = re.compile(r'[^a-zA-Z0-9:/._-]')
RE_REPEATED_ALNUM    = re.compile(r'([a-zA-Z0-9])\1{3,}')
RE_ALNUM_ONLY        = re.compile(r'[^a-zA-Z0-9]')

RE_KEYWORDS = {kw: re.compile(rf'\b{re.escape(kw)}\b', re.I) for kw in {
    'login','signin','sign-in','logon','log-in','logout','register','registration',
    'signup','sign-up','verify','verification','validate','validation','authenticate',
    'authentication','authorize','otp','mfa','2fa','token','captcha','credential',
    'username','password','passwd','passcode','reset','recovery','recover','unlock',
    'account','myaccount','accounts','profile','dashboard','portal','member',
    'membership','customer','user','client','payment','pay','invoice','billing',
    'bill','checkout','order','purchase','transaction','refund','reimbursement',
    'cashback','wallet','bank','banking','netbanking','credit','debit','card',
    'cardnumber','cvv','expiry','iban','swift','wire','transfer','remittance','loan',
    'urgent','immediately','action-required','action','required','important',
    'critical','warning','alert','notice','notification','reminder','deadline',
    'expire','expiry','expiring','expired','secure','security','safe','safety',
    'protect','protection','privacy','suspend','suspended','suspension','restrict',
    'restricted','blocked','locked','compromised','breach','hacked','unauthorized',
    'unusual','suspicious','fraud','fraudulent','risk','update','upgrade','confirm',
    'confirmation','reconfirm','submit','complete','finish','continue','proceed',
    'activate','activation','claim','redeem','reward','prize','winner',
    'webscr','ebayisapi','dispatch','cmd',
}}

# ---------------------------------------------------------------------------
# Lookup sets
# ---------------------------------------------------------------------------
SUSPICIOUS_TLDS = {
    'tk','ml','ga','cf','gq','xyz','top','club','online','site','pw','cc','ws',
    'info','biz','name','pro','icu','buzz','cyou','cfd','sbs','rest','hair',
    'beauty','skin','lol','vip','win','loan','cricket','party','trade','racing',
    'stream','download','gdn','life','live','click','link','support','help',
    'services','solutions','center','systems','network','digital',
    'ru','cn','br','bd','ug','ke','ng',
}

BRAND_NAMES = {
    'google','gmail','youtube','googleplay','apple','icloud','itunes','appstore',
    'microsoft','outlook','onedrive','office365','skype','teams','meta','facebook',
    'instagram','whatsapp','messenger','oculus','twitter','tiktok','snapchat',
    'pinterest','linkedin','amazon','aws','alexa','primevideo','netflix','spotify',
    'discord','zoom','slack','dropbox','adobe','oracle','salesforce','shopify',
    'ebay','flipkart','myntra','meesho','alibaba','aliexpress','taobao','walmart',
    'target','bestbuy','etsy','lazada','tokopedia','mercadolibre','paypal','stripe',
    'square','chase','wellsfargo','bankofamerica','citibank','citi','hsbc','barclays',
    'lloyds','natwest','santander','deutschebank','bnpparibas','ing','rabobank',
    'usbank','capitalone','tdbank','scotiabank','rbc','sbi','sbionline','statebank',
    'hdfcbank','hdfc','icicibank','icici','axisbank','axis','kotakbank','kotak',
    'pnb','bob','canarabank','unionbank','yesbank','indusindbank','federalbank',
    'paytm','phonepe','gpay','googlepay','amazonpay','mobikwik','freecharge',
    'razorpay','cashfree','payu','venmo','cashapp','zelle','wise','revolut',
    'klarna','afterpay','affirm','airtel','jio','vodafone','bsnl','idea','att',
    'verizon','tmobile','sprint','comcast','xfinity','bt','o2','orange','binance',
    'coinbase','kraken','bitfinex','kucoin','okx','bybit','crypto','fedex','ups',
    'dhl','usps','royalmail','indiapost','bluedart','delhivery',
}

LONG_URL_THRESHOLD = 75

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _levenshtein(a: str, b: str) -> int:
    if a == b: return 0
    if not a:  return len(b)
    if not b:  return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            curr[j] = min(prev[j] + 1, curr[j-1] + 1,
                          prev[j-1] + (0 if ca == cb else 1))
        prev = curr
    return prev[-1]


def _brand_match(domain_token: str) -> bool:
    if domain_token in BRAND_NAMES:
        return True
    if len(domain_token) < 5:
        return False
    for brand in BRAND_NAMES:
        if abs(len(domain_token) - len(brand)) <= 1:
            if _levenshtein(domain_token, brand) == 1:
                return True
    return False


def _has_ip(netloc: str) -> int:
    host_part = netloc.split('@')[-1]
    host = host_part.split(':')[0].strip('[]')
    if RE_IPV4.match(host_part) or RE_IPV4.match(host):
        return 1
    if ':' in host_part and RE_IPV6.match(host_part):
        return 1
    return 0

# ---------------------------------------------------------------------------
# Main feature extractor
# ---------------------------------------------------------------------------
def extract_features(url: str) -> dict:
    try:
        url      = url.strip()
        norm     = url if url.startswith(('http://', 'https://')) else 'http://' + url
        parsed   = urlparse(norm)
        netloc   = parsed.netloc.lower()
        path     = parsed.path
        query    = parsed.query
        url_len  = len(url)

        # TLD + subdomain
        if USE_TLDEXTRACT:
            ext               = tldextract.extract(norm)
            tld               = ext.suffix.split('.')[-1] if ext.suffix else ''
            subs              = [s for s in ext.subdomain.split('.') if s and s != 'www']
            registered_domain = ext.domain.lower()
        else:
            parts             = netloc.split('.')
            tld               = parts[-1] if parts else ''
            subs              = [s for s in parts[:-2] if s and s != 'www']
            registered_domain = parts[-2].lower() if len(parts) >= 2 else netloc

        # redirect_count: "http"/"https" in path+query only (not protocol)
        redirect_count = len(RE_HTTP_IN_PATH.findall(path + query))

        # brand_similarity
        brand_sim = int(_brand_match(registered_domain))

        # keyword_score: match on netloc+path only, word-boundary, capped at 5
        netloc_path   = netloc + path
        keyword_score = min(5, sum(1 for pat in RE_KEYWORDS.values() if pat.search(netloc_path)))

        # entropy: computed on alphanumeric-only domain string
        clean_netloc  = RE_ALNUM_ONLY.sub('', netloc)
        entropy_val   = round(shannon_entropy(clean_netloc if clean_netloc else netloc), 6)

        # digit/special counts on full URL
        num_digits  = len(RE_DIGITS.findall(url))
        num_special = len(RE_SPECIAL.findall(url))

        # domain digit ratio
        netloc_len         = len(netloc)
        domain_digit_count = len(RE_DIGITS.findall(netloc))
        domain_digit_ratio = round(domain_digit_count / netloc_len, 6) if netloc_len else 0

        return {
            "url_length"         : url_len,
            "redirect_count"     : redirect_count,
            "has_punycode"       : int('xn--' in netloc),
            "suspicious_tld"     : int(tld in SUSPICIOUS_TLDS),
            "subdomain_depth"    : len(subs),
            "keyword_score"      : keyword_score,
            "entropy"            : entropy_val,
            "brand_similarity"   : brand_sim,
            "has_ip"             : _has_ip(netloc),
            "has_https"          : int(parsed.scheme == 'https'),
            "num_digits"         : num_digits,
            "num_special_chars"  : num_special,
            "url_digit_ratio"    : round(num_digits  / url_len, 6) if url_len else 0,
            "url_special_ratio"  : round(num_special / url_len, 6) if url_len else 0,
            "domain_length"      : netloc_len,
            "domain_digit_ratio" : domain_digit_ratio,
            "path_length"        : len(path),
            "path_depth"         : path.count('/'),
            "has_query"          : int(bool(query)),
            "dash_count"         : netloc.count('-'),
            "dot_count"          : netloc.count('.'),
            "is_long_url"        : int(url_len > LONG_URL_THRESHOLD),
            "has_repeated_chars" : int(bool(RE_REPEATED_ALNUM.search(url))),
        }
    except Exception:
        return {k: 0 for k in [
            "url_length","redirect_count","has_punycode","suspicious_tld",
            "subdomain_depth","keyword_score","entropy","brand_similarity","has_ip",
            "has_https","num_digits","num_special_chars","url_digit_ratio",
            "url_special_ratio","domain_length","domain_digit_ratio","path_length",
            "path_depth","has_query","dash_count","dot_count","is_long_url",
            "has_repeated_chars",
        ]}

# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------
df = pd.read_csv(r"Data\train.csv")

features_list = [extract_features(url) for url in df["URL"]]
features_df   = pd.DataFrame(features_list)

output_df = pd.concat([
    df["URL"].reset_index(drop=True),
    features_df,
    df["Label"].reset_index(drop=True),
], axis=1)
output_df.columns = ["url"] + list(features_df.columns) + ["label"]
output_df.to_csv("processed_dataset.csv", index=False)

records = [
    {
        "url"     : row["url"],
        "features": {col: row[col] for col in features_df.columns},
        "label"   : int(row["label"]),
    }
    for _, row in output_df.iterrows()
]
with open("processed_dataset.json", "w") as f:
    json.dump(records, f, indent=2)
