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

SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq',
    'xyz', 'top', 'club', 'online', 'site', 'pw', 'cc', 'ws',
    'info', 'biz', 'name', 'pro',
    'icu', 'buzz', 'cyou', 'cfd', 'sbs', 'rest',
    'hair', 'beauty', 'skin', 'lol', 'vip', 'win',
    'loan', 'cricket', 'party', 'trade', 'racing',
    'stream', 'download', 'gdn', 'life', 'live',
    'click', 'link', 'support', 'help', 'services',
    'solutions', 'center', 'systems', 'network', 'digital',
    'ru', 'cn', 'br', 'in', 'bd', 'ug', 'ke', 'ng',
}

PHISHING_KEYWORDS = {
    'login', 'signin', 'sign-in', 'logon', 'log-in',
    'logout', 'register', 'registration', 'signup', 'sign-up',
    'verify', 'verification', 'validate', 'validation',
    'authenticate', 'authentication', 'authorize', 'otp',
    'mfa', '2fa', 'token', 'captcha', 'credential',
    'username', 'password', 'passwd', 'passcode',
    'reset', 'recovery', 'recover', 'unlock',
    'account', 'myaccount', 'accounts', 'profile',
    'dashboard', 'portal', 'member', 'membership',
    'customer', 'user', 'client',
    'payment', 'pay', 'invoice', 'billing', 'bill',
    'checkout', 'order', 'purchase', 'transaction',
    'refund', 'reimbursement', 'cashback', 'wallet',
    'bank', 'banking', 'netbanking', 'credit', 'debit',
    'card', 'cardnumber', 'cvv', 'expiry', 'iban',
    'swift', 'wire', 'transfer', 'remittance', 'loan',
    'urgent', 'immediately', 'action-required', 'action',
    'required', 'important', 'critical', 'warning',
    'alert', 'notice', 'notification', 'reminder',
    'deadline', 'expire', 'expiry', 'expiring', 'expired',
    'secure', 'security', 'safe', 'safety',
    'protect', 'protection', 'privacy',
    'suspend', 'suspended', 'suspension', 'restrict',
    'restricted', 'blocked', 'locked', 'compromised',
    'breach', 'hacked', 'unauthorized', 'unusual',
    'suspicious', 'fraud', 'fraudulent', 'risk',
    'update', 'upgrade', 'confirm', 'confirmation',
    'reconfirm', 'submit', 'complete', 'finish',
    'continue', 'proceed', 'activate', 'activation',
    'claim', 'redeem', 'reward', 'prize', 'winner',
    'webscr', 'ebayisapi', 'dispatch', 'cmd',
}

BRAND_NAMES = {
    'google', 'gmail', 'youtube', 'googleplay',
    'apple', 'icloud', 'itunes', 'appstore',
    'microsoft', 'outlook', 'onedrive', 'office365', 'skype', 'teams',
    'meta', 'facebook', 'instagram', 'whatsapp', 'messenger', 'oculus',
    'twitter', 'x', 'tiktok', 'snapchat', 'pinterest', 'linkedin',
    'amazon', 'aws', 'alexa', 'primevideo',
    'netflix', 'spotify', 'discord', 'zoom', 'slack', 'dropbox',
    'adobe', 'oracle', 'salesforce', 'shopify',
    'ebay', 'flipkart', 'myntra', 'meesho',
    'alibaba', 'aliexpress', 'taobao', 'jd',
    'walmart', 'target', 'bestbuy', 'etsy',
    'lazada', 'tokopedia', 'mercadolibre',
    'paypal', 'stripe', 'square',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'citi',
    'hsbc', 'barclays', 'lloyds', 'natwest', 'santander',
    'deutschebank', 'bnpparibas', 'ing', 'rabobank',
    'usbank', 'capitalone', 'tdbank', 'scotiabank', 'rbc',
    'sbi', 'sbionline', 'statebank',
    'hdfcbank', 'hdfc', 'icicibank', 'icici',
    'axisbank', 'axis', 'kotakbank', 'kotak',
    'pnb', 'bob', 'canarabank', 'unionbank',
    'yesbank', 'indusindbank', 'federalbank',
    'paytm', 'phonepe', 'gpay', 'googlepay',
    'amazonpay', 'mobikwik', 'freecharge',
    'razorpay', 'cashfree', 'payu',
    'venmo', 'cashapp', 'zelle', 'wise', 'revolut',
    'klarna', 'afterpay', 'affirm',
    'airtel', 'jio', 'vodafone', 'bsnl', 'idea',
    'att', 'verizon', 'tmobile', 'sprint',
    'comcast', 'xfinity', 'bt', 'o2', 'orange',
    'binance', 'coinbase', 'kraken', 'bitfinex',
    'kucoin', 'okx', 'bybit', 'crypto',
    'fedex', 'ups', 'dhl', 'usps', 'royalmail',
    'indiapost', 'bluedart', 'delhivery',
}

def shannon_entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())

def extract_features(url):
    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        netloc = parsed.netloc.lower()
        full = url.lower()

        if USE_TLDEXTRACT:
            ext = tldextract.extract(url)
            tld = ext.suffix.split('.')[-1] if ext.suffix else ''
            subdomains = [s for s in ext.subdomain.split('.') if s] if ext.subdomain else []
            subdomain_depth = len(subdomains)
        else:
            parts = netloc.split('.')
            tld = parts[-1] if parts else ''
            subdomain_depth = max(0, len(parts) - 2)

        return {
            "url_length": len(url),
            "redirect_count": max(0, len(re.findall(r'https?://', url)) - 1),
            "has_punycode": int('xn--' in netloc),
            "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
            "subdomain_depth": subdomain_depth,
            "keyword_score": sum(1 for kw in PHISHING_KEYWORDS if kw in full),
            "entropy": round(shannon_entropy(url), 6),
            "brand_similarity": int(any(b in full for b in BRAND_NAMES)),
            "has_ip": int(bool(re.match(r'\d{1,3}(\.\d{1,3}){3}', netloc)))
        }
    except Exception:
        return {k: 0 for k in ["url_length","redirect_count","has_punycode","suspicious_tld","subdomain_depth","keyword_score","entropy","brand_similarity","has_ip"]}

df = pd.read_csv(r"Data\phishing_dataset_20k_final.csv")

features_list = [extract_features(url) for url in df["URL"]]
features_df = pd.DataFrame(features_list)

output_df = pd.concat([
    df["URL"].reset_index(drop=True),
    features_df,
    df["Label"].reset_index(drop=True)
], axis=1)

output_df.columns = ["url"] + list(features_df.columns) + ["label"]
output_df.to_csv("test_extra_dataset.csv", index=False)

records = output_df.apply(
    lambda row: {
        "url": row["url"],
        "features": {col: row[col] for col in features_df.columns},
        "label": int(row["label"])
    }, axis=1
).tolist()

with open("test_extra_dataset.json", "w") as f:
    json.dump(records, f, indent=2)