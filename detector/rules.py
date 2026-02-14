import re

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "password",
    "signin", "bank", "confirm", "billing", "payment", "webscr"
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"
}

REGEX_PATTERNS = {
    "ip_in_domain": re.compile(r"^(?:http(s)?://)?(\d{1,3}\.){3}\d{1,3}"),
    "at_symbol": re.compile(r"@"),
    "double_slash_redirect": re.compile(r"//.*//"),
    "hex_encoding": re.compile(r"%[0-9a-fA-F]{2}"),
}

