import regex
from tldextract import extract
import ipaddress
from bs4 import BeautifulSoup
import urllib.request
import whois
import datetime

# -1 legitimate
# 1 phishing
# 0 suspicious


def main(url):
    print("url : " + url)

    check = [[having_IP_Address(url), url_length(url), shortening_service(url), having_at_symbol(
        url), prefix_suffix(url), sub_domain(url), https_token(url)]]

    return check


# feature 1 -- Using the IP Address
def having_IP_Address(url):
    try:
        ipaddress.ip_address(url)
        return 1
    except:
        return -1


# feature 2 -- Long URL to Hide the Suspicious Part
def url_length(url):
    length = len(url)
    if(length < 54):
        return -1
    elif(54 <= length <= 75):
        return 0
    else:
        return 1


# feature 3 -- Tiny URLs, URL shortning services
def shortening_service(url):
    try:
        match = regex.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                             'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                             'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                             'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                             'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                             'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                             'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', url)
        if match:
            return 1
        else:
            return -1
    except:
        return 'error'


# feature 4 -- URL’s having “@” Symbol
def having_at_symbol(url):
    symbol = regex.findall(r'@', url)
    if(len(symbol) == 0):
        return -1  # No @ symbol
    else:
        return 1


# feature 6 -- Adding Prefix or Suffix Separated by (-) to the Domain
def prefix_suffix(url):
    subDomain, domain, suffix = extract(url)
    # print("subDomain : "+subDomain)
    # print("Domain : "+domain)
    # print("Suffix : "+suffix)

    if(domain.count('-')):
        return 1
    else:
        return -1


# feature 7 -- Sub Domain and Multi Sub Domains
def sub_domain(url):
    try:
        subDomain = extract(url)
        if(subDomain.count('.') == 0):
            return -1
        elif(subDomain.count('.') == 1):
            return 0
        else:
            return 1
    except:
        return 'error'


# feature 12 -- The Existence of “HTTPS” Token in the Domain Part of the URL
def https_token(url):
    match = regex.search('https://|http://', url)
    try:
        if match.start(0) == 0 and match.start(0) is not None:
            url = url[match.end(0):]
            match = regex.search('http|https', url)
            if match:
                return 1
            else:
                return -1
    except:
        return 'error'
