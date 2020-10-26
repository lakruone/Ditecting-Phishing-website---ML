import regex
from tldextract import extract
import ipaddress

# -1 legitimate
# 1 phishing
# 0 suspicious


def main(url):
    print("url : " + url)

    check = [[having_IP_Address(url), url_length(url), having_at_symbol(
        url), prefix_suffix(url), sub_domain(url)]]

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
