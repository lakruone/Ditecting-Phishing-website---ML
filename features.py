import regex
from tldextract import extract

# -1 legitimate
# 1 phishing
# 0 suspicious


def main(url):
    print("url : " + url)
    check = [[url_length(url), having_at_symbol(
        url), prefix_suffix(url), sub_domain(url)]]
    return check


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


# feature 6 --Adding Prefix or Suffix Separated by (-) to the Domain
def prefix_suffix(url):
    try:
        prefix_suffix = extract(url)
        if(prefix_suffix.count('-')):
            return 1
        else:
            return -1
    except:
        return 'Error'


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



