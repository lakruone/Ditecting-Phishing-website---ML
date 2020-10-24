import regex


def main(url):
    print("url : " +url)


    check = [[url_length(url),having_at_symbol(url)]]

    return check

# feature 2 -- Long URL to Hide the Suspicious Part
def url_length(url):
    length=len(url)
    if(length<54):
        return -1
    elif(54<=length<=75):
        return 0
    else:
        return 1

# feature 4 -- URL’s having “@” Symbol
def having_at_symbol(url):
    symbol=regex.findall(r'@',url)
    if(len(symbol)==0):
        return -1 # No @ symbol
    else:
        return 1
