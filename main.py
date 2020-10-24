import features

print("Hello")
url = input("Please Enter the URL and press enter to proceed : ")

# url = "http://ebay.co.uk"

response = features.main(url)
print(response)
