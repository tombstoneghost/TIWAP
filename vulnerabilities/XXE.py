# Imports
import base64
from lxml import etree
from urllib.parse import unquote


# Low Vulnerability
def xxe_low(data):
    name = "Invalid"
    tree = etree.fromstring(data)

    for child in tree:
        if child.tag == "name":
            name = "Hey! " + child.text

    result = "<result><msg>%s</msg><result>" % name

    return result


# Medium Vulnerability
def xxe_medium(data):
    decode_data = base64.b64decode(data)
    data = unquote(decode_data)

    tree = etree.fromstring(data)

    for child in tree:
        if child.tag == "name":
            name = "Hey! " + child.text

    result = "<result><msg>%s</msg><result>" % name

    return result
