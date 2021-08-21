# Imports
from lxml import etree


# Low Vulnerability
def xxe_low(data):
    name = "Invalid"
    tree = etree.fromstring(data)

    for child in tree:
        if child.tag == "name":
            name = "Hey! " + child.text

    result = "<result><msg>%s</msg><result>" % name

    return result
