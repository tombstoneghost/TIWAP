# Imports
import os
import sys


# Low Vulnerability
def cmd_injection_low(query):
    if "win" in sys.platform:
        query = 'ping ' + query
    elif "linux" in sys.platform:
        query = 'ping -c 4 ' + query

    stream = os.popen(query)
    output = stream.read()

    return output
