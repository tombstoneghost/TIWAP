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


# Medium Vulnerability
def cmd_injection_medium(query):
    filters = [';', '&&', '||']
    for x in filters:
        if x in query:
            message = "Input query blocked: " + query
            return message

    return cmd_injection_low(query)


# Hard Vulnerability
def cmd_injection_hard(query):
    filters = ['& ', ';', '|', '-', '$', '(', ')', '`', '||']
    for x in filters:
        if x in query:
            message = "Input query blocked: " + query
            return message

    return cmd_injection_low(query)
