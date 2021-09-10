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
    if (';' or '&&' or '||') in query:
        message = "Input query blocked: " + query
        return message
    else:
        return cmd_injection_low(query)


# Hard Vulnerability
def cmd_injection_hard(query):
    if ("&" or ";" or '| ' or '-' or '$' or '(' or ')' or '`' or '||') in query:
        message = "Input query blocked: " + query
        return message
    else:
        return cmd_injection_low(query)
