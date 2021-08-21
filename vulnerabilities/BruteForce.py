# Imports

# Low Vulnerability
def brute_force_low(username, password):
    if username == "administrator" and password != "whitetiger93@jen":
        result = "Try again!!!"
    elif username == "administrator" and password == "whitetiger93@jen":
        result = "Logged in Successful :-)"
    else:
        result = "Invalid Credentials :-("

    return result
