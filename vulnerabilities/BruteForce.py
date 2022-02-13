# Imports

# Low Vulnerability
def brute_force_low(username, password):
    if username == "administrator" and password != "12345qwert":
        result = "Try again!!!"
    elif username == "administrator" and password == "12345qwert":
        result = "Logged in Successful :-)"
    else:
        result = "Invalid Credentials :-("

    return result
