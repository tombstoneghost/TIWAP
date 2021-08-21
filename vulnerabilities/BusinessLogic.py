# Imports

# Low Vulnerability
def business_logic_low(username, password):
    if username == "catherine" and password != "starwars":
        result = "Password is incorrect... Try again!!!"
    elif username != "catherine" and password == "starwars":
        result = "Username is incorrect... Try again!!!"
    elif username == "catherine" and password == "starwars":
        result = "Logged in Successful"
    else:
        result = "Invalid Credentials"

    return result
