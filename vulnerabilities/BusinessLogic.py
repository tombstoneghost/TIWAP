# Imports
from helper.db_manager import DBManager

# DB Manager
dbm = DBManager()


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


# Hard Vulnerability
def business_logic_hard(username, passwordn):
    if dbm.check_user(username=username):
        if dbm.update_pass(username=username, password=passwordn):
            return "Password Updated Successfully!!!"

    return "No user"
