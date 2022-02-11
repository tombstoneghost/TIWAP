# Imports
from helper.mongodb_manager import MongoDBManager

# Global Objects
mongo_dbm = MongoDBManager()


# Low Vulnerability
def no_sql_injection_low(username, password):
    data = mongo_dbm.check_login(username=username, password=password)

    return data
