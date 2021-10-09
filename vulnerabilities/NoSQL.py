# Imports
from helper.mongodb_manager import MongoDBManager

# Global Objects
mongo_dbm = MongoDBManager()


# Low Vulnerability
def no_sql_injection_low(query):
    data = mongo_dbm.get_data_filtered(filtered=query)

    return data
