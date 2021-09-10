# Imports
from helper.db_manager import DBManager

# DB Manager
dbm = DBManager()


# Stored
def stored_html(name):
    if dbm.save_name(name=name):
        msg = "Name saved!"
    else:
        msg = "Unable to save name."

    data = dbm.get_names()

    return msg, data
