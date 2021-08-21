# Imports
from helper.db_manager import DBManager

# DB Manager
dbm = DBManager()


# Stored - Low
def stored_xss_low(comment):
    msg = ""

    if dbm.save_comment(comment=comment):
        msg = "Comment Saved"
    else:
        msg = "Unable to Save Comment"

    data = dbm.get_comments()
    return msg, data
