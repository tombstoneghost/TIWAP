# Imports
from helper.db_manager import DBManager

# DB Manager
dbm = DBManager()


# Stored - Low
def stored_xss_low(comment):
    if dbm.save_comment(comment=comment):
        msg = "Comment Saved"
    else:
        msg = "Unable to Save Comment"

    data = dbm.get_comments()

    return msg, data


# Stored - Medium
def stored_xss_medium(comment):
    if "<script>" in comment.lower():
        return "Try Harder", {}
    else:
        return stored_xss_low(comment)
