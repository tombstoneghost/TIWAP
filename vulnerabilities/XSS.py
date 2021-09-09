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


# Common Filter - Hard
def filter_input(data):
    filters = ["onerror", "onfocus", "onfocusin", "onfocusout", "onload", "onresize", "onscroll", "onclick",
               "onkeydown", "onkeypress", "onkeyup", "onselect"]

    for f in filters:
        if f in data:
            return True

    return False


# Stored - Hard
def stored_xss_hard(comment):
    if "<script>" in comment.lower() or filter_input(data=comment):
        return "Try Harder", {}
    else:
        return stored_xss_low(comment)
