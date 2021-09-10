# Imports


# Get Level by Code:
def get_level_by_code(code):
    if code == 0:
        return "Low"
    if code == 1:
        return "Medium"
    if code == 2:
        return "Hard"


# Get Level by Name
def get_level_by_name(name):
    if name == 'low':
        return 0
    if name == 'medium':
        return 1
    if name == 'hard':
        return 2
