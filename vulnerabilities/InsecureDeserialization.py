# Imports
import base64
import json
import pickle


# Vulnerability Level - Low
def serialize_low(data: dict): 
    d = json.dumps(data)

    token = base64.b64encode(d.encode('ascii')).decode()

    return token

def deserialize_low(data: str): 
    d = base64.b64decode(data).decode()

    return json.loads(d)

# Vulnerability Level - Medium
def serialize_medium(data: dict): 
    d = pickle.dumps(data)

    token = base64.b64encode(d).decode()

    return token

def deserialize_medium(data: str): 
    d = base64.b64decode(data).decode()

    return pickle.loads(d)
