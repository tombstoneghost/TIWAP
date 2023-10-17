# Imports
from pymongo import MongoClient
from hashlib import md5

import json

# Global Variables
client = MongoClient("mongodb://username:password@db:27017/?authMechanism=DEFAULT", connectTimeoutMS=60000, connect=False)


class MongoDBManager:
    def __init__(self):
        self.connection = client.get_database("TIWAP").get_collection("users")

    def check_login_low(self, username):

        try:
            username = json.loads(username)
        except Exception:
            username = username

        query = {"username": username}

        print("Query", query)

        res = self.connection.find(query)

        data = []

        for d in res:
            data.append(d)

        return data
    
    def check_login_medium(self, username, password):

        try:
            username = json.loads(username)
        except Exception:
            username = username

        try:
            password = json.loads(password)
        except Exception:
            password_hash = md5(bytes(password, encoding='utf-8')).hexdigest()
            password = password_hash


        query = {"username": username, "password": password}

        print("Query", query)

        res = self.connection.find(query)

        data = []

        for d in res:
            data.append(d)

        return data

    def reset_db(self):
        db = client.get_database("TIWAP")
        collection = db.get_collection("users")

        collection.delete_many({})

        dict_1 = {'username': 'admin', 'password': '21232f297a57a5a743894a0e4a801fc3'}
        dict_2 = {'username': 'john', 'password': '6e0b7076126a29d5dfcbd54835387b7b'}

        collection.insert_many([dict_1, dict_2])
