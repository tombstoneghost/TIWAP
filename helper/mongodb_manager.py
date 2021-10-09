# Imports
from pymongo import MongoClient

# Global Variables
client = MongoClient("mongodb://localhost:27017/")


class MongoDBManager:
    def __init__(self):
        self.connection = client.get_database("TIWAP").get_collection("cars")

    def get_data_all(self):
        data = []
        for d in self.connection.find():
            data.append(d)

        return data

    def get_data_filtered(self, filtered):
        try:
            res = self.connection.find({"name": filtered})
            data = []

            for r in res:
                del r['_id']
                data.append(r)

            return data

        except Exception as e:
            return e

    def reset_db(self):
        db = client["TIWAP"]
        col_1 = db["cars"]
        col_2 = db["users"]

        col_1.delete_many({})
        col_2.delete_many({})

        dict_1 = {"name":"720d", "company":"BMW"}
        dict_2 = {'name': 'G63','company': 'AMG'}
        dict_3 = {'name': 'A8','company': 'Audi'}
        dict_4 = {'username':'admin','password':'admin'}
        dict_5 = {'username':'john','password':'john123'}

        col_1.insert_many([dict_1,dict_2,dict_3])
        col_2.insert_many([dict_4,dict_5])