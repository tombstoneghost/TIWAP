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
        res = self.connection.find(filtered)

        data = []

        for r in res:
            data.append(r)

        return data
