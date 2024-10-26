import database


db = database.client.get_database("mcsmirror")
cores_collection = db.get_collection("cores")
downloads_collection = db.get_collection("downloads")