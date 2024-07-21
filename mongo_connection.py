from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import UpdateOne
from pymongo.errors import PyMongoError
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

class MongoCon:
    def __init__(self):
        """
        Initialize the MongoDB connection and collections.
        """
        try:
            mongo_uri = os.getenv("MONGO_URI")
            db_name = os.getenv("DB_NAME")
            collection_name = os.getenv("COLLECTION_NAME")
            sync_collection_name = os.getenv("SYNC_COLLECTION_NAME")
            self.client = AsyncIOMotorClient(mongo_uri)
            self.cve_collection = self.get_mongo_collection(db_name, collection_name)
            self.sync_collection = self.get_mongo_collection(db_name, sync_collection_name)
        except PyMongoError as e:
            print(f"Error connecting to MongoDB: {e}")
            self.client = None
            self.cve_collection = None
            self.sync_collection = None

    def get_mongo_collection(self, db_name, collection_name):
        """
        Get the MongoDB collection, create indexes if necessary.

        Args:
            db_name (str): The name of the database.
            collection_name (str): The name of the collection.

        Returns:
            collection: The MongoDB collection object, or None if an error occurred.
        """
        if not self.client:
            return None
        db = self.client[db_name]
        collection = db[collection_name]
        if collection_name == os.getenv("COLLECTION_NAME"):
            collection.create_index("cve.id", unique=True)
            collection.create_index("cve.lastModified")
            collection.create_index("cve.metrics.cvssMetricV2.cvssData.baseScore")
            collection.create_index("cve.metrics.cvssMetricV3.cvssData.baseScore")
        return collection
    
    async def store_cve_data(self, cve_data):
        """
        Store CVE data in MongoDB with upsert logic.

        Args:
            cve_data (dict): The CVE data to store.

        Returns:
            None
        """
        if self.cve_collection is None:
            print("No MongoDB collection available.")
            return
        operations = [
            UpdateOne(
                {'cve.id': item['cve']['id']},
                {'$set': item},
                upsert=True
            )
            for item in cve_data.get('vulnerabilities', [])
        ]
        if operations:
            try:
                await self.cve_collection.bulk_write(operations)
            except PyMongoError as e:
                print(f"Error during bulk write operation: {e}")

    async def get_last_sync_time(self):
        """
        Get the last sync time from the sync collection.

        Returns:
            str: The last sync time in ISO format, or None if not found.
        """
        if self.sync_collection is None:
            print("No MongoDB sync collection available.")
            return None
        try:
            last_sync = await self.sync_collection.find_one({"_id": "cve_nvd_data_sync_col"})
            if last_sync:
                return last_sync['last_sync_time']
        except PyMongoError as e:
            print(f"Error fetching last sync time: {e}")
        return None

    async def update_last_sync_time(self, last_sync_time):
        """
        Update the last sync time in the sync collection.

        Args:
            last_sync_time (str): The last sync time to set.

        Returns:
            None
        """
        if self.sync_collection is None:
            print("No MongoDB sync collection available.")
            return
        try:
            await self.sync_collection.update_one(
                {"_id": "cve_nvd_data_sync_col"},
                {"$set": {"last_sync_time": last_sync_time}},
                upsert=True
            )
        except PyMongoError as e:
            print(f"Error updating last sync time: {e}")

    async def add_or_update_cve_in_mongo(self, data):
        """
        Add or update CVE data in MongoDB based on the last modified timestamp.

        Args:
            data (dict): The CVE data to add or update.

        Returns:
            None
        """
        if self.cve_collection is None:
            print("No MongoDB collection available.")
            return
        operations = []
        for cve in data.get('vulnerabilities', []):
            cve_id = cve['cve']['id']
            last_modified = cve['cve']['lastModified']

            try:
                existing_cve = await self.cve_collection.find_one({'cve.id': cve_id})

                if existing_cve:
                    existing_last_modified = existing_cve['cve']['lastModified']
                    if existing_last_modified != last_modified:
                        # Update the document if the lastModified timestamp has changed
                        operations.append(UpdateOne(
                            {'cve.id': cve_id},
                            {'$set': cve},
                            upsert=True
                        ))
                else:
                    # Insert the document if it doesn't exist
                    operations.append(UpdateOne(
                        {'cve.id': cve_id},
                        {'$set': cve},
                        upsert=True
                    ))
            except PyMongoError as e:
                print(f"Error adding/updating CVE in MongoDB: {e}")
        if operations:
            try:
                await self.cve_collection.bulk_write(operations)
            except PyMongoError as e:
                print(f"Error during bulk write operation: {e}")
