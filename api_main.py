from fastapi import FastAPI, HTTPException, Query, Request
from pymongo import MongoClient
from typing import List
from datetime import datetime, timedelta
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

app = FastAPI()

# MongoDB connection configuration
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")
COLLECTION_NAME = os.getenv("COLLECTION_NAME")

# Rate limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

class CVE(BaseModel):
    cve: dict

def get_mongo_collection(db_name=DB_NAME, collection_name=COLLECTION_NAME):
    """
    Get the MongoDB collection.

    Args:
        db_name (str): The name of the database.
        collection_name (str): The name of the collection.

    Returns:
        collection: The MongoDB collection object.
    """
    client = MongoClient(MONGO_URI)
    db = client[db_name]
    collection = db[collection_name]
    return collection

@app.get("/cve/cve_id", response_model=CVE)
@limiter.limit("5/minute")
async def get_cve_by_id(request: Request, id: str):
    """
    Get a CVE by its ID.

    Args:
        request (Request): The HTTP request object.
        id (str): The CVE ID.

    Returns:
        CVE: The CVE data.
    """
    collection = get_mongo_collection()
    cve = collection.find_one({'cve.id': id}, {'_id': 0})
    if cve:
        return cve
    else:
        raise HTTPException(status_code=404, detail="CVE not found")

@app.get("/cve/score", response_model=List[CVE])
@limiter.limit("5/minute")
async def get_cve_by_score(request: Request, min_score: float = Query(0.0, ge=0.0), max_score: float = Query(10.0, le=10.0)):
    """
    Get CVEs by their CVSS score range.

    Args:
        request (Request): The HTTP request object.
        min_score (float): The minimum CVSS score.
        max_score (float): The maximum CVSS score.

    Returns:
        List[CVE]: A list of CVEs within the specified score range.
    """
    collection = get_mongo_collection()
    cves = collection.find({
        '$or': [
            {'cve.metrics.cvssMetricV2.cvssData.baseScore': {'$gte': min_score, '$lte': max_score}},
            {'cve.metrics.cvssMetricV3.cvssData.baseScore': {'$gte': min_score, '$lte': max_score}}
        ]
    }, {'_id': 0})
    return list(cves)

@app.get("/cve/modified", response_model=List[CVE])
@limiter.limit("5/minute")
async def get_cve_by_modified_date(request: Request, days: int = Query(7, ge=1)):
    """
    Get CVEs modified within the last specified number of days.

    Args:
        request (Request): The HTTP request object.
        days (int): The number of days to look back.

    Returns:
        List<CVE>: A list of CVEs modified within the specified time frame.
    """
    date_threshold = (datetime.now() - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
    collection = get_mongo_collection()
    cves = collection.find({'cve.lastModified': {'$gte': str(date_threshold)}}, {'_id': 0})
    return list(cves)

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=2040, log_level="debug")
