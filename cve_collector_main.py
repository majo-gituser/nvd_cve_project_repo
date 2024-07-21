import aiohttp
import asyncio
from datetime import datetime, timedelta
from mongo_connection import MongoCon
import schedule
import time
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

NVD_CVE_API = os.getenv("NVD_CVE_API")
Pagination = 2000
Sync_Interval_Days = int(os.getenv("SYNC_INTERVAL_DAYS"))

mongo_con_obj = MongoCon()

async def get_cve_data_from_api(session, params, retries=3):
    """
    Fetch CVE data from the NVD API with retry logic.

    Args:
        session (aiohttp.ClientSession): The HTTP session to use.
        params (dict): The query parameters for the API call.
        retries (int): The number of retry attempts in case of failure.

    Returns:
        dict: The JSON response from the API, or None if an error occurred.
    """
    for attempt in range(retries):
        try:
            async with session.get(NVD_CVE_API, params=params) as response:
                if response.status == 403:
                    print(f"Access forbidden for URL: {response.url}")
                    return None
                response.raise_for_status()  # Raise an exception for HTTP errors
                return await response.json()
        except aiohttp.ClientResponseError as e:
            if e.status in [429, 500, 502, 503, 504]:  # Retry on server errors
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
                continue
            print(f"HTTP error {e.status} for URL: {response.url}")
        except Exception as e:
            print(f"Error fetching data: {e}")
    return None

async def collect_cve_data_at_once(start_index=0, results_per_page=Pagination):
    """
    Collect CVE data in a single run, starting from a specific index.

    Args:
        start_index (int): The starting index for the data collection.
        results_per_page (int): The number of results to fetch per page.

    Returns:
        None
    """
    async with aiohttp.ClientSession() as session:
        while True:
            params = {
                'startIndex': start_index,
                'resultsPerPage': results_per_page
            }
            data = await get_cve_data_from_api(session, params)
            if not data or 'vulnerabilities' not in data:
                print(f"End of data / Invalid data structure received from NVD API at index {start_index}.")
                break

            await mongo_con_obj.store_cve_data(data)

            # If fewer results are returned than requested, it indicates no more data
            if len(data.get('vulnerabilities', [])) < results_per_page:
                print("No more data available.")
                break

            start_index += results_per_page
            await asyncio.sleep(1)  # Avoid rate limiting

async def update_cve_from_api(start_index=0, results_per_page=Pagination):
    """
    Update the CVE data from the API incrementally based on the last sync time.

    Args:
        start_index (int): The starting index for the data update.
        results_per_page (int): The number of results to fetch per page.

    Returns:
        None
    """
    last_sync_time = await mongo_con_obj.get_last_sync_time()
    if not last_sync_time:
        last_sync_time = (datetime.now() - timedelta(days=30)).isoformat()
    current_time = datetime.now().isoformat()
    
    async with aiohttp.ClientSession() as session:
        while True:
            params = {
                "startIndex": start_index,
                "resultsPerPage": results_per_page,
                "lastModStartDate": last_sync_time,
                "lastModEndDate": current_time
            }
            data = await get_cve_data_from_api(session, params)
            if not data or 'vulnerabilities' not in data:
                print(f"End of data / Invalid data structure received from NVD API at index {start_index}.")
                break

            await mongo_con_obj.add_or_update_cve_in_mongo(data)

            # If fewer results are returned than requested, it indicates no more data
            if len(data.get('vulnerabilities', [])) < results_per_page:
                print("No more data available.")
                break

            start_index += results_per_page
            await asyncio.sleep(1)  # Avoid rate limiting

    await mongo_con_obj.update_last_sync_time(datetime.now().isoformat())

def run_one_time_scan():
    """
    Run a one-time scan to collect all CVE data.

    Returns:
        None
    """
    print("Running one time data sync")
    loop = asyncio.get_event_loop()
    start_time = datetime.now()
    loop.run_until_complete(collect_cve_data_at_once())
    end_time = datetime.now()
    print("time_took : ", end_time - start_time)

def run_incremental_update():
    """
    Run an incremental update to collect CVE data based on the last sync time.

    Returns:
        None
    """
    print("Starting data update")
    loop = asyncio.get_event_loop()
    start_time = datetime.now()
    loop.run_until_complete(update_cve_from_api())
    end_time = datetime.now()
    print("time_took : ", end_time - start_time)


if __name__ == "__main__":
    run_one_time_scan()
    schedule.every(Sync_Interval_Days).days.do(run_incremental_update)
    while True:
        schedule.run_pending()
        time.sleep(1)
