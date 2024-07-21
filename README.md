CVE Data Collection and API Service

Overview

	This project consists of three main components:
		1. Data Collector (cve_collector_main.py): Collects and updates CVE data from the NVD API and stores it in MongoDB.
		2. MongoDB Connection (mongo_connection.py): Handles MongoDB operations, including storing, updating, and querying CVE data.
		3. API Service (api_main.py): Provides a RESTful API to query CVE data from MongoDB.

Components

	1. Data Collector (cve_collector_main.py)

		This script is responsible for:
			- Fetching CVE data from the NVD API.
			- Storing new CVEs or updating existing ones in MongoDB.
			- Running periodic updates using the schedule library.

		Key Features:
			- Uses aiohttp for asynchronous HTTP requests.
			- Handles pagination and retries for API requests.
			- Uses asynchronous I/O for efficient data processing.

	2. MongoDB Connection (mongo_connection.py)

		This module provides an interface for:
			- Connecting to MongoDB.
			- Storing and updating CVE data in the MongoDB collections.
			- Managing synchronization timestamps.

		Key Features:
			- Uses motor for asynchronous MongoDB operations.
			- Provides methods for bulk writing and incremental updates.

	3. API Service (api_main.py)

		This FastAPI application exposes endpoints to:
			- Retrieve CVE details by ID.
			- Query CVEs based on their CVSS score.
			- Retrieve CVEs modified within a specified time range.

		Key Features:
			- Implements rate limiting using slowapi.
			- Provides fast, asynchronous API responses.
			- Uses pydantic for data validation and type checking.

Installation
	1. Prerequisites
		Python 3.7+
		MongoDB
		Virtual Environment (recommended)

	1. Clone the repository:
		git clone https://github.com/majo-gituser/nvd_cve_project_repo.git
		cd nvd_cve_project_repo
    
	2. Create a virtual environment and install dependencies:
		python -m venv venv
		source venv/bin/activate   On Windows use venv\Scripts\activate
		pip install -r requirements.txt

	3. Setup .env file
		NVD_CVE_API=<Your NVD CVE API URL>
		MONGO_URI=<Your MongoDB URI>
		DB_NAME=<Your Database Name>
		COLLECTION_NAME=<Your CVE Collection Name>
		SYNC_COLLECTION_NAME=<Your Sync Collection Name>
		SYNC_INTERVAL_DAYS=<Sync Interval in Days>

    

3. Set up MongoDB and ensure it's running on localhost:27017.

Usage

	Running the Data Collector

		To run the data collector and perform an incremental update:
			python cve_collector_main.py
		The script will also schedule updates every SYNC_INTERVAL_DAYS days configured in .env file.

	Running the API Service

		python api_main.py 
		The API will be available at http://localhost:2040.

Endpoints:

	GET /cve/cve_id: Retrieve CVE details by ID.
		Query Parameters: id (string) - The CVE ID.

	GET /cve/score: Query CVEs based on CVSS score.
		Query Parameters: min_score (float) - Minimum CVSS score, max_score (float) - Maximum CVSS score.

	GET /cve/modified: Retrieve CVEs modified within a specified number of days.
		Query Parameters: days (int) - Number of days to look back.
	
Troubleshooting:
	Ensure that all environment variables are correctly set in the `.env` file.
	Check MongoDB connection settings and ensure the database is accessible.
	Monitor API rate limits and adjust sleep intervals to avoid being throttled.
	Use profiling tools to identify and resolve performance bottlenecks.
