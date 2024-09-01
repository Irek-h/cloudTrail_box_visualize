import os
import json
import matplotlib.pyplot as plt
from datetime import datetime

# Function to load all CloudTrail logs from the current directory
def load_cloudtrail_logs_from_directory(directory='.'):
    logs = []
    for filename in os.listdir(directory):
        if filename.endswith(".json"):
            filepath = os.path.join(directory, filename)
            print(f"Loading {filepath}")  # Debug: Output the file being processed
            try:
                with open(filepath, 'r') as file:
                    data = json.load(file)
                    records = data.get('Records', [])
                    logs.extend(records)
                    print(f"Loaded {len(records)} records from {filename}")  # Debug: Output the number of records loaded
            except json.JSONDecodeError:
                print(f"Error reading {filename}, it may not be a valid JSON file.")
    return logs

def check(logs):
    for record in logs:
        print(record['userIdentity'])


check(load_cloudtrail_logs_from_directory())