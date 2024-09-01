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

# Function to process logs and extract actions with timestamps
def process_logs(logs):
    actions = []
    for record in logs:
        user_identity = record.get('userIdentity', {})
        user = user_identity.get('arn', user_identity.get('userName', 'unknown')).split('/')[-1]
        action = {
            'user': user,  # Extract user or default to 'unknown'
            'action': record.get('eventName', 'unknown'),
            'resource': record.get('requestParameters', {}).get('instanceId', 'unknown'),  # Example for EC2
            'time': datetime.strptime(record['eventTime'], '%Y-%m-%dT%H:%M:%SZ')  # Convert eventTime to datetime object
        }
        actions.append(action)

    # Sort actions by time
    actions.sort(key=lambda x: x['time'])
    print(f"Total actions processed: {len(actions)}")  # Debug: Output the total number of actions processed
    return actions

# Function to visualize actions on a timeline without connecting them
def visualize_actions_timeline(actions):
    times = [action['time'] for action in actions]
    labels = [f"{action['action']} by {action['user']}\n{action['resource']}" for action in actions]

    plt.figure(figsize=(15, 5))
    plt.scatter(times, [1] * len(times), c='skyblue', s=100)  # Plot each action as a point
    for i, label in enumerate(labels):
        plt.text(times[i], 1.01, label, rotation=45, ha='right', fontsize=8)

    plt.yticks([])  # Remove y-axis labels
    plt.xlabel('Time')
    plt.title('CloudTrail Actions Timeline')
    plt.grid(True)
    plt.show()

# Main execution
directory = '.'  # Assuming the current directory
logs = load_cloudtrail_logs_from_directory(directory)
actions = process_logs(logs)
visualize_actions_timeline(actions)
