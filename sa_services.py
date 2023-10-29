# Required Imports
import os
import subprocess
import time
import requests
import jwt as pyjwt
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from cryptography.hazmat.primitives import serialization
        
import base64
import json
import requests
from cryptography.hazmat.primitives import serialization
import time
import jwt as pyjwt
from google.auth.credentials import Credentials

# Function to authenticate the user
def authenticate():
    # Get credential path
    credential_path = os.path.expanduser('~/.config/gcloud/application_default_credentials.json')
    if not os.path.exists(credential_path):
        # Authenticate if credentials not found
        subprocess.run(["gcloud", "auth", "application-default", "login"], check=True)

# Function to create a service account
def create_service_account():
    try:
        # Input project id and account name
        project_id = input("Enter the project ID: ")
        account_name = input("Enter the service account name: ")
        
        # Create service account using gcloud command
        subprocess.run(["gcloud", "iam", "service-accounts", "create", account_name, "--display-name", 
                        account_name, "--project", project_id], check=True)
        print(f"Service account {account_name} created successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error creating service account: {e}")

# Function to get a service account
def get_service_account():
    try:
        # Input service account email
        email = input("Enter the service account email: ")
        
        # Get service account details using gcloud command
        subprocess.run(["gcloud", "iam", "service-accounts", "describe", email], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error getting service account: {e}")

# Function to list all service accounts
def list_service_accounts():
    try:
        # Input project id
        project_id = input("Enter the project ID: ")
        
        # List service accounts using gcloud command
        subprocess.run(["gcloud", "iam", "service-accounts", "list", "--project", project_id], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error listing service accounts: {e}")

# Function to delete a service account
def delete_service_account():
    try:
        # Input service account email
        email = input("Enter the service account email: ")
        
        # Delete service account using gcloud command
        subprocess.run(["gcloud", "iam", "service-accounts", "delete", email, "--quiet"], check=True)
        print(f"Service account {email} deleted successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error deleting service account: {e}")

# Function to upload the certificate as a service account key to Google Cloud
def upload_certificate():
    try:
        # Input service account email and certificate file name
        email = input("Enter the service account email: ")
        cert_file = input("Enter the certificate file name (with extension): ")
        
        # Upload certificate using gcloud command
        subprocess.run(["gcloud", "iam", "service-accounts", "keys", "upload", cert_file, "--iam-account", 
                        email], check=True)
        print(f"Certificate uploaded successfully to service account {email}.")
    except subprocess.CalledProcessError as e:
        print(f"Error uploading certificate: {e}")

# List all instances in a project
def list_instances():
    try:
        # Load the private key
        with open("private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        # Define necessary claims for a Google service account
        claims = {
            "iss": "[SERVICE_ACCOUNT_NAME]@[PROJECT_NAME].iam.gserviceaccount.com",
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "aud": "https://www.googleapis.com/oauth2/v4/token",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        # Generate JWT
        encoded_jwt = pyjwt.encode(claims, private_key, algorithm='RS256')
        # Send the JWT to the Google OAuth 2.0 Authorization Server
        response = requests.post(
            "https://www.googleapis.com/oauth2/v4/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": encoded_jwt,
            },
        )
        # Verify if the response was successful
        response.raise_for_status()

        # Get access token from response
        access_token = response.json()["access_token"]
        # Create credentials with the access token
        credentials = Credentials(access_token)

        # Authenticate API requests
        service = build('compute', 'v1', credentials=credentials)

        # Get list of all instances in the project
        instances = service.instances().list(project='[PROJECT_NAME]', zone='us-west1-b').execute()

        # Check if instances exist
        if 'items' in instances:
            for instance in instances['items']:
                print(f"Instance name: {instance['name']}")
        else:
            print(f"No instances found in the project.")
    except Exception as e:
        print(f"An error occurred while listing the instances: {e}")

def upload_certificate_sa():
    try:
        # Load the private key
        with open("private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        # Define necessary claims for a Google service account
        claims = {
            "iss": "[SA_NAME]@[PROJECT_NAME].iam.gserviceaccount.com",
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "aud": "https://www.googleapis.com/oauth2/v4/token",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        # Generate JWT
        encoded_jwt = pyjwt.encode(claims, private_key, algorithm='RS256')
        # Send the JWT to the Google OAuth 2.0 Authorization Server
        response = requests.post(
            "https://www.googleapis.com/oauth2/v4/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": encoded_jwt,
            },
        )
        # Verify if the response was successful
        response.raise_for_status()

        # Get access token from response
        access_token = response.json()["access_token"]
        # Create credentials with the access token
        # credentials = Credentials(access_token)
        
        # Define the headers
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json; charset=utf-8',
        }

        # Load the data from the self_signed.crt file
        with open('self_signed.crt', 'rb') as f:
            data = f.read()

        # Encode the certificate in base64
        base64_cert = base64.b64encode(data).decode('utf-8')

        # Create a JSON payload with the base64 encoded certificate
        payload = {
            'publicKeyData': base64_cert,
        }

        # Define the URL
        url = "https://iam.googleapis.com/v1/projects/[PROJECT_NAME]/serviceAccounts/[SERVICE_ACCOUNT_NAME].iam.gserviceaccount.com/keys:upload"
        # Make the POST request
        response = requests.post(url, headers=headers, json=payload)
        # Print the response
        print(response.json())
        
    except Exception as e:
        print(f"An error occurred uploading the certificate: {e}")

# Main function
def main():
    # Authenticate user
    authenticate()
    while True:
        # Display options
        print("1. Create a service account")
        print("2. Get a service account")
        print("3. List all service accounts")
        print("4. Delete a service account")
        print("5. Upload the certificate as a service account key to Google Cloud")
        print("6. List instances")
        print("7. upload certificate using sa")
        print("8. Exit")
        choice = input("Enter your choice: ")
        # Execute option based on user choice
        if choice == '1':
            create_service_account()
        elif choice == '2':
            get_service_account()
        elif choice == '3':
            list_service_accounts()
        elif choice == '4':
            delete_service_account()
        elif choice == '5':
            upload_certificate()
        elif choice == '6':
            list_instances()
        elif choice == '7':
            upload_certificate_sa()
        elif choice == '8':
            break
        else:
            print("Invalid choice. Please try again.")

# Begin execution here
if __name__ == "__main__":
    main()
