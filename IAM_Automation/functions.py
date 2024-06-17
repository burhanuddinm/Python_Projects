import boto3
import getpass
from tabulate import tabulate
import csv
import os
import signal
import botocore
from datetime import datetime, timezone
from botocore.exceptions import ClientError
import platform
import threading
import time



#Login Functions#
credentials_path = os.environ.get("AWS_CONFIG_FILE")


def get_aws_credentials(credentials_path, max_attempts=3):
    # if not credentials_path.strip():
    #     print("Path cannot be kept as empty/invalid.")
    #     return

    attempts = 0
    
    while attempts < max_attempts:
        # Check if credentials file exists
        if os.path.exists(credentials_path) and os.path.getsize(credentials_path) > 0:
            with open(credentials_path, "r") as file:
                access_key_id = file.readline().strip()
                secret_access_key = file.readline().strip()

            # Verify the credentials
            if verify_aws_credentials(access_key_id, secret_access_key):
                print("User login successful.")
                return access_key_id, secret_access_key
            else:
                print("Invalid credentials. Please provide correct AWS credentials.")
                clear_credentials_file(credentials_path)
        else:
            print("Credentials file is empty or not found. Please provide your AWS credentials.")
            access_key_id = input("Enter your AWS Access Key ID: ")
            secret_access_key = getpass.getpass(prompt='Enter your AWS Secret Access Key: ')

            # Verify the credentials
            if verify_aws_credentials(access_key_id, secret_access_key):
                # Save credentials to file
                with open(credentials_path, "w") as file:
                    file.write(f"[default]\n")
                    file.write(f"aws_access_key_id = {access_key_id}\n")
                    file.write(f"aws_secret_access_key = {secret_access_key}\n")
                print("User login successful.")
                return access_key_id, secret_access_key
            else:
                print("Invalid credentials. Please provide correct AWS credentials.")
                # Clear the credentials file
                clear_credentials_file(credentials_path)
        
        attempts += 1
    
    # If max_attempts reached, exit the script
    print("Maximum login attempts reached. Exiting script.")
    exit(1)
        
def verify_aws_credentials(access_key_id, secret_access_key):
    try:
        # Create an STS client using the provided credentials
        sts_client = boto3.client('sts', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
        
        # Call get_caller_identity() to verify the credentials
        sts_client.get_caller_identity()
        
        # If the call succeeds, the credentials are valid
        return True
    except Exception as e:
        print(f"Credential verification failed: {e}")
        # If any exception occurs, the credentials are invalid
        return False

def reset_timer():
    global timer
    if timer:
        timer.cancel()
    timer = threading.Timer(60, auto_exit)  # 300 seconds = 5 minutes
    timer.start()
    
def auto_exit():
    print("\nNo activity detected for 5 minutes. Exiting...")
    clear_credentials_file(credentials_path)
    exit(0)


def is_valid_path(path):
    return os.path.isdir(path)

def clear_credentials_file(credentials_path):
    with open(credentials_path, "w") as file:
        file.write("")


#Create Functions#

def create_iam_client(credentials_path):
    access_key_id, secret_access_key = get_aws_credentials(credentials_path)
    return boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)

def create_aws_group(group_name, policy_arn):
    # Create IAM client
    iam = boto3.client('iam')
    try:
        # Attempt to create the group
        response = iam.create_group(GroupName=group_name)
        print("Group created:", group_name)
    except ClientError as e:
        # Check if the error is due to the group already existing
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            print(f"Group '{group_name}' already exists. Please select a unique group name.")
            return None
        else:
            # If it's another type of error, raise it to the caller
            raise e
    
    # Attach policy
    iam.attach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
    
    return response['Group']

def create_aws_user(username):
    # Create IAM client
    iam = boto3.client('iam')
    
    # Create user
    response = iam.create_user(UserName=username)
    
    return response['User']

def create_login_profile_for_user(username, password):
    iam = boto3.client('iam')
    try:
        # Correctly create a login profile without using unsupported parameters
        response = iam.create_login_profile(
            UserName=username,
            Password=password,
            # Optional: Set PasswordResetRequired to True if the user should reset their password upon next sign-in
            PasswordResetRequired=True  # Defaults to False if not specified
        )
        # Access and print the response to see the details of the operation
        print(f"Login profile for user '{username}' created successfully.")
    except Exception as e:
        print(f"Failed to create login profile for user '{username}': {str(e)}")


def delete_login_profile(username):
    iam = boto3.client('iam')
    try:
        iam.delete_login_profile(UserName=username)
        print(f"Login profile for user '{username}' deleted successfully.")
    except iam.exceptions.NoSuchEntityException:
        print(f"No login profile found for user '{username}'.")
    except botocore.exceptions.BotoCoreError as e:
        print(f"An error occurred: {e}")
        
def clone_user(existing_username, new_username, credentials_path):
    aws_credentials = {
        'aws_access_key_id': '',
        'aws_secret_access_key': '',
        'region_name': 'us-east-1'  # Specify your AWS region
    }

    with open(credentials_path, 'r') as f:
        for line in f:
            if line.startswith('aws_access_key_id'):
                aws_credentials['aws_access_key_id'] = line.split('=')[1].strip()
            elif line.startswith('aws_secret_access_key'):
                aws_credentials['aws_secret_access_key'] = line.split('=')[1].strip()

        iam = boto3.client('iam', **aws_credentials)
        
    # Step 1 & 2: Create a new user profile
    try:
        iam.create_user(UserName=new_username)
        print(f"Created new user: {new_username}")
    except iam.exceptions.EntityAlreadyExistsException:
        print(f"User {new_username} already exists.")

    # Step 3: Clone all policies attached to the existing user
    try:
        existing_user_policies = iam.list_attached_user_policies(UserName=existing_username)
        for policy in existing_user_policies['AttachedPolicies']:
            iam.attach_user_policy(UserName=new_username, PolicyArn=policy['PolicyArn'])
            print(f"Attached policy {policy['PolicyArn']} to {new_username}")
    except iam.exceptions.NoSuchEntityException:
        print(f"No policies found for user {existing_username}.")
    except iam.exceptions.InvalidInputException:
        print("Failed to attach policies due to invalid input.")

    # Step 4: Clone group memberships
    try:
        existing_user_groups = iam.list_groups_for_user(UserName=existing_username)
        for group in existing_user_groups['Groups']:
            iam.add_user_to_group(GroupName=group['GroupName'], UserName=new_username)
            print(f"Added user {new_username} to group {group['GroupName']}")
    except iam.exceptions.NoSuchEntityException:
        print(f"No groups found for user {existing_username}.")
    except iam.exceptions.InvalidInputException:
        print("Failed to add user to groups due to invalid input.")

    # Step 5: Clone access keys
    try:
        existing_access_keys = iam.list_access_keys(UserName=existing_username)
        for access_key in existing_access_keys['AccessKeyMetadata']:
            iam.create_access_key(UserName=new_username)
            print(f"Created access key for {new_username}")
    except iam.exceptions.NoSuchEntityException:
        print(f"No access keys found for user {existing_username}.")
    except iam.exceptions.InvalidInputException:
        print("Failed to create access keys due to invalid input.")

    print(f"Successfully cloned user {existing_username} to {new_username}.")

    
def list_users_groups_and_access_keys_Clone():
    iam = boto3.client('iam')
    response = iam.list_users()
    users = response['Users']
    
    print("List of users:")
    for user in users:
        username = user['UserName']
        print(f"Username: {username}")
        # Optionally, list groups and policies associated with each user here


def create_access_key(username, credentials_path):
    iam = boto3.client('iam')
    response = iam.create_access_key(UserName=username)
    access_key = response['AccessKey']

    # Write the access key to a CSV file in the same directory as the script
    access_key_file_path = os.path.join(credentials_path, f"{username}_access_keys.csv")
    with open(access_key_file_path, "w") as file:
        file.write("AccessKeyId,SecretAccessKey\n")
        file.write(f"{access_key['AccessKeyId']},{access_key['SecretAccessKey']}\n")
    print(f"Access key created and saved to {access_key_file_path}")

def delete_access_keys(username):
    iam = boto3.client('iam')
    try:
        # List user's access keys
        response = iam.list_access_keys(UserName=username)
        access_keys = response['AccessKeyMetadata']
        
        # Delete each access key
        for access_key in access_keys:
            iam.delete_access_key(UserName=username, AccessKeyId=access_key['AccessKeyId'])
            print(f"Access key '{access_key['AccessKeyId']}' deleted for user '{username}'.")
    except iam.exceptions.NoSuchEntityException:
        print(f"No access keys found for user '{username}'.")

def create_password():
    # Generate a random password
    password = getpass.getpass(prompt='Enter password for the user: ')
    
    return password


def delete_group_and_users(group_name):
    """
    Deletes the specified group and detaches its policies without deleting the users.

    Parameters:
    - group_name (str): The name of the group to delete.
    """
    iam = boto3.client('iam')

    try:
        # Retrieve information about the group
        response = iam.get_group(GroupName=group_name)
        users = response.get('Users', [])
        attached_policies = iam.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
    except iam.exceptions.NoSuchEntityException:
        print(f"Group '{group_name}' does not exist.")
        return

    # List users associated with the group
    print(f"Users in group '{group_name}':")
    for user in users:
        print("- Username:", user['UserName'])

    # List policies attached to the group
    print(f"\nPolicies attached to group '{group_name}':")
    for policy in attached_policies:
        print("- Policy ARN:", policy['PolicyArn'])

    # Ask for confirmation to delete the group
    confirmation = input("Please confirm if you want to delete the group and its associated users (yes/no): ").lower()
    if confirmation == "yes":
        # Detach each policy from the group
        for policy in attached_policies:
            iam.detach_group_policy(GroupName=group_name, PolicyArn=policy['PolicyArn'])
            print(f"Policy '{policy['PolicyName']}' detached from group '{group_name}'")

        # Remove each user from the group
        for user in users:
            username = user['UserName']
            iam.remove_user_from_group(GroupName=group_name, UserName=username)
            print(f"User '{username}' removed from group '{group_name}'")

        # Delete the group
        iam.delete_group(GroupName=group_name)
        print(f"Group '{group_name}' deleted successfully.")
    elif confirmation == "no":
        print("Deletion cancelled.")
    else:
        print("Invalid input. Please enter 'yes' or 'no'.")

def delete_group(group_name):
    # Create IAM client
    iam = boto3.client('iam')
    
    try:
        # Delete group
        iam.delete_group(GroupName=group_name)
        print("Group deleted:", group_name)
    except iam.exceptions.NoSuchEntityException:
        print(f"Group '{group_name}' does not exist.")
    except iam.exceptions.DeleteConflictException as e:
        # Handle deletion conflict (e.g., users still exist in the group)
        print(f"Error: {e}")
        print(f"Group '{group_name}' has active user(s). Please remove them first before deleting the group.")
    except Exception as e:
        print(f"An error occurred: {e}")
        
def delete_user(username):
    # Create IAM client
    iam = boto3.client('iam')

    try:
        # List user's access keys
        response = iam.list_access_keys(UserName=username)
        access_keys = response['AccessKeyMetadata']
        
        # Delete each access key
        for access_key in access_keys:
            iam.delete_access_key(UserName=username, AccessKeyId=access_key['AccessKeyId'])
            print(f"Access key '{access_key['AccessKeyId']}' deleted for user '{username}'")
       
        # Detach policies from the user
        attached_policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
        for policy in attached_policies:
            iam.detach_user_policy(UserName=username, PolicyArn=policy['PolicyArn'])
            print(f"Detached policy '{policy['PolicyArn']}' from user '{username}'")
       
        # Delete user
        iam.delete_user(UserName=username)
        print("User deleted:", username)
    except iam.exceptions.NoSuchEntityException:
        print(f"User '{username}' does not exist.")
    except iam.exceptions.NoSuchEntityException:
        print(f"User '{username}' does not have any access keys.")


def unlink_user_from_group(username, group_name):
    iam = boto3.client('iam')
    try:
        iam.remove_user_from_group(GroupName=group_name, UserName=username)
        print(f"User {username} unlinked from group {group_name}")
    except Exception as e:
        print(f"Error unlinking user {username} from group {group_name}: {e}")


def detach_policies_from_group(group_name):
    # Create IAM client
    iam = boto3.client('iam')

    # List attached policies
    response = iam.list_attached_group_policies(GroupName=group_name)
    policies = response['AttachedPolicies']

    # Detach policies from the group
    for policy in policies:
        iam.detach_group_policy(GroupName=group_name, PolicyArn=policy['PolicyArn'])
        print(f"Policy '{policy['PolicyName']}' detached from group '{group_name}'")
    
def group_exists(group_name):
    # Check if group exists
    try:
        iam = boto3.client('iam')
        iam.get_group(GroupName=group_name)
        return True
    except iam.exceptions.NoSuchEntityException:
        return False

def link_user_to_group(username, group_name):
    # Create IAM client
    iam = boto3.client('iam')
    
    # Add user to group
    iam.add_user_to_group(UserName=username, GroupName=group_name)

#--------------------------------------------------------------------#
def list_active_groups():
    # Create IAM client
    iam = boto3.client('iam')

    # List all IAM groups
    response = iam.list_groups()
    groups = response['Groups']
    
    # Extract group names
    group_names = [group['GroupName'] for group in groups]

    # Print groups in a table format
    headers = ["Group Name"]
    data = [[group_name] for group_name in group_names]
    print(tabulate(data, headers=headers, tablefmt="grid"))
    
def list_active_users():
    # Create IAM client
    iam = boto3.client('iam')

    # List all IAM users
    response = iam.list_users()
    users = response['Users']

    # Extract user names
    user_names = [user['UserName'] for user in users]

    # Print users in a table format
    headers = ["User Name"]
    data = [[user_name] for user_name in user_names]
    print(tabulate(data, headers=headers, tablefmt="grid"))
    
def list_users_and_groups():
    # Create IAM client
    iam = boto3.client('iam')
    
    # List all IAM users
    try:
        response = iam.list_users()
        users = response.get('Users', [])  # Use .get() to handle potential missing key
        if not users:
            print("No users found.")
            return
    except Exception as e:
        print(f"Error: {e}")
        return

    user_data = []
    for user in users:
        user_name = user['UserName']
        groups = get_user_groups(iam, user_name)
        user_data.append([user_name, groups])
    
    # Print the user and group details in tabular format
    print(tabulate(user_data, headers=["Username", "Groups"], tablefmt="grid"))   

    
def list_user_and_group_options():
    print("User and Group Options:")
    print("1. List user and group details")
    print("2. List group details with associated users")
    print("3. List users and last login details")
    print("4. Download list of users and associated groups")
    
    choice = input("Enter the number corresponding to your choice: ")
    
    if choice == "1":
        list_users_groups_and_access_keys()
    elif choice == "2":
        list_all_groups_and_users()
    elif choice == "3":
        list_users_and_last_login()
    elif choice == "4":
        download_user_list()
    else:
        print("Invalid choice. Please enter a number between 1 and 4.")

def list_users_groups_and_access_keys():
    # Create IAM client
    iam = boto3.client('iam')

    # List all IAM users
    try:
        response = iam.list_users()
        users = response.get('Users', [])
        if not users:
            print("No users found.")
            return
    except Exception as e:
        print(f"Error: {e}")
        return

    user_data = []
    all_groups = set()
    groups_with_users = set()

    for user in users:
        user_name = user['UserName']
        
        # Get the user's groups
        try:
            user_groups_response = iam.list_groups_for_user(UserName=user_name)
            user_groups = [group['GroupName'] for group in user_groups_response['Groups']]
            groups_with_users.update(user_groups)
        except Exception as e:
            print(f"Error fetching groups for user {user_name}: {e}")
            user_groups = []

        # Check if the user has access keys
        try:
            access_keys_response = iam.list_access_keys(UserName=user_name)
            access_keys_present = len(access_keys_response['AccessKeyMetadata']) > 0
        except Exception as e:
            print(f"Error fetching access keys for user {user_name}: {e}")
            access_keys_present = False

        # Combine all groups into a single string
        groups_str = ', '.join(user_groups) if user_groups else 'No groups'

        user_data.append([user_name, groups_str, 'Yes' if access_keys_present else 'No'])

    # List all IAM groups
    try:
        response = iam.list_groups()
        groups = response.get('Groups', [])
        if not groups:
            print("No groups found.")
            return
        all_groups = {group['GroupName'] for group in groups}
    except Exception as e:
        print(f"Error: {e}")
        return

    # Identify groups with no users
    groups_without_users = all_groups - groups_with_users

    # Add groups with no users to user_data
    for group in groups_without_users:
        user_data.append([f"No users", group, ''])

    print("Users, Groups, Access Keys Present:")
    print(tabulate(user_data, headers=["User Name", "Groups", "Access Keys Present"], tablefmt="grid"))
        
def list_all_groups_and_users():
    # Create IAM client
    iam = boto3.client('iam')

    # List all IAM groups
    response = iam.list_groups()
    groups = response['Groups']

    group_data = []
    for group in groups:
        group_name = group['GroupName']
        
        # Get users in the group
        response = iam.get_group(GroupName=group_name)
        users = response['Users']
        
        users_list = [user['UserName'] for user in users]
        group_data.append([group_name, ', '.join(users_list) if users_list else 'No users in this group'])

    print("Groups and their associated users:")
    print(tabulate(group_data, headers=["Group Name", "Associated Users"], tablefmt="grid"))

def list_users_and_last_login():
    # Create IAM client
    iam = boto3.client('iam')
    iam_client = boto3.client('iam')

    # List all IAM users
    response = iam.list_users()
    users = response['Users']
    
    user_data = []
    for user in users:
        user_name = user['UserName']
        creation_time = user['CreateDate'].strftime("%Y-%m-%d %H:%M:%S")
        
        # Last Activity
        try:
            user_details = iam.get_user(UserName=user_name)
            last_activity = user_details['User'].get('PasswordLastUsed', "Never used")
            if isinstance(last_activity, datetime):
                last_activity = last_activity.strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:
            last_activity = "Error fetching last activity"
        
        # Password Age
        try:
            login_profile = iam.get_login_profile(UserName=user_name)
            password_age = (datetime.now(timezone.utc) - login_profile['LoginProfile']['CreateDate']).days
        except iam.exceptions.NoSuchEntityException:
            password_age = "No password"

        # Console Last Sign-In
        try:
            password_last_used = user.get('PasswordLastUsed')
            if password_last_used:
                console_last_sign_in = password_last_used.strftime("%Y-%m-%d %H:%M:%S")
            else:
                console_last_sign_in = "Never signed in"
        except Exception as e:
            console_last_sign_in = "Error fetching sign-in info"

        # Access Key Last Use
        try:
            access_keys_response = iam.list_access_keys(UserName=user_name)
            access_keys = access_keys_response.get('AccessKeyMetadata', [])
            if access_keys:
                last_used_info = iam.get_access_key_last_used(AccessKeyId=access_keys[0]['AccessKeyId'])
                access_key_last_use = last_used_info['AccessKeyLastUsed']['LastUsedDate'].strftime("%Y-%m-%d %H:%M:%S")
            else:
                access_key_last_use = "No access key"
        except Exception as e:
            access_key_last_use = "Error fetching access key usage"

        user_data.append([user_name, last_activity, password_age, console_last_sign_in, access_key_last_use, creation_time])
    
    # Print user data in a table format
    print("Users and their details:")
    print(tabulate(user_data, headers=["User Name", "Last Activity", "Password Age (days)", "Console Last Sign-In", "Access Key Last Use", "Creation Time"], tablefmt="grid"))


def get_user_groups(iam, username):
    try:
        response = iam.list_groups_for_user(UserName=username)
        groups = response['Groups']
        return ", ".join(group['GroupName'] for group in groups)
    except iam.exceptions.NoSuchEntityException:
        return "No groups"

def get_user_tags(iam, username):
    try:
        response = iam.list_user_tags(UserName=username)
        tags = response['Tags']
        return ", ".join(f"{tag['Key']}={tag['Value']}" for tag in tags)
    except iam.exceptions.NoSuchEntityException:
        return "No tags"


def download_user_list():
    # Create IAM client
    iam = boto3.client('iam')

    # List all IAM users
    try:
        response = iam.list_users()
        users = response.get('Users', [])
        if not users:
            print("No users found.")
            return
    except Exception as e:
        print(f"Error: {e}")
        return

    # Ask the user to input the filename
    csv_file_name = input("Enter the filename (without extension) to save the user list (e.g., user_list): ")

    # Define the CSV file path
    csv_file_path = f"{csv_file_name}.csv"

    # Write user details to a CSV file
    with open(csv_file_path, "w", newline="") as file:
        # Define the CSV writer
        writer = csv.writer(file)

        # Write header row
        writer.writerow(["Username", "Group", "ARN", "Console Access", "Created Date", "Last Activity", "Access Key", "Permissions", "Tags"])

        # Write user details
        for user in users:
            user_name = user["UserName"]
            arn = user["Arn"]
            created_date = user["CreateDate"].strftime("%Y-%m-%d %H:%M:%S")
            console_access = has_console_access(iam, user_name)
            access_key_present = has_access_key(iam, user_name)
            permissions = get_permissions(iam, user_name)
            groups = get_user_groups(iam, user_name)
            tags = get_user_tags(iam, user_name)
            last_activity = get_last_activity(iam, user_name)

            writer.writerow([user_name, groups, arn, console_access, created_date, last_activity, access_key_present, permissions, tags])

    print(f"User list downloaded successfully. Saved as: {csv_file_path}")


#--------------------------------------------------------------------#

def change_user_password():
    iam = boto3.client('iam')
    
    user_name = input("Enter the username for which you want to change the password: ")

    # Check if the user exists
    try:
        response = iam.get_user(UserName=user_name)
        print(f"User {user_name} found. Proceeding with password change.")
    except iam.exceptions.NoSuchEntityException:
        print(f"Error: User '{user_name}' does not exist.")
        return

    # Function to prompt for password and change it
    def prompt_and_change_password():
        retries = 2
        while retries > 0:
            new_password = getpass.getpass("Enter the new password for the user: ")

            try:
                # Check if the user has a login profile
                iam.get_login_profile(UserName=user_name)
                # If the login profile exists, update the password
                iam.update_login_profile(
                    UserName=user_name,
                    Password=new_password,
                    PasswordResetRequired=True
                )
                print(f"Password for user '{user_name}' has been changed successfully.")
                return True
            except iam.exceptions.NoSuchEntityException:
                # If the login profile does not exist, create one
                try:
                    iam.create_login_profile(
                        UserName=user_name,
                        Password=new_password,
                        PasswordResetRequired=True
                    )
                    print(f"Login profile for user '{user_name}' created and password set successfully.")
                    return True
                except iam.exceptions.PasswordPolicyViolationException as e:
                    print(f"Error: {e.response['Error']['Message']}")
                    print("Please try again with a password that meets the policy requirements.")
                    retries -= 1
                    if retries == 0:
                        print("Maximum retry attempts reached. Password change failed.")
                        return False
            except Exception as e:
                print(f"Error changing password for user '{user_name}': {e}")
                return False

    # Attempt to change the password with retries
    success = prompt_and_change_password()
    if not success:
        print("Password change process terminated.")

def user_exists(username):
    # Check if user exists
    try:
        iam = boto3.client('iam')
        iam.get_user(UserName=username)
        return True
    except iam.exceptions.NoSuchEntityException:
        return False

def list_users_in_group(group_name):
    # Create IAM client
    iam = boto3.client('iam')

    try:
        # Get users in the group
        response = iam.get_group(GroupName=group_name)
        users = response['Users']
        
        print(f"Users in group '{group_name}':")
        if users:
            for user in users:
                print("- Username:", user['UserName'])
        else:
            print("No users in this group")
    except iam.exceptions.NoSuchEntityException:
        print(f"Group '{group_name}' does not exist.")

def has_console_access(iam, user_name):
    try:
        iam.get_login_profile(UserName=user_name)
        return "Yes"
    except iam.exceptions.NoSuchEntityException:
        return "No"

def has_access_key(iam, user_name):
    response = iam.list_access_keys(UserName=user_name)
    return "Yes" if response['AccessKeyMetadata'] else "No"

def get_linked_groups(username):
    # Create IAM client
    iam = boto3.client('iam')

    # Initialize an empty list to store linked groups
    linked_groups = []

    try:
        # Get the groups associated with the user
        response = iam.list_groups_for_user(UserName=username)
        if 'Groups' in response:
            for group in response['Groups']:
                linked_groups.append(group['GroupName'])
    except iam.exceptions.NoSuchEntityException:
        # If the user doesn't exist or is not associated with any group, return an empty list
        pass

    return linked_groups

def get_last_activity(iam, user_name):
    try:
        user_details = iam.get_user(UserName=user_name)
        last_activity = user_details['User'].get('PasswordLastUsed')
        if last_activity:
            return last_activity.strftime("%Y-%m-%d %H:%M:%S")
        else:
            return "No activity"
    except Exception as e:
        return f"Error: {e}"


def get_permissions(iam, user_name):
    user_policies = []
    group_policies = []
    
    # User attached policies
    attached_policies = iam.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
    for policy in attached_policies:
        user_policies.append(policy['PolicyName'])
    
    # User inline policies
    inline_policies = iam.list_user_policies(UserName=user_name)['PolicyNames']
    user_policies.extend(inline_policies)
    
    # Group policies
    group_names = get_user_groups(iam, user_name).split(", ")
    for group_name in group_names:
        # Attached group policies
        attached_group_policies = iam.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
        for policy in attached_group_policies:
            group_policies.append(policy['PolicyName'])
        
        # Inline group policies
        inline_group_policies = iam.list_group_policies(GroupName=group_name)['PolicyNames']
        group_policies.extend(inline_group_policies)
    
    return ", ".join(set(user_policies + group_policies))


def get_group_option():
    print("Group options:")
    print("1. Create a new group")
    print("2. Use an existing group")
    choice = input("Enter the number corresponding to your choice: ")
    return choice

def get_console_access_option():
    print("Console access options:")
    print("1. Enable console access as admin")
    print("2. Enable console access as user")
    choice = input("Enter the number corresponding to your choice: ")
    return choice

def get_linking_option():
    print("Linking options:")
    print("1. Link to the newly created group")
    print("2. Add to a custom group")
    choice = input("Enter the number corresponding to your choice: ")
    return choice

