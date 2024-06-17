from functions import *
import signal

def main():
    pass

def sigint_handler(signal, frame):
    clear_credentials_file(credentials_path)
    print("Exiting script due to SIGINT (Ctrl+C).")
    exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, sigint_handler)
    # Main function
    # credentials_path = input("Enter the path to store your AWS credentials file: ")
    credentials_path = os.environ.get("AWS_CONFIG_FILE")
    while not credentials_path:
        # Prompt the user to enter the path to store the AWS credentials file
        credentials_path = input("Enter the path to store your AWS credentials file: ").strip()
        if not credentials_path:
            print("Path cannot be kept as empty/invalid.")
        else:
            os.environ["AWS_CONFIG_FILE"] = credentials_path
    
    iam = create_iam_client(credentials_path)
    if iam:
        while True:
            print("Options:")
            print("1. Create AWS group")
            print("2. Create AWS account")
            print("3. List users, their associated groups, and access keys")
            print("4. Delete user")
            print("5. Delete group")
            print("6. Change user's group")
            print("7. Change user's password")
            print("8. Exit")
            choice = input("Enter the number corresponding to your choice: ")

            if choice == "1":
                # Group creation
                group_name = input("Enter group name: ")
                if not group_name.strip():
                    print("Invalid input. Group name cannot be empty.")
                    continue
                policy_arn = input("Enter policy ARN to attach to the group: ")
                group = create_aws_group(group_name, policy_arn)
                if group:
                    print("Policy attached to group:", group_name)
                else:
                    print("Group creation failed. Please try again with a unique group name.")
            elif choice == "2":
                # AWS Account creation
                while True:
                    print("\nCreate User Menu:")
                    print("1. Create a New user")
                    print("2. Clone an existing user")
                    user_creation_choice = input("Enter your choice (1/2/): ").strip()
                    if user_creation_choice == "1":
                        while True:
                            username = input("Enter username: ")
                            if not username.strip():
                                print("Invalid input. Username cannot be empty.")
                                continue
                            if not user_exists(username):
                                break
                            else:
                                print("User already exists. Please enter a unique username.")
                        
                        enable_console_access = input("Enable console access? (yes/no): ").lower() == "yes"
                        if enable_console_access:
                            console_access_choice = get_console_access_option()
                            if console_access_choice == "1":
                                user_type = "admin"
                            elif console_access_choice == "2":
                                user_type = "user"
                            else:
                                print("Invalid choice. Defaulting to user.")
                                user_type = "user"
                        password = create_password()
                        user = create_aws_user(username)
                        print("User created:", user['UserName'])
                        create_login_profile_for_user(username, password)
                        
                        create_access_key_option = input("Do you want to create access key for this user? (yes/no): ").lower()
                        if create_access_key_option == "yes":
                            create_access_key(username, os.path.dirname(credentials_path))

                        while True:
                            link_to_group_option = input("Do you want to add the user to an existing group? (yes/no): ").lower()
                            if link_to_group_option == "yes":
                                print("Existing groups:")
                                list_all_groups_and_users()
                                group_name = input("Enter the name of the group to link to: ")
                                if group_name.strip():
                                    if group_exists(group_name):
                                        link_user_to_group(username, group_name)
                                        print("User linked to the group.")
                                        break
                                    else:
                                        print("Group does not exist.")
                                else:
                                    print("Invalid input. Group name cannot be empty.")
                            elif link_to_group_option == "no":
                                create_group_option = input("Do you want to create a new group? (yes/no): ").lower()
                                if create_group_option == "yes":
                                    while True:
                                        group_name = input("Enter group name: ")
                                        if group_name.strip():
                                            if group_exists(group_name):
                                                print("Group already exists. Please select a unique group name.")
                                            else:
                                                policy_arn = input("Enter policy ARN to attach to the group: ")
                                                group = create_aws_group(group_name, policy_arn)
                                                if group:
                                                    print("Policy attached to group:", group_name)
                                                    link_user_to_group(username, group_name)
                                                    print("User linked to the newly created group.")
                                                    break
                                                else:
                                                    print("Group creation failed. Please try again with a unique group name.")
                                        else:
                                            print("Invalid input. Group name cannot be empty.")
                                elif create_group_option == "no":
                                    print("Error: User must be associated with a group. Please add user to a group to proceed further.")
                                    delete_user(username)
                                    print("User creation cancelled.")
                                else:
                                    print("Invalid input.")
                                break
                            else:
                                print("Invalid option.")
                        break
                    
                    elif user_creation_choice == "2":
                        new_username = input("Enter the new username: ")
                        if not new_username.strip():
                            print("Invalid input. Username cannot be empty.")
                            continue
                        if user_exists(new_username):
                            print("User already exists. Please enter a unique username.")
                            continue
                        
                        print("Existing users:")
                        list_users_groups_and_access_keys()
                        reference_user = input("Enter the username to clone: ")
                        if not reference_user.strip() or not user_exists(reference_user):
                            print("Invalid input. Reference user does not exist.")
                            continue
                        
                        clone_user(reference_user, new_username, credentials_path)
                        break
                    
            elif choice == "3":
                # List users, their associated groups, and access keys
                users_data = list_user_and_group_options()
                # export_to_csv = input("Do you want to export the data to a CSV file? (yes/no): ").lower()
                # if export_to_csv == "yes":
                #     # Call export_active_users_to_csv function with users_data
                #     export_active_users_to_csv("user_data", users_data)
                # elif export_to_csv == "no":
                #     pass
                # else:
                #     print("Invalid input. Please enter 'yes' or 'no'.")
            elif choice == "4":
                # Delete user
                print("Existing users and associated groups:")
                list_users_and_groups()
                username = input("Enter the name of the user to delete: ")
                if username.strip():
                    # Check if the user is linked to a group
                    linked_group = get_linked_groups(username)
                    if linked_group:
                        # Ask for confirmation to delete user and associated group
                        confirmation = input("Please confirm if you need to delete the user and group associated with this user or just user ? yes(group-delete)/no(only-user-delete): ").lower()
                        if confirmation == "yes":
                            delete_access_keys(username)
                            for group_name in linked_group:
                            # Detach policies from the group
                                detach_policies_from_group(group_name)
                            # Delete user and its associated group
                            for group_name in linked_group:
                                delete_group_and_users(group_name)
                                delete_login_profile(username)
                            # print("User and associated group deleted.")
                                delete_user(username)
                                print("User and associated group both deleted.")
                        elif confirmation == "no":
                            delete_access_keys(username)
                            for group_name in linked_group:
                            # Unlink user from its associated group
                                unlink_user_from_group(username, group_name)
                            print("User unlinked from associated group.")
                            delete_login_profile(username)
                            delete_user(username)
                        else:
                            print("Invalid input. Please enter 'yes' or 'no'.")
                    else:
                        delete_login_profile(username)
                        delete_user(username)
                else:
                    print("Invalid input. Username cannot be empty.")
            elif choice == "5":
                # Delete group
                print("Existing groups:")
                list_all_groups_and_users()
                group_name = input("Enter the name of the group to delete: ")
                if group_name.strip():
                    # List users in the group
                    list_users_in_group(group_name)
                    # Ask for confirmation to delete the group and its associated users
                    confirmation = input("Please confirm if you want to delete the group and its associated users (yes/no): ").lower()
                    if confirmation == "yes":
                        # Detach policies from the group
                        detach_policies_from_group(group_name)
                        # Delete the group and its associated users
                        delete_group_and_users(group_name)
                    elif confirmation == "no":
                        print("Deletion cancelled.")
                    else:
                        print("Invalid input. Please enter 'yes' or 'no'.")
                else:
                    print("Invalid input. Group name cannot be empty.")
            elif choice == "6":
                # Print list of users and their groups
                print("Existing users and groups associated:")
                list_users_groups_and_access_keys()
                
                # Change user's group
                print("Change user's group:")
                username = input("Enter the username: ")
                
                if username.strip():
                    if user_exists(username):
                        # Check if the user is currently linked to a group
                        current_groups = get_linked_groups(username)
                        if current_groups:
                            print(f"User '{username}' is currently linked to the following groups:")
                            for group in current_groups:
                                print(f"- {group}")
                            
                            # Prompt user to unlink from all groups
                            unlink_all = input("Do you want to unlink from all groups? (yes/no): ").lower()
                            if unlink_all == "yes":
                                # Unlink user from all groups
                                for group in current_groups:
                                    unlink_user_from_group(username, group)
                                print(f"User '{username}' unlinked from all groups.")
                                
                                # Prompt user to link a new group
                                # List active groups
                                print("Existing groups:")
                                list_all_groups_and_users()
                                # Prompt user to choose a new group
                                new_group_name = input("Enter the name of the new group to link to: ")
                                if new_group_name.strip():
                                    if group_exists(new_group_name):
                                        # Link user to the new group
                                        link_user_to_group(username, new_group_name)
                                        print(f"User '{username}' linked to group '{new_group_name}'.")
                                    else:
                                        print("Group does not exist.")
                                else:
                                    print("Invalid input. Group name cannot be empty.")
                                
                            elif unlink_all == "no":
                                # Prompt user to link the new group along with the existing ones
                                link_both_groups = input("Do you want to link the new group along with the existing ones? (yes/no): ").lower()
                                if link_both_groups == "yes":
                                    # List active groups
                                    print("Existing groups:")
                                    list_all_groups_and_users()
                                    # Prompt user to choose the new group
                                    new_group_name = input("Enter the name of the new group to link to: ")
                                    if new_group_name.strip():
                                        if group_exists(new_group_name):
                                            # Link user to the new group
                                            link_user_to_group(username, new_group_name)
                                            print(f"User '{username}' linked to group '{new_group_name}' along with the existing groups.")
                                        else:
                                            print("Group does not exist.")
                                elif link_both_groups == "no":
                                    # Skip linking new group
                                    pass
                                else:
                                    print("Invalid input. Please enter 'yes' or 'no'.")
                        else:
                            print(f"User '{username}' is not currently linked to any group.")
                            
                            # List active groups
                            print("Existing groups:")
                            list_users_groups_and_access_keys()
                            
                            # Prompt user to choose a new group
                            new_group_name = input("Enter the name of the new group to link to: ")
                            if new_group_name.strip():
                                if group_exists(new_group_name):
                                    # Link user to the new group
                                    link_user_to_group(username, new_group_name)
                                    print(f"User '{username}' linked to group '{new_group_name}'.")
                                else:
                                    print("Group does not exist.")
                            else:
                                print("Invalid input. Group name cannot be empty.")
                    else:
                        print(f"User '{username}' does not exist.")
                else:
                    print("Invalid input. Username cannot be empty.")
            elif choice == "7":
                print("Existing users:")
                list_users_groups_and_access_keys()                
                change_user_password()
            elif choice == "8":
                # Exit
                clear_credentials_file(credentials_path)
                print("Exiting program.")
                break
            else:
                print("Invalid choice. Please select a valid option.")
            print("\nAfter script:")
            print("1. View all options")
            print("2. Exit")
            next_action = input("Enter the number corresponding to your choice: ")
            if next_action == "2":
                print("Exiting program.")
                clear_credentials_file(credentials_path)
                break
