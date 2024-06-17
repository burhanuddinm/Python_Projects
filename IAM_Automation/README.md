**AWS IAM Management Script**

-------------------------------------------------
**GOAL**
-------------------------------------------------
Most AWS learners and Cloud Engineers start their journey with IAM roles, policies, user/group creation, deletion, and more. 
While some choose to perform these tasks via the AWS Management Console, others prefer using the AWS CLI. I chose to create my own Python-based solution to manage AWS IAM tasks seamlessly.

As a tech enthusiast with a passion for problem-solving and task automation, I developed a small Python script to handle various IAM operations. 
This script is designed to simplify IAM management, making it easy to integrate with any of your existing scripting workflows.

-------------------------------------------------
**PROBLEM SOLVED**
-------------------------------------------------
This script addresses the need for an efficient and straightforward way to manage AWS IAM tasks without relying on the AWS Management Console or AWS CLI. 
It provides a user-friendly interface for performing common IAM operations, saving time and reducing the complexity involved in managing IAM roles, policies, users, and groups.

-------------------------------------------------
**FEATURES**
-------------------------------------------------
The script provides the following functionalities:

1. **Create AWS Group:** Easily create new AWS groups and attach policies to them.
2. **Create AWS Account:** Create new IAM users with optional console access and access key, Cloning users with existing users.
3. **List Users, Groups, and Access Keys:** List all users, their associated groups, and access keys to manage your AWS IAM users also have the option of downloading user base data for auditing in CSV format.
4. **Delete User:** Delete IAM users, with the option to unlink or delete their associated groups.
5. **Delete Group:** Remove AWS groups along with their attached policies.
6. **Change User's Group:** Move users between groups.
7. **Change User's Password:** Update the password for IAM users.

-------------------------------------------------
**PRE-REQUISITES**
-------------------------------------------------
To use this script, you need an existing IAM user with an access key and secret key that has permission to create and delete IAM resources.

-------------------------------------------------
**SCRIPT STRUCTURE**
-------------------------------------------------
The repository contains two main files:

- main.py: Contains the main user interactive functions.
- functions.py: Contains all the underlying functions and logic

This separation helps in maintaining the code by keeping the user interaction logic and the IAM operations logic distinct, making it easier for learners and developers to understand and modify the code.

-------------------------------------------------
**INTEGRATIONS**
-------------------------------------------------
This script can be easily integrated into your existing scripting logic, making it the quickest way to manage IAM tasks for large organizations. By automating IAM operations, you can ensure consistency and save time on repetitive tasks.

-------------------------------------------------
**CONCLUSION**
-------------------------------------------------
This AWS IAM Management Script is a powerful tool for anyone looking to simplify their IAM management tasks. Whether you're a learner or a seasoned Cloud Engineer, this script offers an efficient way to handle IAM operations programmatically.

Feel free to explore the code, suggest improvements, and contribute to the repository!

