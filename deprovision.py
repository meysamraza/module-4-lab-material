import boto3
import sys

def deprovision_user(username):
    iam = boto3.client('iam')

    print(f"Deprovisioning {username}...")

    # Delete access keys
    keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
    for key in keys:
        iam.delete_access_key(UserName=username, AccessKeyId=key['AccessKeyId'])
        print(f"Deleted access key {key['AccessKeyId']}")

    # Delete login profile (console password), if exists
    try:
        iam.delete_login_profile(UserName=username)
        print("Deleted console login profile")
    except iam.exceptions.NoSuchEntityException:
        print("No login profile to delete")

    # Detach managed policies
    policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
    for p in policies:
        iam.detach_user_policy(UserName=username, PolicyArn=p['PolicyArn'])
        print(f"Detached policy {p['PolicyName']}")

    # Remove from groups
    groups = iam.list_groups_for_user(UserName=username)['Groups']
    for g in groups:
        iam.remove_user_from_group(GroupName=g['GroupName'], UserName=username)
        print(f"Removed from group {g['GroupName']}")

    # Delete inline policies
    inline = iam.list_user_policies(UserName=username)['PolicyNames']
    for pname in inline:
        iam.delete_user_policy(UserName=username, PolicyName=pname)
        print(f"Deleted inline policy {pname}")

    # Finally delete the user
    iam.delete_user(UserName=username)
    print(f"{username} fully deprovisioned and deleted.")

if __name__ == "__main__":
    deprovision_user(sys.argv[1])
