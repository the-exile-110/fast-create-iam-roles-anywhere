# Quick IAM Roles Generation Script

A script for quickly generating IAM roles with specified attributes.

# Prerequisites:

- jq must be installed
- [cfssl](https://github.com/cloudflare/cfssl) must be installed
- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) must be installed
- [aws_signing_helper](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html) must be
  installed

# Usage

### Run the script

```shell
./create_iam_roles_anywhere
```

Follow the prompt and enter the required information.

# Explanation

The script will prompt the user to enter the following information:

- Hostname
- Country
- State
- Locality
- Organization
- OrganizationalUnit

It will then create a ca.json file with the entered information and generate the IAM roles. The generated IAM role will
be outputted in JSON format.