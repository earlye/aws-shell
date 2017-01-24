# aws-shell: a shell for aws.

## Installation

```bash
pip install future
pip install boto3
git clone {url}
cd aws-shell
ln -s $(pwd)/aws-shell {some directory on your path}
gem install aws-mfa ## <-- if you use MFA for AWS
```

## Usage

```bash
# Configure aws credentials. Skip this if you've done it before.
$ aws configure

# Authenticate MFA. Skip this if you've done it recently or aren't using FMA
$ aws-mfa
Enter the 6-digit code from your MFA device:
{6-digit code}
$ eval $(aws-mfa)

# Run aws shell
$ aws-shell
(aws)/: help

Documented commands (type help <topic>):
========================================
delete_stack  exit  help  quit  ssh  stack  stack_resource  stacks  up
```
