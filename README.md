# aws-shell: a shell for aws.

## Overview

I wasn't happy with the AWS web console, because the UI felt
disjointed and was slow to navigate. So I slapped this together:
a very simple interactive cli shell in python.

I'm actively using it for work, so it supports the things that
I'm doing, rather than being an exhaustive system. I invite
pull requests for missing features, bugfixes, etc.

## WARNINGS

This tool is incredibly immature. It WILL be changing considerably as
long as I'm using it, because I will be viewing the things it does (or
doesn't do), and the manner in which it does (or doesn't do) them as
impediments to my workflow.

It is not even "alpha" level code yet, so expect things to be broken
or buggy. Also expect syntax to be in a fairly constant state of flux.

## Installation

```bash
pip install future
pip install boto3
git clone git@github.com:earlye/aws-shell.git
cd aws-shell
ln -s $(pwd)/aws-shell {some directory on your $PATH}
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

## SSH support

If you've set up your `~/.ssh/config` so that using ssh to connect via an instance's IP
address will "just work," then this is probably the best part of `aws-shell`.

aws-shell can ssh to an instance without you having to figure out its
ip, modify /etc/host, or know anything other than its aws instance id:

```bash
(aws)/: ssh {instance-id}
/usr/bin/ssh {first private ip}
Last login: {sometime} from {somewhere}

       __|  __|_  )
       _|  (     /   Amazon Linux AMI
      ___|\___|___|

https://aws.amazon.com/amazon-linux-ami/2016.09-release-notes/
```

If you've navigated to an autoscaling group, you don't even need to
know the instance id. You can ssh by the instance's index in the
autoscaling group's list of instances:

```bash
(aws)/stack:{stack}/stack:{substack}/: asg 0
loading auto scaling group 0
loading stack resource arn:{arn}
AutoScaling Group:{name}
=== Instances ===
  0 Healthy az-2a {instance-id}
  1 Healthy az-2b {instance-id}
  2 Healthy az-2c {instance-id}
(aws)/stack:{stack}/stack:{substack}/asg:{asg}/: ssh 2
/usr/bin/ssh {first private ip}
Last login: {sometime} from {somewhere}

       __|  __|_  )
       _|  (     /   Amazon Linux AMI
      ___|\___|___|

https://aws.amazon.com/amazon-linux-ami/2016.09-release-notes/
```

So how do you set up your `~/.ssh/config` for this? I don't really
profess to be an expert, but here's the magic from mine, modified
to protect my account, of course:

```
Host 192.168.* ### Not the actual subnet, obviously - adjust to match your subnet
     User {host-user}
     IdentityFile {bastion-identity-path}
     ProxyCommand ssh -i {host-identity-path} -W %h:%p {bastion-user}@{bastion-host-ip-or-name}
```

Obviously, `{host-user}`, `{bastion-identity-path}`,
`{host-identity-path}`, `{bastion-user}`, and
`{bastion-host-ip-or-name}` will all vary for your AWS setup. I may
have `{bastion-identity-path}` and `{host-identity-path}`
swapped. Like I said, not an expert on ssh proxying.

