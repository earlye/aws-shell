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
```

## Usage

```bash
# Configure aws credentials. Skip this if you've done it before.
$ aws configure

# Run aws shell
$ aws-shell
(aws)/: help

Documented commands (type help <topic>):
========================================
delete_stack  exit  help  quit  ssh  stack  stack_resource  stacks  up

# Provide MFA token:
(aws)/: mfa 848034
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

It also supports port forwarding!

```bash
(aws)/stack:{stack}/stack:{substack}/asg:{asg}/: ssh 2 -L 8888:localhost:8888
/usr/bin/ssh {first private ip}
Last login: {sometime} from {somewhere}

       __|  __|_  )
       _|  (     /   Amazon Linux AMI
      ___|\___|___|

https://aws.amazon.com/amazon-linux-ami/2016.09-release-notes/
$ exit
(aws)/stack:{stack}/stack:{substack}/asg:{asg}/: ssh 2 -L 8888 # <-- useful shorthand!
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

## New Features

_Most Recent Last. Doesn't include bug fixes, or any features I forgot
to list. Maybe that last bit was obvious :-D_

* You can now input an MFA token by running `mfa {token}`. It's
rudimentary support at this point, and likely broken if you've
never used [aws-mfa](https://github.com/lonelyplanet/aws-mfa) before.

* You can now ssh with shorthanded port forwarding. Basically, if you
want to forward a port on the remote server via the same local port,
you no longer have to use the `-L {port}:localhost:{port}`
syntax. Instead, just say `-L {port}`. You can still use the server as
a tunnel to yet another server, or choose different local/remote port
numbers with the old syntax though.

* When launching, aws-shell automatically runs "stacks" for you.

* --profile (short: -p) selects a specific AWS profile. This is helpful
when other processes require that your default profile be one other than
the one you would like aws-shell to use.

* aws-shell now knows how to get your aws device info. I also tried to
make it file-compatible with aws-mfa, so you should in theory not need
the separate aws-mfa tool any longer - just use aws-shell to manage your
.aws/{mfa-related-files}, and you should be good to go. Of course, my
wife always says she wants to move to Theory, because everything
works... in Theory.

* --mfa (short: -m) provide your mfa command at launch. If you *know*
your cached mfa credentials are expired, this saves the step of waiting
for aws-shell to get access denied.

* there is now a `profile` command to change profiles after you've 
started aws-shell.

* `stacks` now adds `-e` and `-i` parameters so you can exclude or
include new stack states in the filter.

* `~/.aws-shell.yaml` is the new config file. It has one setting for now,
`profile`. Example:

```
---
profile: {aws profile name}
```

* `ssh` commands now have a `-R`/`--replace-key` option. It is quite
possible in AWS for IP addresses to get recycled, especially if you 
are creating/tearing-down cloudformation stacks while iterating on
their templates. When this happens, you don't want to have to go
hack on `~/.ssh/known_hosts` in order to ssh in to the host. This option
will run the appropriate command (`ssh-keygen -R {host}`) to remove
the entry before running ssh.

* auto-scaling groups now support the `terminateInstance` command.
