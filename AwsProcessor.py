from SilentException import SilentException
from SlashException import SlashException

from AwsConnectionFactory import AwsConnectionFactory
from CommandArgumentParser import *
from stdplus import *
from run_cmd import run_cmd

import cmd
import json
import os
import signal
import sys
import traceback
from botocore.exceptions import ClientError
from pprint import pprint

class AwsProcessor(cmd.Cmd):
    backgroundTasks=[]
    resourceTypeAliases={ 'AWS::AutoScaling::AutoScalingGroup' : 'asg',
                          'AWS::CloudFormation::Stack' : 'stack',
                          'AWS::EC2::NetworkInterface' : 'eni' }
    processorFactory = None
    
    def __init__(self,prompt,parent):
        cmd.Cmd.__init__(self)
        self.raw_prompt = prompt
        self.prompt = prompt + "/: "
        self.parent = parent

    def emptyline(self):
        pass

    @staticmethod
    def killBackgroundTasks():
        for pid in AwsProcessor.backgroundTasks:
            print "Killing pid:{}".format(pid)
            os.kill(pid,signal.SIGQUIT)
    
    def onecmd(self, line):
        try:
            return cmd.Cmd.onecmd(self,line)
        except SystemExit, e:
            raise e;
        except SlashException, e:
            if None == self.parent:
                pass
            else:
                raise e
        except SilentException:
            pass
        except ClientError as e:
            # traceback.print_exc()
            if e.response['Error']['Code'] == 'AccessDenied':
                print "ERROR: Access Denied. Maybe you need to run mfa {code}"
                traceback.print_exc()
        except Exception, other:
            traceback.print_exc()
        except:
            print "Unexpected error:", sys.exc_info()[0]

    def mfa_devices(self, profile='default'):
        list_mfa_devices_command = ["aws","--profile",profile,"--output","json","iam","list-mfa-devices"]
        result = run_cmd(list_mfa_devices_command)
        if result.retCode == 0 :
            return json.loads("\n".join(result.stdout))['MFADevices']
        else:
            raise Exception('There was a problem fetching MFA devices from AWS')
            
    def load_arn_from_aws(self, profile):
        devices = self.mfa_devices(profile)
        if len(devices):
            return devices[0]['SerialNumber']
        else:
            raise Exception('No MFA devices were found for your account')

    def do_mfa(self, args):
        """Enter a 6-digit MFA token. mfa -h for more details"""
        parser = CommandArgumentParser("mfa")
        parser.add_argument(dest='token',help='MFA token value');
        parser.add_argument("-p","--profile",dest='profile',default=AwsConnectionFactory.instance.getProfile(),help='MFA token value');
        args = vars(parser.parse_args(args))

        token = args['token']
        profile = args['profile']
        arn = AwsConnectionFactory.instance.load_arn(profile)

        credentials_command = ["aws","--profile",profile,"--output","json","sts","get-session-token","--serial-number",arn,"--token-code",token]
        output = run_cmd(credentials_command) # Throws on non-zero exit :yey:

        credentials = json.loads("\n".join(output.stdout))['Credentials']
        AwsConnectionFactory.instance.setMfaCredentials(credentials,profile)

    def do_up(self,args):
        """Go up one level"""
        if None == self.parent:
            print "You're at the root. Try 'quit' to quit"
        else:
            return True

    def do_slash(self,args):
        """Go up to root level"""
        if None == self.parent:
            print "You're at the root. Try 'quit' to quit"
        else:
            raise SlashException()

    def do_profile(self,args):
        """Select AWS profile"""
        parser = CommandArgumentParser("profile")
        parser.add_argument(dest="profile",help="Profile name")
        parser.add_argument('-v','--verbose',dest="verbose",action='store_true',help='verbose')
        args = vars(parser.parse_args(args))

        profile = args['profile']
        verbose = args['verbose']
        if verbose:
            print "Selecting profile '{}'".format(profile)
        AwsConnectionFactory.resetInstance(profile=profile)

    def do_quit(self,args):
        """Alias for 'exit'"""
        return self.do_exit(args)
        
    def do_exit(self,args):
        """Exit cf-ui"""
        raise SystemExit

    def stackResource(self,stackName,logicalId):
        print "loading stack resource {}.{}".format(stackName,logicalId)
        stackResource = AwsConnectionFactory.instance.getCfResource().StackResource(stackName,logicalId)
        pprint(stackResource)
        if "AWS::CloudFormation::Stack" == stackResource.resource_type:
            pprint(stackResource)
            print "Found a stack w/ physical id:{}".format(stackResource.physical_resource_id)
            childStack = AwsConnectionFactory.instance.getCfResource().Stack(stackResource.physical_resource_id)
            print "Creating prompt"
            AwsProcessor.processorFactory.Stack(childStack,logicalId,self).cmdloop()
        elif "AWS::AutoScaling::AutoScalingGroup" == stackResource.resource_type:
            scalingGroup = stackResource.physical_resource_id
            AwsProcessor.processorFactory.AutoScalingGroup(scalingGroup,self).cmdloop()
        elif "AWS::EC2::NetworkInterface" == stackResource.resource_type:
            eniId = stackResource.physical_resource_id
            AwsProcessor.processorFactory.Eni(eniId,self).cmdloop()
        else:
            pprint(stackResource)
            print("- description:{}".format(stackResource.description))
            print("- last_updated_timestamp:{}".format(stackResource.last_updated_timestamp))
            print("- logical_resource_id:{}".format(stackResource.logical_resource_id))
            print("- metadata:{}".format(stackResource.metadata.strip()))
            print("- physical_resource_id:{}".format(stackResource.physical_resource_id))
            print("- resource_status:{}".format(stackResource.resource_status))
            print("- resource_status_reason:{}".format(stackResource.resource_status_reason))
            print("- resource_type:{}".format(stackResource.resource_type))
            print("- stack_id:{}".format(stackResource.stack_id))

    def ssh(self,instanceId,interfaceNumber,forwarding,replaceKey,keyscan,background,verbosity=0):
        client = AwsConnectionFactory.getEc2Client()
        response = client.describe_instances(InstanceIds=[instanceId])
        networkInterfaces = response['Reservations'][0]['Instances'][0]['NetworkInterfaces'];
        if None == interfaceNumber:
            number = 0
            for interface in networkInterfaces:
                print "{0:3d} {1}".format(number,interface['PrivateIpAddress'])
                number += 1
        else:
            address = "{}".format(networkInterfaces[interfaceNumber]['PrivateIpAddress'])
            if replaceKey or keyscan:
                args=["/usr/bin/ssh-keygen","-R",address]
                print " ".join(args)
                os.waitpid(fexecvp(args),0)

            if keyscan:
                # Have to read ~/.ssh/config to see if there's a proxy command :/                
                config = readSshConfig()
                
            args=["/usr/bin/ssh",address]
            if not forwarding == None:
                for forwardInfo in forwarding:
                    if isInt(forwardInfo):
                        forwardInfo = "{0}:localhost:{0}".format(forwardInfo)
                    args.extend(["-L",forwardInfo])
                if background:
                    args.extend(["-N","-n"])
            else:
                background = False # Background is ignored if not forwarding

            if verbosity > 0:
                args.append("-" + "v" * verbosity)
                
            print " ".join(args)
            pid = fexecvp(args)
            if background:
                print "SSH Started in background. pid:{}".format(pid)
                AwsProcessor.backgroundTasks.append(pid)
            else:
                os.waitpid(pid,0)

    def do_ssh(self,args):
        """SSH to an instance. ssh -h for detailed help."""
        parser = CommandArgumentParser()
        parser.add_argument(dest='instance-id',help='instance id of the instance to ssh to')
        parser.add_argument('-a','--interface-number',dest='interface-number',default='0',help='instance id of the instance to ssh to')
        parser.add_argument('-L',dest='forwarding',nargs='*',help="port forwarding string: {localport}:{host-visible-to-instance}:{remoteport} or {port}")
        parser.add_argument('-R','--replace-key',dest='replaceKey',default=False,action='store_true',help="Replace the host's key. This is useful when AWS recycles an IP address you've seen before.")
        parser.add_argument('-Y','--keyscan',dest='keyscan',default=False,action='store_true',help="Perform a keyscan to avoid having to say 'yes' for a new host. Implies -R.")
        parser.add_argument('-B','--background',dest='background',default=False,action='store_true',help="Run in the background. (e.g., forward an ssh session and then do other stuff in aws-shell).")
        parser.add_argument('-v',dest='verbosity',default=0,action=VAction,nargs='?',help='Verbosity. The more instances, the more verbose');
        args = vars(parser.parse_args(args))

        instanceId = args['instance-id']
        interfaceNumber = int(args['interface-number'])
        forwarding = args['forwarding']
        replaceKey = args['replaceKey']
        keyscan = args['keyscan']
        background = args['background']
        verbosity = args['verbosity']
        self.ssh(instanceId,interfaceNumber, forwarding, replaceKey, keyscan, background, verbosity)

