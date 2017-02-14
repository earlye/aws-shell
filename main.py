#!/usr/local/bin/python

import argparse
import atexit
import boto3
import cmd
import json
import os
import readline
import shlex
import subprocess
import sys
import traceback

from AwsConnectionFactory import AwsConnectionFactory

from botocore.exceptions import ClientError
from run_cmd import run_cmd
from pprint import pprint
from stdplus import *

awsConnectionFactory = None

stackStatusFilter=['CREATE_COMPLETE','CREATE_FAILED','CREATE_IN_PROGRESS','ROLLBACK_IN_PROGRESS','ROLLBACK_COMPLETE']

resourceTypeAliases={ 'AWS::AutoScaling::AutoScalingGroup' : 'asg',
                      'AWS::CloudFormation::Stack' : 'stack' }

mappedKeys = { 'SecretAccessKey' : 'AWS_SECRET_ACCESS_KEY', 'SessionToken': 'AWS_SECURITY_TOKEN', 'AccessKeyId' : 'AWS_ACCESS_KEY_ID' }


class SilentException(Exception):
    def __init__(self):
        Exception.__init__(self)

class SlashException(Exception):
    def __init__(self):
        Exception.__init__(self)
        
class CommandArgumentParser(argparse.ArgumentParser):
    def __init__(self,command = None):
        argparse.ArgumentParser.__init__(self, prog=command)
        
    def exit(self, status=0, message=None):
        if None == message:
            raise SilentException
        else:
            raise Exception(message)

    def error(self, message):
        raise Exception(message)

class AwsProcessor(cmd.Cmd):
    def __init__(self,prompt,parent):
        cmd.Cmd.__init__(self)
        self.raw_prompt = prompt
        self.prompt = prompt + "/: "
        self.parent = parent

    def emptyline(self):
        pass

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
        parser.add_argument("-p","--profile",dest='profile',default=awsConnectionFactory.getProfile(),help='MFA token value');
        args = vars(parser.parse_args(shlex.split(args)))

        token = args['token']
        profile = args['profile']
        arn = awsConnectionFactory.load_arn(profile)

        credentials_command = ["aws","--profile",profile,"--output","json","sts","get-session-token","--serial-number",arn,"--token-code",token]
        output = run_cmd(credentials_command) # Throws on non-zero exit :yey:

        credentials = json.loads("\n".join(output.stdout))['Credentials']
        awsConnectionFactory.setMfaCredentials(credentials,profile)

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
            raise SlashException

    def do_profile(self,args):
        """Select AWS profile"""
        parser = CommandArgumentParser("profile")
        parser.add_argument(dest="profile",help="Profile name");
        args = vars(parser.parse_args(shlex.split(args)))

        profile = args['profile']
        global awsConnectionFactory
        awsConnectionFactory = AwsConnectionFactory(profile=profile)

    def do_quit(self,args):
        """Alias for 'exit'"""
        return self.do_exit(args)
        
    def do_exit(self,args):
        """Exit cf-ui"""
        raise SystemExit

    def stackResource(self,stackName,logicalId):
        print "loading stack resource {}.{}".format(stackName,logicalId)
        stackResource = awsConnectionFactory.getCfResource().StackResource(stackName,logicalId)
        pprint(stackResource)
        if "AWS::CloudFormation::Stack" == stackResource.resource_type:
            pprint(stackResource)
            print "Found a stack w/ physical id:{}".format(stackResource.physical_resource_id)
            childStack = awsConnectionFactory.getCfResource().Stack(stackResource.physical_resource_id)
            print "Creating prompt"
            AwsStack(childStack,logicalId,self).cmdloop()
        elif "AWS::AutoScaling::AutoScalingGroup" == stackResource.resource_type:
            scalingGroup = stackResource.physical_resource_id
            AwsAutoScalingGroup(scalingGroup,self).cmdloop()
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

    def ssh(self,instanceId,interfaceNumber,forwarding):
        client = awsConnectionFactory.getEc2Client()
        response = client.describe_instances(InstanceIds=[instanceId])
        networkInterfaces = response['Reservations'][0]['Instances'][0]['NetworkInterfaces'];
        if None == interfaceNumber:
            number = 0
            for interface in networkInterfaces:
                print "{0:3d} {1}".format(number,interface['PrivateIpAddress'])
                number += 1
        else:
            address = "{}".format(networkInterfaces[interfaceNumber]['PrivateIpAddress'])
            args=["/usr/bin/ssh",address]
            if not forwarding == None:                
                for forwardInfo in forwarding:
                    if isInt(forwardInfo):
                        forwardInfo = "{0}:localhost:{0}".format(forwardInfo)
                    args.extend(["-L",forwardInfo])
            print " ".join(args)
            pid = os.fork()
            if pid == 0:
                os.execvp(args[0],args)
                sys.exit(0)
            else:
                os.waitpid(pid,0)
            
    def do_ssh(self,args):
        """SSH to an instance. ssh -h for detailed help."""
        parser = CommandArgumentParser()
        parser.add_argument(dest='instance-id',help='instance id of the instance to ssh to')
        parser.add_argument('-a','--interface-number',dest='interface-number',default='0',help='instance id of the instance to ssh to')
        parser.add_argument('-L',dest='forwarding',nargs='*',help="port forwarding string: {localport}:{host-visible-to-instance}:{remoteport} or {port}")
        args = vars(parser.parse_args(shlex.split(args)))

        instanceId = args['instance-id']
        interfaceNumber = int(args['interface-number'])
        forwarding = args['forwarding']
        self.ssh(instanceId,interfaceNumber, forwarding)

class AwsAutoScalingGroup(AwsProcessor):
    def __init__(self,scalingGroup,parent):
        AwsProcessor.__init__(self,parent.raw_prompt + "/asg:" + scalingGroup,parent)
        self.client = awsConnectionFactory.getAsgClient()
        self.scalingGroup = scalingGroup
        self.scalingGroupDescription = self.client.describe_auto_scaling_groups(AutoScalingGroupNames=[self.scalingGroup])
        self.do_printInstances('')
        
    def do_printInstances(self,args):
        """Print the list of instances in this auto scaling group. printInstances -h for detailed help"""
        parser = CommandArgumentParser("stack")
        parser.add_argument('-a','--addresses',action='store_true',dest='addresses',help='list all ip addresses');
        args = vars(parser.parse_args(shlex.split(args)))

        client = boto3.client('ec2')
        
        print "AutoScaling Group:{}".format(self.scalingGroup)
        print "=== Instances ==="
        instances = self.scalingGroupDescription['AutoScalingGroups'][0]['Instances']

        index = 0
        for instance in instances:
            print "* {0:3d} {1} {2} {3}".format(index,instance['HealthStatus'],instance['AvailabilityZone'],instance['InstanceId'])
            if args['addresses']:
                response = client.describe_instances(InstanceIds=[instance['InstanceId']])
                networkInterfaces = response['Reservations'][0]['Instances'][0]['NetworkInterfaces']
                number = 0
                print "  Network Interfaces:"
                for interface in networkInterfaces:
                    print "    * {0:3d} {1}".format(number, interface['PrivateIpAddress'])
                    number +=1                
            index += 1

    def do_ssh(self,args):
        """SSH to an instance. ssh -h for detailed help"""
        parser = CommandArgumentParser("ssh")
        parser.add_argument(dest='instance',help='instance index or name');
        parser.add_argument('-a','--address-number',default='0',dest='interface-number',help='instance id of the instance to ssh to');
        parser.add_argument('-L',dest='forwarding',nargs='*',help="port forwarding string of the form: {localport}:{host-visible-to-instance}:{remoteport} or {port}")
        args = vars(parser.parse_args(shlex.split(args)))

        interfaceNumber = int(args['interface-number'])
        forwarding = args['forwarding']                            
        try:
            index = int(args['instance'])
            instances = self.scalingGroupDescription['AutoScalingGroups'][0]['Instances']
            instance = instances[index]
            self.ssh(instance['InstanceId'],interfaceNumber,forwarding)
        except ValueError:
            self.ssh(args['instance'],interfaceNumber,forwarding)

        
        
class AwsStack(AwsProcessor):
    def __init__(self,stack,logicalName,parent):
        """Construct an AwsStack command processor"""
        AwsProcessor.__init__(self,parent.raw_prompt + "/stack:" + logicalName,parent)
        self.wrappedStack = self.wrapStack(stack)
        self.printStack(self.wrappedStack)

    def wrapStack(self,stack):
        result = {};
        result['rawStack'] = stack;

        resourcesByType = {};
        for resource in stack.resource_summaries.all():
            if not resource.resource_type in resourcesByType:
                resourcesByType[resource.resource_type] = {}
            resourcesByType[resource.resource_type][resource.logical_id] = resource;
        result['resourcesByTypeName'] = resourcesByType;

        resourcesByTypeIndex = {};
        for resourceType, resources in resourcesByType.items():
            resourcesByTypeIndex[resourceType] = {};
            index = 0
            for name,resource in resources.items():
                resourcesByTypeIndex[resourceType][index] = resource
                index += 1
        result['resourcesByTypeIndex'] = resourcesByTypeIndex;
        return result
        
    def printStack(self,wrappedStack,include=None):
        """Prints the stack"""
        rawStack = wrappedStack['rawStack']
        print "==== Stack {} ====".format(rawStack.name)
        # pprint(wrappedStack)
        print "Status: {} {}".format(rawStack.stack_status,defaultify(rawStack.stack_status_reason,''))

        if None == include or 'events' in include:
            print "== events:"
            count = 0
            for event in wrappedStack['rawStack'].events.all():
                pprint( event )
                count += 1
                if count > 5:
                    break;

        for resourceType, resources in wrappedStack['resourcesByTypeIndex'].items():
            if resourceType in resourceTypeAliases:
                resourceType = resourceTypeAliases[resourceType];
            if None == include or resourceType in include:
                print "== {}:".format(resourceType) 
                for index, resource in resources.items():
                    print "    {0:3d}: {1:30} {2:20} {3}".format(index,resource.logical_id,resource.resource_status,defaultify(resource.resource_status_reason,''))

    def do_browse(self,args):
        """Open the current stack in a browser."""
        rawStack = self.wrappedStack['rawStack']
        os.system("open -a \"Google Chrome\" https://us-west-2.console.aws.amazon.com/cloudformation/home?region=us-west-2#/stack/detail?stackId={}".format(rawStack.stack_id))
                
    def do_refresh(self,args):
        """Refresh view of the current stack. refresh -h for detailed help"""
        self.wrappedStack = self.wrapStack(awsConnectionFactory.getCfResource().Stack(self.wrappedStack['rawStack'].name))
        
    def do_print(self,args):
        """Print the current stack. print -h for detailed help"""
        parser = CommandArgumentParser("print")
        parser.add_argument('-r','--refresh',dest='refresh',action='store_true',help='refresh view of the current stack')
        parser.add_argument('-i','--include',dest='include',default=None,nargs='+',help='resource types to include')
        args = vars(parser.parse_args(shlex.split(args)))

        if args['refresh']:
            self.do_refresh('')

        self.printStack(self.wrappedStack,args['include'])
        
    def do_resource(self,args):
        """Go to the specified resource. resource -h for detailed help"""
        parser = CommandArgumentParser("resource")
        parser.add_argument('-i','--logical-id',dest='logical-id',help='logical id of the child resource');
        args = vars(parser.parse_args(shlex.split(args)))

        stackName = self.wrappedStack['rawStack'].name
        logicalId = args['logical-id']
        self.stackResource(stackName,logicalId)

    def do_asg(self,args):
        """Go to the specified auto scaling group. asg -h for detailed help"""
        parser = CommandArgumentParser("asg")
        parser.add_argument(dest='asg',help='asg index or name');
        args = vars(parser.parse_args(shlex.split(args)))

        print "loading auto scaling group {}".format(args['asg'])
        try:
            index = int(args['asg'])
            asgSummary = self.wrappedStack['resourcesByTypeIndex']['AWS::AutoScaling::AutoScalingGroup'][index]
        except:
            asgSummary = self.wrappedStack['resourcesByTypeName']['AWS::AutoScaling::AutoScalingGroup'][args['asg']]

        self.stackResource(asgSummary.stack_name,asgSummary.logical_id)

    def do_stack(self,args):
        """Go to the specified stack. stack -h for detailed help."""
        parser = CommandArgumentParser("stack")
        parser.add_argument(dest='stack',help='stack index or name');
        args = vars(parser.parse_args(shlex.split(args)))

        print "loading stack {}".format(args['stack'])
        try:
            index = int(args['stack'])            
            stackSummary = self.wrappedStack['resourcesByTypeIndex']['AWS::CloudFormation::Stack'][index]
        except ValueError:
            stackSummary = self.wrappedStack['resourcesByTypeName']['AWS::CloudFormation::Stack'][args['stack']]

        self.stackResource(stackSummary.stack_name,stackSummary.logical_id)

    def do_stacks(self,args):
        self.do_print('-r --include stack')

class AwsRoot(AwsProcessor):
    def __init__(self):
        AwsProcessor.__init__(self,"(aws)",None)
        self.stackList = None;

    def do_stack(self,args):
        """Go to the specified stack. stack -h for detailed help"""
        parser = CommandArgumentParser("stack")
        parser.add_argument(dest='stack',help='stack index or name');
        args = vars(parser.parse_args(shlex.split(args)))

        try:
            index = int(args['stack'])
            if self.stackList == None:
                self.do_stacks('-s')
            stack = awsConnectionFactory.getCfResource().Stack(self.stackList[index]['StackName'])
        except ValueError:
            stack = awsConnectionFactory.getCfResource().Stack(args['stack'])

        AwsStack(stack,stack.name,self).cmdloop()    

    def do_delete_stack(self,args):
        """Delete specified stack. delete_stack -h for detailed help."""
        parser = CommandArgumentParser("delete_stack")
        parser.add_argument(dest='stack',help='stack index or name');
        args = vars(parser.parse_args(shlex.split(args)))

        try:
            index = int(args['stack'])
            if self.stackList == None:
                self.do_stacks('-s')
            stack = awsConnectionFactory.getCfResource().Stack(self.stackList[index]['StackName'])
        except ValueError:
            stack = awsConnectionFactory.getCfResource().Stack(args['stack'])

        print "Here are the details of the stack you are about to delete:"
        print "Stack.name: {}".format(stack.name)
        print "Stack.stack_id: {}".format(stack.stack_id)
        print "Stack.creation_time: {}".format(stack.creation_time)
        confirmation = raw_input("If you are sure, enter the Stack.name here: ")
        if stack.name == confirmation:
            stack.delete()
        

    def do_stacks(self,args):
        """List available stacks. stacks -h for detailed help."""
        parser = CommandArgumentParser()
        parser.add_argument('-s','--silent',dest='silent',action='store_true',help='Run silently');
        parser.add_argument('-i','--include',nargs='*',dest='includes',default=[],help='Add statuses');
        parser.add_argument('-e','--exclude',nargs='*',dest='excludes',default=[],help='Remove statuses');
        args = vars(parser.parse_args(shlex.split(args)))

        nextToken = None

        includes = args['includes']
        excludes = args['excludes']

        global stackStatusFilter
        for i in includes:            
            if not i in stackStatusFilter:
                stackStatusFilter.append(i)
        for e in excludes:
            stackStatusFilter.remove(e)

        complete = False;
        stackSummaries = []
        while not complete:
            if None == nextToken:
                stacks = awsConnectionFactory.getCfClient().list_stacks(StackStatusFilter=stackStatusFilter)
            else:
                stacks = awsConnectionFactory.getCfClient().list_stacks(NextToken=nextToken,StackStatusFilter=stackStatusFilter)
                #pprint(stacks)
            if not 'NextToken' in stacks:
                complete = True;
            else:
                nextToken = stacks['NextToken']

            if 'StackSummaries' in stacks:
                stackSummaries.extend(stacks['StackSummaries'])

        stackSummaries = sorted(stackSummaries, key= lambda entry: entry['StackName'])
        index = 0;
        stackSummariesByIndex = {}
        for summary in stackSummaries:
            summary['Index'] = index
            stackSummariesByIndex[index] = summary
            index += 1

        self.stackList = stackSummariesByIndex
        if not args['silent']:
            for index,summary in stackSummariesByIndex.items():
                print '{0:3d}: {2:20} {1:40} {3}'.format(summary['Index'],summary['StackName'],summary['StackStatus'],defaultifyDict(summary,'StackStatusReason',''))
        
    def do_stack_resource(self, args):
        """Use specified stack resource. stack_resource -h for detailed help."""
        parser = CommandArgumentParser()
        parser.add_argument('-s','--stack-name',dest='stack-name',help='name of the stack resource');
        parser.add_argument('-i','--logical-id',dest='logical-id',help='logical id of the child resource');
        args = vars(parser.parse_args(shlex.split(args)))

        stackName = args['stack-name']
        logicalId = args['logical-id']

        self.stackResource(stackName,logicalId)

def main(argv):
    parser = CommandArgumentParser()
    parser.add_argument('-p','--profile',dest='profile',default='default',help='select aws profile');
    parser.add_argument('-m','--mfa',dest='mfa',help='provide mfa code');
    args = vars(parser.parse_args(argv))
    
    histfile = os.path.join(os.path.expanduser("~"), ".aws_hist")
    try:
        readline.read_history_file(histfile)
        readline.set_history_length(1000)
    except IOError:
        pass
    atexit.register(readline.write_history_file, histfile)

    global awsConnectionFactory
    command_prompt = AwsRoot()
    command_prompt.onecmd("profile {}".format(args['profile']))
    if None != args['mfa']:
        command_prompt.onecmd("mfa {}".format(args['mfa']))
    command_prompt.onecmd("stacks")
    command_prompt.cmdloop()

if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except SilentException:
        pass
