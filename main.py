#!/usr/local/bin/python

import argparse
import atexit
import boto3
import cmd
import os
import readline
import shlex
import sys

from pprint import pprint

cfResource = boto3.resource('cloudformation')
cfClient = boto3.client('cloudformation')
stackStatusFilter=['CREATE_COMPLETE','CREATE_IN_PROGRESS']

resourceTypeAliases={ 'AWS::AutoScaling::AutoScalingGroup' : 'asg',
                      'AWS::CloudFormation::Stack' : 'stack' }

class SilentException(Exception):
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

    def onecmd(self, line):
        try:
            return cmd.Cmd.onecmd(self,line)
        except SystemExit, e:
            raise e;
        except SilentException:
            pass
        except Exception, other:
            print "ERROR: {}".format(other)
        except:
            print "Unexpected error:", sys.exc_info()[0]

    def do_up(self,args):
        """Go up one level"""
        if None == self.parent:
            print "You're at the root. Try 'quit' to quit"
        else:
            return True

    def do_quit(self,args):
        """Alias for 'exit'"""
        return self.do_exit(args)
        
    def do_exit(self,args):
        """Exit cf-ui"""
        raise SystemExit

    def stackResource(self,stackName,logicalId):
        print "loading stack resource {}.{}".format(stackName,logicalId)
        stackResource = cfResource.StackResource(stackName,logicalId)
        if "AWS::CloudFormation::Stack" == stackResource.resource_type:
            childStack = cfResource.Stack(stackResource.physical_resource_id)
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

    def ssh(self,instanceId,interfaceNumber):
        client = boto3.client('ec2')
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
        parser.add_argument('-i','--instance-id',dest='instance-id',help='instance id of the instance to ssh to');
        parser.add_argument('-a','--interface-number',dest='interface-number',help='instance id of the instance to ssh to');
        args = vars(parser.parse_args(shlex.split(args)))

        instanceId = args['instance-id']
        interfaceNumber = int(args['interface-number'])
        self.ssh(instanceId,interfaceNumber)

class AwsAutoScalingGroup(AwsProcessor):
    def __init__(self,scalingGroup,parent):
        AwsProcessor.__init__(self,parent.raw_prompt + "/asg:" + scalingGroup,parent)
        self.client = boto3.client('autoscaling')
        self.scalingGroup = scalingGroup
        self.scalingGroupDescription = self.client.describe_auto_scaling_groups(AutoScalingGroupNames=[self.scalingGroup])
        self.do_printInstances('')
        
    def do_printInstances(self,args):
        """Print the list of instances in this auto scaling group. printInstances -h for detailed help"""
        print "AutoScaling Group:{}".format(self.scalingGroup)
        print "=== Instances ==="
        instances = self.scalingGroupDescription['AutoScalingGroups'][0]['Instances']
        index = 0
        for instance in instances:
            print "{0:3d} {1} {2} {3}".format(index,instance['HealthStatus'],instance['AvailabilityZone'],instance['InstanceId'])
            index += 1

    def do_ssh(self,args):
        """SSH to an instance. ssh -h for detailed help"""
        parser = CommandArgumentParser("stack")
        parser.add_argument(dest='instance',nargs='?',help='instance index or name');
        parser.add_argument('-a','--address-number',default='0',dest='interface-number',help='instance id of the instance to ssh to');
        args = vars(parser.parse_args(shlex.split(args)))

        interfaceNumber = int(args['interface-number'])
        try:
            index = int(args['instance'])
            instances = self.scalingGroupDescription['AutoScalingGroups'][0]['Instances']
            instance = instances[index]
            self.ssh(instance['InstanceId'],interfaceNumber)
        except ValueError:
            self.ssh(args['instance'],interfaceNumber)

        
        
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
        
    def printStack(self,wrappedStack):
        """Prints the stack"""
        print "Stack {}".format(wrappedStack['rawStack'].name)
        pprint(wrappedStack)

        print "== Recent Events"
        count = 0
        for event in wrappedStack['rawStack'].events.all():
            pprint( event )
            count += 1
            if count > 5:
                break;

        print "== Resources"
        for resourceType, resources in wrappedStack['resourcesByTypeIndex'].items():
            if resourceType in resourceTypeAliases:
                resourceType = resourceTypeAliases[resourceType];
            print "=> {}".format(resourceType)
            for index, resource in resources.items():
                print "{0:3d}: {1}".format(index,resource.logical_id)

    def do_print(self,args):
        """Print the current stack. print -h for detailed help"""
        parser = CommandArgumentParser("print")
        args = vars(parser.parse_args(shlex.split(args)))
        self.printStack(self.wrappedStack)
        
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
        parser.add_argument(dest='asg',nargs='?',help='asg index or name');
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
        parser.add_argument(dest='stack',nargs='?',help='stack index or name');
        args = vars(parser.parse_args(shlex.split(args)))

        print "loading stack {}".format(args['stack'])
        try:
            index = int(args['stack'])
            stackSummary = self.wrappedStack['resourcesByTypeIndex']['AWS::CloudFormation::Stack'][index]
        except ValueError:
            stackSummary = self.wrappedStack['resourcesByTypeName']['AWS::CloudFormation::Stack'][args['stack']]

        self.stackResource(stackSummary.stack_name,stackSummary.logical_id)

class AwsRoot(AwsProcessor):
    def __init__(self):
        AwsProcessor.__init__(self,"(aws)",None)
        self.stackList = None;

    def do_stack(self,args):
        """Go to the specified stack. stack -h for detailed help"""
        parser = CommandArgumentParser("stack")
        parser.add_argument(dest='stack',nargs='?',help='stack index or name');
        args = vars(parser.parse_args(shlex.split(args)))

        try:
            index = int(args['stack'])
            if self.stackList == None:
                self.do_stacks('-s')
            stack = cfResource.Stack(self.stackList[index]['StackName'])
        except ValueError:
            stack = cfResource.Stack(args['stack'])

        AwsStack(stack,stack.name,self).cmdloop()

    def do_delete_stack(self,args):
        """Delete specified stack. delete_stack -h for detailed help."""
        parser = CommandArgumentParser("delete_stack")
        parser.add_argument(dest='stack',nargs='?',help='stack index or name');
        args = vars(parser.parse_args(shlex.split(args)))

        try:
            index = int(args['stack'])
            if self.stackList == None:
                self.do_stacks('-s')
            stack = cfResource.Stack(self.stackList[index]['StackName'])
        except ValueError:
            stack = cfResource.Stack(args['stack'])

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
        args = vars(parser.parse_args(shlex.split(args)))

        nextToken = None

        complete = False;
        stackSummaries = []
        while not complete:
            if None == nextToken:
                stacks = cfClient.list_stacks(StackStatusFilter=stackStatusFilter)
            else:
                stacks = cfClient.list_stacks(NextToken=nextToken,StackStatusFilter=stackStatusFilter)
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
                print '{0:3d}: {1!s}'.format(summary['Index'],summary['StackName'])
        
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
    histfile = os.path.join(os.path.expanduser("~"), ".aws_hist")
    try:
        readline.read_history_file(histfile)
        readline.set_history_length(1000)
    except IOError:
        pass
    atexit.register(readline.write_history_file, histfile)

    command_prompt = AwsRoot()
    command_prompt.cmdloop()

if __name__ == "__main__":
    main(sys.argv[1:])
