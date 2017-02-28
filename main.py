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
import yaml

from AwsConnectionFactory import AwsConnectionFactory
from AwsProcessor import AwsProcessor
from AwsProcessorFactoryImpl import AwsProcessorFactoryImpl
from CommandArgumentParser import CommandArgumentParser        

from botocore.exceptions import ClientError
from fnmatch import fnmatch
from run_cmd import run_cmd
from pprint import pprint
from stdplus import *

stackStatusFilter=['CREATE_COMPLETE','CREATE_FAILED','CREATE_IN_PROGRESS','ROLLBACK_IN_PROGRESS','ROLLBACK_COMPLETE','UPDATE_COMPLETE']


mappedKeys = { 'SecretAccessKey' : 'AWS_SECRET_ACCESS_KEY', 'SessionToken': 'AWS_SECURITY_TOKEN', 'AccessKeyId' : 'AWS_ACCESS_KEY_ID' }

from SilentException import SilentException
from SlashException import SlashException

from AwsAutoScalingGroup import AwsAutoScalingGroup        
from AwsStack import AwsStack

            
class AwsRoot(AwsProcessor):
    def __init__(self):
        AwsProcessor.__init__(self,"(aws)",None)
        self.stackList = None;

    def do_stack(self,args):
        """Go to the specified stack. stack -h for detailed help"""
        parser = CommandArgumentParser("stack")
        parser.add_argument(dest='stack',help='stack index or name');
        args = vars(parser.parse_args(args))

        try:
            index = int(args['stack'])
            if self.stackList == None:
                self.do_stacks('-s')
            stack = AwsConnectionFactory.instance.getCfResource().Stack(self.stackList[index]['StackName'])
        except ValueError:
            stack = AwsConnectionFactory.instance.getCfResource().Stack(args['stack'])

        AwsProcessor.processorFactory.Stack(stack,stack.name,self).cmdloop()

    def do_delete_stack(self,args):
        """Delete specified stack. delete_stack -h for detailed help."""
        parser = CommandArgumentParser("delete_stack")
        parser.add_argument(dest='stack',help='stack index or name');
        args = vars(parser.parse_args(args))

        try:
            index = int(args['stack'])
            if self.stackList == None:
                self.do_stacks('-s')
            stack = AwsConnectionFactory.instance.getCfResource().Stack(self.stackList[index]['StackName'])
        except ValueError:
            stack = AwsConnectionFactory.instance.getCfResource().Stack(args['stack'])

        print "Here are the details of the stack you are about to delete:"
        print "Stack.name: {}".format(stack.name)
        print "Stack.stack_id: {}".format(stack.stack_id)
        print "Stack.creation_time: {}".format(stack.creation_time)
        confirmation = raw_input("If you are sure, enter the Stack.name here: ")
        if stack.name == confirmation:
            stack.delete()
            print "Stack deletion in progress"
        else:
            print "Stack deletion canceled: '{}' != '{}'".format(stack.name,confirmation)

    def do_stacks(self,args):
        """List available stacks. stacks -h for detailed help."""
        parser = CommandArgumentParser()
        parser.add_argument('-s','--silent',dest='silent',action='store_true',help='Run silently');
        parser.add_argument('-i','--include',nargs='*',dest='includes',default=[],help='Add statuses');
        parser.add_argument('-e','--exclude',nargs='*',dest='excludes',default=[],help='Remove statuses');
        parser.add_argument(dest='filters',nargs='*',default=["*"],help='Filter stacks');
        args = vars(parser.parse_args(args))

        nextToken = None

        includes = args['includes']
        excludes = args['excludes']
        filters = args['filters']

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
                stacks = AwsConnectionFactory.instance.getCfClient().list_stacks(StackStatusFilter=stackStatusFilter)
            else:
                stacks = AwsConnectionFactory.instance.getCfClient().list_stacks(NextToken=nextToken,StackStatusFilter=stackStatusFilter)
                #pprint(stacks)
            if not 'NextToken' in stacks:
                complete = True;
            else:
                nextToken = stacks['NextToken']

            if 'StackSummaries' in stacks:
                stackSummaries.extend(stacks['StackSummaries'])

        stackSummaries = filter( lambda x: fnmatches(x['StackName'],filters),stackSummaries)
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
        args = vars(parser.parse_args(args))

        stackName = args['stack-name']
        logicalId = args['logical-id']

        self.stackResource(stackName,logicalId)

def main(argv):
    configFile = os.path.join(os.path.expanduser("~"),".aws-shell.yaml")
    config={}
    if os.path.exists(configFile):
        print "Loading config:{}".format(configFile)
        config = yaml.load(readfile(configFile))        

    parser = CommandArgumentParser()
    parser.add_argument('-p','--profile',dest='profile',default=defaultifyDict(config,'profile','default'),help='select aws profile');
    parser.add_argument('-m','--mfa',dest='mfa',help='provide mfa code');
    args = vars(parser.parse_args(argv))
    
    histfile = os.path.join(os.path.expanduser("~"), ".aws_hist")
    try:
        readline.read_history_file(histfile)
        readline.set_history_length(1000)
    except IOError:
        pass
    atexit.register(readline.write_history_file, histfile)

    atexit.register(AwsProcessor.killBackgroundTasks)
    AwsProcessor.processorFactory = AwsProcessorFactoryImpl()

    command_prompt = AwsRoot()
    command_prompt.onecmd("profile -v {}".format(args['profile']))
    if None != args['mfa']:
        command_prompt.onecmd("mfa {}".format(args['mfa']))
    command_prompt.onecmd("stacks")
    command_prompt.cmdloop()

if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except SilentException:
        pass
