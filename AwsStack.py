import os;

from AwsProcessor import AwsProcessor
from AwsConnectionFactory import AwsConnectionFactory
from CommandArgumentParser import CommandArgumentParser
from stdplus import *

from pprint import pprint

class WrappedEvent:
    def __init__(self,event):
        # pprint(event)
        self.event = event
        self.logical_id = event.id
        self.resource_status = event.logical_resource_id + ":" + event.resource_status
        self.resource_status_reason = event.resource_status_reason

class WrappedOutput:
    def __init__(self,output):
        # pprint(output)
        self.output = output
        self.logical_id = output['OutputKey']
        self.resource_status = output['OutputValue']
        self.resource_status_reason = defaultifyDict(output,'Description','')
        
class AwsStack(AwsProcessor):
    def __init__(self,stack,logicalName,parent):
        """Construct an AwsStack command processor"""
        AwsProcessor.__init__(self,parent.raw_prompt + "/stack:" + logicalName,parent)
        self.wrappedStack = self.wrapStack(stack)
        self.printStack(self.wrappedStack)

    def wrapStackEvents(self,stack):
        events = {}
        i = 0;
        if None != stack.events:
            for event in stack.events.all():
                events[i] = WrappedEvent(event)
                i = i + 1
        return events;

    def wrapStackOutputs(self,stack):
        outputs = {}
        i = 0;
        if None != stack.outputs:
            for output in stack.outputs:
                outputs[i] = WrappedOutput(output)
                i = i + 1
        return outputs

    def wrapStack(self,stack):
        result = {};
        result['rawStack'] = stack;

        resourcesByType = {};
        for resource in stack.resource_summaries.all():
            if not resource.resource_type in resourcesByType:
                resourcesByType[resource.resource_type] = {}
            resourcesByType[resource.resource_type][resource.logical_id] = resource;

        resourcesByType['events'] = self.wrapStackEvents(stack)
        resourcesByType['outputs'] = self.wrapStackOutputs(stack)

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
        
    def printStack(self,wrappedStack,include=None,filters=["*"]):
        """Prints the stack"""
        rawStack = wrappedStack['rawStack']
        print "==== Stack {} ====".format(rawStack.name)
        print "Status: {} {}".format(rawStack.stack_status,defaultify(rawStack.stack_status_reason,''))

        for resourceType, resources in wrappedStack['resourcesByTypeIndex'].items():
            if resourceType in AwsProcessor.resourceTypeAliases:
                resourceType = AwsProcessor.resourceTypeAliases[resourceType];
            if (None == include or resourceType in include) and len(resources):
                print "== {}:".format(resourceType)
                logicalIdWidth = 1
                resourceStatusWidth = 1
                resourceStatusReasonWidth = 1
                for index, resource in resources.items():
                    logicalIdWidth = max(logicalIdWidth,len(resource.logical_id))
                    resourceStatusWidth = max(resourceStatusWidth,len(resource.resource_status))
                    resourceStatusReasonWidth = max(resourceStatusReasonWidth,len(defaultify(resource.resource_status_reason,'')))
                frm = "    {{0:3d}}: {{1:{0}}} {{2:{1}}} {{3}}".format(logicalIdWidth,resourceStatusWidth)
                for index, resource in resources.items():
                    if fnmatches(resource.logical_id.lower(),filters):
                        print frm.format(index,resource.logical_id,resource.resource_status,defaultify(resource.resource_status_reason,''))

    def do_browse(self,args):
        """Open the current stack in a browser."""
        rawStack = self.wrappedStack['rawStack']
        os.system("open -a \"Google Chrome\" https://us-west-2.console.aws.amazon.com/cloudformation/home?region=us-west-2#/stack/detail?stackId={}".format(rawStack.stack_id))
                
    def do_refresh(self,args):
        """Refresh view of the current stack. refresh -h for detailed help"""
        self.wrappedStack = self.wrapStack(AwsConnectionFactory.instance.getCfResource().Stack(self.wrappedStack['rawStack'].name))
        
    def do_print(self,args):
        """Print the current stack. print -h for detailed help"""
        parser = CommandArgumentParser("print")
        parser.add_argument('-r','--refresh',dest='refresh',action='store_true',help='refresh view of the current stack')
        parser.add_argument('-i','--include',dest='include',default=None,nargs='+',help='resource types to include')
        parser.add_argument(dest='filters',nargs='*',default=["*"],help='Filter stacks');
        args = vars(parser.parse_args(args))

        if args['refresh']:
            self.do_refresh('')

        self.printStack(self.wrappedStack,args['include'],args['filters'])
        
    def do_resource(self,args):
        """Go to the specified resource. resource -h for detailed help"""
        parser = CommandArgumentParser("resource")
        parser.add_argument('-i','--logical-id',dest='logical-id',help='logical id of the child resource');
        args = vars(parser.parse_args(args))

        stackName = self.wrappedStack['rawStack'].name
        logicalId = args['logical-id']
        self.stackResource(stackName,logicalId)

    def do_asg(self,args):
        """Go to the specified auto scaling group. asg -h for detailed help"""
        parser = CommandArgumentParser("asg")
        parser.add_argument(dest='asg',help='asg index or name');
        args = vars(parser.parse_args(args))

        print "loading auto scaling group {}".format(args['asg'])
        try:
            index = int(args['asg'])
            asgSummary = self.wrappedStack['resourcesByTypeIndex']['AWS::AutoScaling::AutoScalingGroup'][index]
        except:
            asgSummary = self.wrappedStack['resourcesByTypeName']['AWS::AutoScaling::AutoScalingGroup'][args['asg']]

        self.stackResource(asgSummary.stack_name,asgSummary.logical_id)

    def do_eni(self,args):
        """Go to the specified eni. eni -h for detailed help."""
        parser = CommandArgumentParser("eni")
        parser.add_argument(dest='eni',help='eni index or name');
        args = vars(parser.parse_args(args))

        print "loading eni {}".format(args['eni'])
        try:
            index = int(args['eni'])
            eniSummary = self.wrappedStack['resourcesByTypeIndex']['AWS::EC2::NetworkInterface'][index]
        except ValueError:
            eniSummary = self.wrappedStack['resourcesByTypeName']['AWS::EC2::NetworkInterface'][args['eni']]

        pprint(eniSummary)
        self.stackResource(eniSummary.stack_name,eniSummary.logical_id)

    def do_stack(self,args):
        """Go to the specified stack. stack -h for detailed help."""
        parser = CommandArgumentParser("stack")
        parser.add_argument(dest='stack',help='stack index or name');
        args = vars(parser.parse_args(args))

        print "loading stack {}".format(args['stack'])
        try:
            index = int(args['stack'])            
            stackSummary = self.wrappedStack['resourcesByTypeIndex']['AWS::CloudFormation::Stack'][index]
        except ValueError:
            stackSummary = self.wrappedStack['resourcesByTypeName']['AWS::CloudFormation::Stack'][args['stack']]

        self.stackResource(stackSummary.stack_name,stackSummary.logical_id)

    def do_stacks(self,args):
        """Same as print -r --include stack"""
        self.do_print(args + " -r --include stack" )

