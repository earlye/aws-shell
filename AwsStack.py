from AwsProcessor import AwsProcessor
from AwsConnectionFactory import AwsConnectionFactory
from CommandArgumentParser import CommandArgumentParser
from stdplus import *

from pprint import pprint

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
            if resourceType in AwsProcessor.resourceTypeAliases:
                resourceType = AwsProcessor.resourceTypeAliases[resourceType];
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
        self.wrappedStack = self.wrapStack(AwsConnectionFactory.instance.getCfResource().Stack(self.wrappedStack['rawStack'].name))
        
    def do_print(self,args):
        """Print the current stack. print -h for detailed help"""
        parser = CommandArgumentParser("print")
        parser.add_argument('-r','--refresh',dest='refresh',action='store_true',help='refresh view of the current stack')
        parser.add_argument('-i','--include',dest='include',default=None,nargs='+',help='resource types to include')
        args = vars(parser.parse_args(args))

        if args['refresh']:
            self.do_refresh('')

        self.printStack(self.wrappedStack,args['include'])
        
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
        self.do_print('-r --include stack')

