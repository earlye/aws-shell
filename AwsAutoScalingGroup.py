from AwsProcessor import AwsProcessor
from AwsConnectionFactory import AwsConnectionFactory
from CommandArgumentParser import CommandArgumentParser

import boto3

class AwsAutoScalingGroup(AwsProcessor):
    def __init__(self,scalingGroup,parent):
        AwsProcessor.__init__(self,parent.raw_prompt + "/asg:" + scalingGroup,parent)
        self.client = AwsConnectionFactory.instance.getAsgClient()
        self.scalingGroup = scalingGroup
        
        self.do_printInstances('-r')
        
    def do_printInstances(self,args):
        """Print the list of instances in this auto scaling group. printInstances -h for detailed help"""
        parser = CommandArgumentParser("stack")
        parser.add_argument('-a','--addresses',action='store_true',dest='addresses',help='list all ip addresses');
        parser.add_argument('-r','--refresh',action='store_true',dest='refresh',help='refresh');
        args = vars(parser.parse_args(args))

        client = AwsConnectionFactory.instance.getEc2Client()

        if args['refresh']:
            self.scalingGroupDescription = self.client.describe_auto_scaling_groups(AutoScalingGroupNames=[self.scalingGroup])
        
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

    def do_terminateInstance(self,args):
        """Terminate an EC2 instance"""
        parser = CommandArgumentParser("ssh")
        parser.add_argument(dest='instance',help='instance index or name');
        args = vars(parser.parse_args(args))

        instanceId = args['instance']
        try:
            index = int(instanceId)
            instances = self.scalingGroupDescription['AutoScalingGroups'][0]['Instances']
            instanceId = instances[index]
        except ValueError:
            pass

        client = AwsConnectionFactory.instance.getEc2Client()
        client.terminate_instances(InstanceIds=[instanceId['InstanceId']])
        self.do_printInstances("-r")

    def do_setDesiredCapacity(self,args):
        """Set the desired capacity"""
        parser = CommandArgumentParser("setDesiredCapacity")
        parser.add_argument(dest='value',type=int,help='new value');
        args = vars(parser.parse_args(args))

        value = int(args['value'])
        print "Setting desired capacity to {}".format(value)
        client = AwsConnectionFactory.instance.getAsgClient()
        client.set_desired_capacity(AutoScalingGroupName=self.scalingGroup,DesiredCapacity=value,HonorCooldown=True)
        print "Scaling activity in progress"

    def do_updateCapacity(self,args):
        """Set the desired capacity"""
        parser = CommandArgumentParser("updateMinMax")
        parser.add_argument('-m','--min',dest='min',type=int,help='new values');
        parser.add_argument('-M','--max',dest='max',type=int,help='new values');
        parser.add_argument('-d','--desired',dest='desired',type=int,help='desired');
        args = vars(parser.parse_args(args))

        minSize = args['min']
        maxSize = args['max']
        desired = args['desired']
        
        print "Setting desired capacity to {}-{}, {}".format(minSize,maxSize,desired)
        client = AwsConnectionFactory.instance.getAsgClient()
        client.update_auto_scaling_group(AutoScalingGroupName=self.scalingGroup,MinSize=minSize,MaxSize=maxSize,DesiredCapacity=desired)
        #client.set_desired_capacity(AutoScalingGroupName=self.scalingGroup,DesiredCapacity=value,HonorCooldown=True)
        print "Scaling activity in progress"
        

    def do_ssh(self,args):
        """SSH to an instance. ssh -h for detailed help"""
        parser = CommandArgumentParser("ssh")
        parser.add_argument(dest='instance',help='instance index or name');
        parser.add_argument('-a','--address-number',default='0',dest='interface-number',help='instance id of the instance to ssh to');
        parser.add_argument('-L',dest='forwarding',nargs='*',help="port forwarding string of the form: {localport}:{host-visible-to-instance}:{remoteport} or {port}")
        parser.add_argument('-R','--replace-key',dest='replaceKey',default=False,action='store_true',help="Replace the host's key. This is useful when AWS recycles an IP address you've seen before.")
        parser.add_argument('-B','--background',dest='background',default=False,action='store_true',help="Run in the background. (e.g., forward an ssh session and then do other stuff in aws-shell).")
        args = vars(parser.parse_args(args))

        interfaceNumber = int(args['interface-number'])
        forwarding = args['forwarding']
        replaceKey = args['replaceKey']
        background = args['background']
        try:
            index = int(args['instance'])
            instances = self.scalingGroupDescription['AutoScalingGroups'][0]['Instances']
            instance = instances[index]
            self.ssh(instance['InstanceId'],interfaceNumber,forwarding,replaceKey,background)
        except ValueError:
            self.ssh(args['instance'],interfaceNumber,forwarding,replaceKey,background)
