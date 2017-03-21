from AwsProcessor import AwsProcessor
from AwsConnectionFactory import AwsConnectionFactory

from pprint import pprint

class AwsEni(AwsProcessor):
    def __init__(self,physicalId,parent):
        """Construct an AwsEni command processor"""
        AwsProcessor.__init__(self,parent.raw_prompt + "/eni:" + physicalId,parent)
        self.physicalId = physicalId
        self.do_refresh('')

    def do_refresh(self,args):
        """Refresh the view of the eni"""
        pprint(AwsConnectionFactory.getEc2Client().describe_network_interfaces(NetworkInterfaceIds=[self.physicalId]));
