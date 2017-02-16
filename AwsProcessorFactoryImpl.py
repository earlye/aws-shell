from AwsAutoScalingGroup import AwsAutoScalingGroup
from AwsStack import AwsStack
from AwsEni import AwsEni

class AwsProcessorFactoryImpl:
    def AutoScalingGroup(self,scalingGroup,parent):
        return AwsAutoScalingGroup(scalingGroup,parent);

    def Eni(self,physicalId,parent):
        return AwsEni(physicalId,parent)
    
    def Stack(self,stack,logicalName,parent):
        return AwsStack(stack,logicalName,parent)
    
