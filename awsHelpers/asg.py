def getInstanceIds(asgClient,asgName):
    asgDescription = asgClient.describe_auto_scaling_groups(AutoScalingGroupNames=[asgName])
    instances = asgDescription['AutoScalingGroups'][0]['Instances']
    instanceIds = [instance['InstanceId'] for instance in instances]
    return instanceIds
