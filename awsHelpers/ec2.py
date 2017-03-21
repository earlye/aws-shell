import yaml

def describeInstances(ec2Client,InstanceIds):
    response = ec2Client.describe_instances(InstanceIds=InstanceIds)
    instanceDescriptions = response['Reservations']
    instances = {}
    for instance in instanceDescriptions:
        instance = instance['Instances'][0]
        instanceId = instance['InstanceId']
        instances[instanceId]=instance
    return instances
    
def instanceIdsToPrivateIps(ec2Client,instanceIds):
    instances = describeInstances(ec2Client,instanceIds)
    result = {}
    for instanceId,instance in instances.items():
        result[instanceId] = []
        for networkInterface in instance['NetworkInterfaces']:
            privateIp = networkInterface['PrivateIpAddress']
            result[instanceId].append(privateIp)
    return result
